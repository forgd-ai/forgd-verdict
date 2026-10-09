# An EKS cluster for the Helm chart, and the identities that let its pods
# act as the store's roles.
#
# This module does NOT deploy the chart, and installs nothing into the
# cluster: no helm or kubernetes provider. The AWS Load Balancer Controller
# gets its IAM role and association here and is installed with the command
# in the `lb_controller_install_command` output.
#
# It also does not create the store. ../store-s3 does, and its writer and
# reader role ARNs are inputs here.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  pod_identity = var.identity_mode == "pod_identity"
  irsa         = var.identity_mode == "irsa"

  create_kms_key = var.secrets_kms_key_arn == ""
  secrets_key    = local.create_kms_key ? aws_kms_key.secrets[0].arn : var.secrets_kms_key_arn

  lb_controller_namespace       = "kube-system"
  lb_controller_service_account = "aws-load-balancer-controller"

  # The issuer without its scheme: the form IAM condition keys and the OIDC
  # provider's ARN use.
  oidc_issuer_host = replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")

  # Built from its parts rather than read from aws_eks_cluster.this, which
  # would make store-s3's roles wait for the cluster.
  cluster_arn = "arn:${data.aws_partition.current.partition}:eks:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:cluster/${var.cluster_name}"

  # The service accounts each role serves, keyed as irsa_trust is.
  # With the connector on, the reader role serves two service accounts; a
  # list under StringEquals matches either. Through JSON because the two
  # branches have different types, and off it must stay a plain string.
  pod_identity_subjects = merge({
    writer = { namespace = var.namespace, service_account = var.writer_service_account }
    reader = { namespace = var.namespace, service_account = jsondecode(var.connector_enabled
      ? jsonencode([var.reader_service_account, var.connector_service_account])
    : jsonencode(var.reader_service_account)) }
    lb_controller = { namespace = local.lb_controller_namespace, service_account = local.lb_controller_service_account }
    }, var.control_enabled ? {
    control = { namespace = var.namespace, service_account = var.control_service_account }
  } : {})

  # Checked on the association under pod_identity and on helm_values_hint
  # under either mode.
  control_ok = !var.control_enabled || (var.control_role_arn != "" && !contains([var.writer_role_arn, var.reader_role_arn], var.control_role_arn))
  control_sa_ok = !var.control_enabled || !contains(concat([var.writer_service_account, var.reader_service_account],
  var.connector_enabled ? [var.connector_service_account] : []), var.control_service_account)

  # Every condition is a session tag Pod Identity sets on the AssumeRole
  # call, the form the EKS user guide documents for restricting a role to a
  # cluster, namespace and service account. eks-cluster-arn carries the
  # account as well. An association with disable_session_tags matches none
  # of them, and its pods get no credentials.
  pod_identity_trust = { for role, s in local.pod_identity_subjects : role => jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = {
          "aws:RequestTag/eks-cluster-arn"            = local.cluster_arn
          "aws:RequestTag/kubernetes-namespace"       = s.namespace
          "aws:RequestTag/kubernetes-service-account" = s.service_account
        }
      }
    }]
  }) }
}

# --- control plane -------------------------------------------------------

data "aws_iam_policy_document" "cluster_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${var.cluster_name}-cluster"
  assume_role_policy = data.aws_iam_policy_document.cluster_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_kms_key" "secrets" {
  count                   = local.create_kms_key ? 1 : 0
  description             = "Envelope encryption of Kubernetes secrets in ${var.cluster_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "secrets" {
  count         = local.create_kms_key ? 1 : 0
  name          = "alias/${var.cluster_name}-secrets"
  target_key_id = aws_kms_key.secrets[0].key_id
}

# The key policy of a module-created key delegates to IAM, and
# AmazonEKSClusterPolicy grants no KMS actions, so without this the cluster
# fails to create. A passed-in key's policy must also allow IAM delegation
# or name this role.
data "aws_iam_policy_document" "cluster_kms" {
  statement {
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ListGrants", "kms:DescribeKey"]
    resources = [local.secrets_key]
  }
}

resource "aws_iam_role_policy" "cluster_kms" {
  name   = "secrets-encryption"
  role   = aws_iam_role.cluster.id
  policy = data.aws_iam_policy_document.cluster_kms.json
}

# Created ahead of the cluster so that EKS writes into a group with a
# retention, rather than creating one that keeps logs forever.
resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.cluster.arn
  tags     = var.tags

  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  vpc_config {
    subnet_ids              = var.subnet_ids
    security_group_ids      = [aws_security_group.api.id]
    endpoint_private_access = true
    endpoint_public_access  = var.endpoint_public_access
    # With public access off, the list is ignored by EKS but still reported
    # back as 0.0.0.0/0; leaving it unset avoids a permanent diff.
    public_access_cidrs = var.endpoint_public_access ? var.public_access_cidrs : null
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = local.secrets_key
    }
  }

  # Access entries only, no aws-auth ConfigMap. The identity that applies
  # this module is made cluster admin; cluster_admin_principal_arns adds
  # others.
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }

  lifecycle {
    precondition {
      condition     = !var.endpoint_public_access || length(var.public_access_cidrs) > 0
      error_message = "endpoint_public_access is true but public_access_cidrs is empty. EKS would open the API endpoint to 0.0.0.0/0; list the ranges that may reach it, or turn public access off."
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.cluster,
    aws_iam_role_policy.cluster_kms,
    aws_cloudwatch_log_group.cluster,
  ]
}

# Attached to the control plane's network interfaces only. The cluster
# security group is on the nodes too, so a rule there would reach them.
resource "aws_security_group" "api" {
  name_prefix = "${var.cluster_name}-api-"
  description = "Callers of the ${var.cluster_name} private API endpoint"
  vpc_id      = var.vpc_id
  tags        = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "api_from_security_group" {
  for_each                     = toset(var.api_allowed_security_group_ids)
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "Kubernetes API"
  tags                         = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "api_from_cidr" {
  for_each          = toset(var.api_allowed_cidrs)
  security_group_id = aws_security_group.api.id
  cidr_ipv4         = strcontains(each.value, ":") ? null : each.value
  cidr_ipv6         = strcontains(each.value, ":") ? each.value : null
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "Kubernetes API"
  tags              = var.tags
}

resource "aws_eks_access_entry" "admin" {
  for_each      = toset(var.cluster_admin_principal_arns)
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  tags          = var.tags
}

resource "aws_eks_access_policy_association" "admin" {
  for_each      = aws_eks_access_entry.admin
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value.principal_arn
  policy_arn    = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}

# --- nodes ---------------------------------------------------------------

data "aws_iam_policy_document" "node_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "${var.cluster_name}-node"
  assume_role_policy = data.aws_iam_policy_document.node_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "AmazonEKSWorkerNodePolicy",
    "AmazonEKS_CNI_Policy",
    "AmazonEC2ContainerRegistryReadOnly",
  ])
  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/${each.value}"
}

# A hop limit of 1 keeps IMDS reachable from host-network pods (the CNI, the
# Pod Identity agent) and unreachable from ordinary pods, which would
# otherwise pick up the node role's credentials, including the CNI's
# permission to modify network interfaces.
resource "aws_launch_template" "node" {
  name_prefix = "${var.cluster_name}-node-"
  tags        = var.tags

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.node_disk_size_gb
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = "${var.cluster_name}-node" })
  }
}

resource "aws_eks_node_group" "this" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-default"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = [var.node_instance_type]
  capacity_type   = var.node_capacity_type
  tags            = var.tags

  # The chart requests about 3.25 vCPU / 7.5 Gi with the six-hourly ingest
  # job running; the default two 4-vCPU nodes leave room for it and the
  # system add-ons.
  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }

  lifecycle {
    precondition {
      condition     = var.node_min_size <= var.node_desired_size && var.node_desired_size <= var.node_max_size
      error_message = "node sizes must satisfy node_min_size <= node_desired_size <= node_max_size."
    }
  }

  depends_on = [aws_iam_role_policy_attachment.node]
}

# --- network policy ------------------------------------------------------

# EKS installs a self-managed vpc-cni with every cluster, so creating the
# managed add-on over it conflicts unless the add-on overwrites it.
resource "aws_eks_addon" "vpc_cni" {
  count                       = var.enable_network_policy ? 1 : 0
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "vpc-cni"
  resolve_conflicts_on_create = "OVERWRITE"
  configuration_values        = jsonencode({ enableNetworkPolicy = "true" })
  tags                        = var.tags

  # A DaemonSet with nowhere to schedule leaves the add-on DEGRADED.
  depends_on = [aws_eks_node_group.this]
}

# --- pod identity --------------------------------------------------------

resource "aws_eks_addon" "pod_identity_agent" {
  count        = local.pod_identity ? 1 : 0
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "eks-pod-identity-agent"
  tags         = var.tags

  # A DaemonSet with nowhere to schedule leaves the add-on DEGRADED.
  depends_on = [aws_eks_node_group.this]
}

# The association is keyed on namespace and service account name, both of
# which must match the release exactly. A mismatch gives a pod with no AWS
# credentials, which surfaces as a dashboard with no findings.
resource "aws_eks_pod_identity_association" "writer" {
  count           = local.pod_identity ? 1 : 0
  cluster_name    = aws_eks_cluster.this.name
  namespace       = var.namespace
  service_account = var.writer_service_account
  role_arn        = var.writer_role_arn
  tags            = var.tags

  depends_on = [aws_eks_addon.pod_identity_agent]
}

resource "aws_eks_pod_identity_association" "reader" {
  count           = local.pod_identity ? 1 : 0
  cluster_name    = aws_eks_cluster.this.name
  namespace       = var.namespace
  service_account = var.reader_service_account
  role_arn        = var.reader_role_arn
  tags            = var.tags

  lifecycle {
    precondition {
      condition     = var.reader_role_arn != var.writer_role_arn
      error_message = "reader_role_arn equals writer_role_arn. The dashboard must hold store-s3's reader role, or the one service a human signs into can rewrite the findings."
    }
  }

  depends_on = [aws_eks_addon.pod_identity_agent]
}

# The findings connector, on the reader role like the dashboard.
resource "aws_eks_pod_identity_association" "connector" {
  count           = var.connector_enabled && local.pod_identity ? 1 : 0
  cluster_name    = aws_eks_cluster.this.name
  namespace       = var.namespace
  service_account = var.connector_service_account
  role_arn        = var.reader_role_arn
  tags            = var.tags

  lifecycle {
    precondition {
      condition     = var.reader_role_arn != var.writer_role_arn
      error_message = "reader_role_arn equals writer_role_arn. The connector must hold store-s3's reader role, or a caller Claude signs in could rewrite the findings."
    }
    precondition {
      condition     = !contains([var.writer_service_account, var.reader_service_account], var.connector_service_account)
      error_message = "connector_service_account must be a service account of its own, not the writer's or the dashboard's."
    }
  }

  depends_on = [aws_eks_addon.pod_identity_agent]
}

# The dashboard with admins enabled, on store-s3's control role.
resource "aws_eks_pod_identity_association" "control" {
  count           = var.control_enabled && local.pod_identity ? 1 : 0
  cluster_name    = aws_eks_cluster.this.name
  namespace       = var.namespace
  service_account = var.control_service_account
  role_arn        = var.control_role_arn
  tags            = var.tags

  lifecycle {
    precondition {
      condition     = local.control_ok
      error_message = "control_enabled needs control_role_arn, store-s3's control_role_arn, and it must differ from writer_role_arn and reader_role_arn. The reader role is shared with the connector, and the writer's can rewrite the findings."
    }
    precondition {
      condition     = local.control_sa_ok
      error_message = "control_service_account must be a service account of its own, not the writer's, the reader's or the connector's."
    }
  }

  depends_on = [aws_eks_addon.pod_identity_agent]
}

# --- IRSA (identity_mode = "irsa") ---------------------------------------

resource "aws_iam_openid_connect_provider" "this" {
  count          = local.irsa ? 1 : 0
  url            = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags
}

data "aws_iam_policy_document" "irsa_trust" {
  for_each = local.irsa ? merge({
    writer = ["system:serviceaccount:${var.namespace}:${var.writer_service_account}"]
    reader = concat(["system:serviceaccount:${var.namespace}:${var.reader_service_account}"],
    var.connector_enabled ? ["system:serviceaccount:${var.namespace}:${var.connector_service_account}"] : [])
    lb_controller = ["system:serviceaccount:${local.lb_controller_namespace}:${local.lb_controller_service_account}"]
    }, var.control_enabled ? {
    control = ["system:serviceaccount:${var.namespace}:${var.control_service_account}"]
  } : {}) : {}

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.this[0].arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer_host}:sub"
      values   = each.value
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

# --- AWS Load Balancer Controller ----------------------------------------

resource "aws_iam_role" "lb_controller" {
  count              = var.lb_controller_enabled ? 1 : 0
  name               = "${var.cluster_name}-aws-load-balancer-controller"
  assume_role_policy = local.irsa ? data.aws_iam_policy_document.irsa_trust["lb_controller"].json : local.pod_identity_trust["lb_controller"]
  tags               = var.tags
}

# iam_policy.json is docs/install/iam_policy.json from
# kubernetes-sigs/aws-load-balancer-controller at tag v3.5.0, unmodified.
# Replace it from the same path when the controller version in
# lb_controller_install_command changes.
resource "aws_iam_policy" "lb_controller" {
  count  = var.lb_controller_enabled ? 1 : 0
  name   = "${var.cluster_name}-aws-load-balancer-controller"
  policy = file("${path.module}/iam_policy.json")
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "lb_controller" {
  count      = var.lb_controller_enabled ? 1 : 0
  role       = aws_iam_role.lb_controller[0].name
  policy_arn = aws_iam_policy.lb_controller[0].arn
}

resource "aws_eks_pod_identity_association" "lb_controller" {
  count           = var.lb_controller_enabled && local.pod_identity ? 1 : 0
  cluster_name    = aws_eks_cluster.this.name
  namespace       = local.lb_controller_namespace
  service_account = local.lb_controller_service_account
  role_arn        = aws_iam_role.lb_controller[0].arn
  tags            = var.tags

  depends_on = [aws_eks_addon.pod_identity_agent]
}
