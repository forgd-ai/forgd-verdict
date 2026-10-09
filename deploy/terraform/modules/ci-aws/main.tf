# The CD identity for scripts/deploy_aws.sh: one IAM role that GitHub
# Actions assumes through OIDC, from one environment of one repository.
#
# Each statement is a call the script makes, scoped to the resource that
# call touches. The role creates, deletes and attaches nothing. Its writes
# are image layers to one ECR repository, new revisions in the task
# definition families Terraform owns, the services' task definition pointer
# and the ingest schedule's target.
#
# This module does not deploy anything. Apply it with an identity that can
# create roles; the role it creates cannot.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  partition         = data.aws_partition.current.partition
  oidc_host         = "token.actions.githubusercontent.com"
  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.oidc_provider_arn
  # An organization with immutable OIDC identifiers enabled presents
  # repo:<org>@<org id>/<repo>@<repo id>:... instead of the short form.
  subjects = concat(
    ["repo:${var.github_org}/${var.github_repo}:environment:${var.github_environment}"],
    var.github_owner_id == null ? [] : ["repo:${var.github_org}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}:environment:${var.github_environment}"],
  )

  eks_cluster_arn = var.eks == null ? null : "arn:${local.partition}:eks:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:cluster/${var.eks.cluster_name}"

  # Read by .github/workflows/deploy.yml, which a fork copies from
  # examples/github/deploy.yml, and passed to deploy_aws.sh as environment
  # variables of the same names.
  repository_variables = concat(
    ["AWS_DEPLOY_ROLE_ARN", "AWS_REGION", "AWS_ECR_REPOSITORY", "AWS_DEPLOY_TARGET",
      "FORGD_VERDICT_URL", "FORGD_COLLECTOR_URL", "FORGD_DASHBOARD_URL", "FORGD_CONNECTOR_URL", "FORGD_INTAKE_URL",
    "AWS_IMAGE_PLATFORM", "AWS_ALLOW_CROSS_BUILD"],
    var.ecs == null ? [] : [
      "AWS_ECS_CLUSTER",
      "AWS_ECS_VERDICT_SERVICE", "AWS_ECS_VERDICT_FAMILY",
      "AWS_ECS_COLLECTOR_SERVICE", "AWS_ECS_COLLECTOR_FAMILY",
      "AWS_ECS_DASHBOARD_SERVICE", "AWS_ECS_DASHBOARD_FAMILY",
      "AWS_ECS_INTAKE_SERVICE", "AWS_ECS_INTAKE_FAMILY",
      "AWS_ECS_CONNECTOR_SERVICE", "AWS_ECS_CONNECTOR_FAMILY",
      "AWS_ECS_INGEST_FAMILY", "AWS_INGEST_SCHEDULE", "AWS_INGEST_SCHEDULE_GROUP",
    ],
    var.eks == null ? [] : ["AWS_EKS_CLUSTER", "AWS_EKS_RELEASE", "AWS_EKS_NAMESPACE", "AWS_EKS_CHART", "AWS_EKS_REGION"],
  )
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = local.subjects
    }
  }
}

resource "aws_iam_role" "deploy" {
  name               = "${var.name_prefix}-deploy"
  assume_role_policy = data.aws_iam_policy_document.trust.json
  tags               = var.tags

  lifecycle {
    precondition {
      condition     = var.create_oidc_provider != (var.oidc_provider_arn != null)
      error_message = "Set exactly one of create_oidc_provider = true and oidc_provider_arn. An account has at most one provider for token.actions.githubusercontent.com; pass its ARN if it exists."
    }
    precondition {
      condition     = (var.github_owner_id == null) == (var.github_repo_id == null)
      error_message = "Set both github_owner_id and github_repo_id, or neither."
    }
    precondition {
      condition     = var.ecs != null || var.eks != null
      error_message = "Set ecs, eks or both. With neither the role can push images and roll nothing."
    }
  }
}

data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "EcrPush"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
    ]
    resources = [var.ecr_repository_arn]
  }

  # --- ecs -----------------------------------------------------------------

  dynamic "statement" {
    for_each = var.ecs == null ? [] : [var.ecs]
    content {
      sid       = "EcsReadTaskDefinitions"
      actions   = ["ecs:DescribeTaskDefinition"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.ecs == null ? [] : [var.ecs]
    content {
      sid       = "EcsRegisterTaskDefinitions"
      actions   = ["ecs:RegisterTaskDefinition"]
      resources = statement.value.task_definition_arns
    }
  }

  # The script carries a revision's tags over to the one it registers.
  dynamic "statement" {
    for_each = var.ecs == null ? [] : [var.ecs]
    content {
      sid       = "EcsTagOnRegister"
      actions   = ["ecs:TagResource"]
      resources = statement.value.task_definition_arns

      condition {
        test     = "StringEquals"
        variable = "ecs:CreateAction"
        values   = ["RegisterTaskDefinition"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.ecs == null ? [] : [var.ecs]
    content {
      sid       = "EcsRollServices"
      actions   = ["ecs:DescribeServices", "ecs:UpdateService"]
      resources = statement.value.service_arns
    }
  }

  dynamic "statement" {
    for_each = var.ecs == null ? [] : [var.ecs]
    content {
      sid       = "PassTaskRoles"
      actions   = ["iam:PassRole"]
      resources = statement.value.task_role_arns

      condition {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = ["ecs-tasks.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.ecs == null ? [] : [var.ecs]
    content {
      sid       = "IngestSchedule"
      actions   = ["scheduler:GetSchedule", "scheduler:UpdateSchedule"]
      resources = [statement.value.schedule_arn]
    }
  }

  # UpdateSchedule passes the target's role again.
  dynamic "statement" {
    for_each = var.ecs == null ? [] : [var.ecs]
    content {
      sid       = "PassSchedulerRole"
      actions   = ["iam:PassRole"]
      resources = [statement.value.schedule_role_arn]

      condition {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = ["scheduler.amazonaws.com"]
      }
    }
  }

  # --- eks -----------------------------------------------------------------

  # For `aws eks update-kubeconfig`. What helm may do in the cluster is the
  # access entry below.
  dynamic "statement" {
    for_each = var.eks == null ? [] : [var.eks]
    content {
      sid       = "EksKubeconfig"
      actions   = ["eks:DescribeCluster"]
      resources = [local.eks_cluster_arn]
    }
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "deploy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}

# Namespace-scoped Edit: the chart renders Deployments, Services, Ingresses,
# ConfigMaps, Secrets, ServiceAccounts and a CronJob, and no RBAC objects.
resource "aws_eks_access_entry" "deploy" {
  count = var.eks == null ? 0 : 1

  cluster_name  = var.eks.cluster_name
  principal_arn = aws_iam_role.deploy.arn
  tags          = var.tags
}

resource "aws_eks_access_policy_association" "deploy" {
  count = var.eks == null ? 0 : 1

  cluster_name  = var.eks.cluster_name
  principal_arn = aws_eks_access_entry.deploy[0].principal_arn
  policy_arn    = "arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"

  access_scope {
    type       = "namespace"
    namespaces = [var.eks.namespace]
  }
}
