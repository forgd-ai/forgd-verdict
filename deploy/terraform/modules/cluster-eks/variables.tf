variable "cluster_name" {
  type = string
  validation {
    # Also prefixes the IAM role and policy names, which cap at 64
    # characters; the longest suffix is -aws-load-balancer-controller.
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{0,34}$", var.cluster_name))
    error_message = "cluster_name must start with a letter and be at most 35 letters, digits and hyphens."
  }
}

variable "kubernetes_version" {
  type        = string
  default     = "1.36"
  description = "EKS minor version. Moving it forward upgrades the control plane in place; EKS does not go backwards."
  validation {
    condition     = can(regex("^1\\.[0-9]+$", var.kubernetes_version))
    error_message = "kubernetes_version is a minor version such as 1.36."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}

# --- network -------------------------------------------------------------
# The caller's VPC. This module creates none.

variable "vpc_id" {
  type        = string
  description = "The VPC holding subnet_ids. Passed to the Load Balancer Controller so it does not read it from instance metadata, which pods cannot reach."
}

variable "subnet_ids" {
  type        = list(string)
  description = "PRIVATE subnets, in at least two availability zones, for the nodes and the control plane's network interfaces. They need a route out to ECR, S3, STS and Anthropic's APIs."
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "EKS needs subnet_ids in at least two availability zones."
  }
}

variable "public_subnet_ids" {
  type        = list(string)
  default     = []
  description = "Public subnets for the internet-facing ALB. Empty leaves the Load Balancer Controller to discover subnets tagged kubernetes.io/role/elb=1."
}

variable "endpoint_public_access" {
  type        = bool
  default     = false
  description = "Whether the Kubernetes API is reachable from outside the VPC. Off means kubectl and helm run from inside it, or over a VPN or peering. Private access is always on."
}

variable "public_access_cidrs" {
  type        = list(string)
  default     = []
  description = "Who may reach the public API endpoint. Required, non-empty, when endpoint_public_access is true; there is no 0.0.0.0/0 default."
  validation {
    condition     = alltrue([for c in var.public_access_cidrs : can(cidrhost(c, 0))])
    error_message = "Every entry in public_access_cidrs must be a CIDR block."
  }
}

variable "api_allowed_security_group_ids" {
  type        = list(string)
  default     = []
  description = "Security groups whose members may reach the private API endpoint on 443: a bastion, a CI runner, a VPN endpoint. The endpoint's network interfaces otherwise admit only the cluster's own security group."
  validation {
    condition     = alltrue([for id in var.api_allowed_security_group_ids : can(regex("^sg-[0-9a-f]+$", id))])
    error_message = "Every entry in api_allowed_security_group_ids must be a security group id (sg-...)."
  }
}

variable "api_allowed_cidrs" {
  type        = list(string)
  default     = []
  description = "IPv4 or IPv6 ranges that may reach the private API endpoint on 443, such as a VPN's client range."
  validation {
    condition     = alltrue([for c in var.api_allowed_cidrs : can(cidrhost(c, 0))])
    error_message = "Every entry in api_allowed_cidrs must be a CIDR block."
  }
  validation {
    condition     = alltrue([for c in var.api_allowed_cidrs : try(tonumber(split("/", c)[1]) > 0, false)])
    error_message = "api_allowed_cidrs may not contain a /0 such as 0.0.0.0/0 or ::/0. List the ranges that need the API."
  }
}

# --- control plane -------------------------------------------------------

variable "cluster_admin_principal_arns" {
  type        = list(string)
  default     = []
  description = "IAM roles or users made cluster admin (AmazonEKSClusterAdminPolicy, cluster scope) through access entries. The identity that applies the module is admin already; when that is CI, leaving this empty gives no human access. Do not list the applying identity: its access entry exists, and creating it again fails."
  validation {
    condition     = alltrue([for a in var.cluster_admin_principal_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/.+$", a))])
    error_message = "Every entry in cluster_admin_principal_arns must be an IAM role or user ARN. For an assumed role, give the role's arn:aws:iam::<account>:role/<name>, not the sts assumed-role ARN."
  }
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = "Retention for the api, audit and authenticator logs. The audit log is the record of who read the forgd-verdict secret."
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a value CloudWatch Logs accepts, such as 30, 90, 365 or 731."
  }
}

variable "secrets_kms_key_arn" {
  type        = string
  default     = ""
  description = "A KMS key for envelope encryption of Kubernetes secrets. Empty creates one, with rotation on. The encryption cannot be turned off once the cluster has it."
  validation {
    condition     = var.secrets_kms_key_arn == "" || can(regex("^arn:aws[a-z-]*:kms:", var.secrets_kms_key_arn))
    error_message = "secrets_kms_key_arn must be empty or a KMS key ARN."
  }
}

# --- nodes ---------------------------------------------------------------

variable "node_instance_type" {
  type        = string
  default     = "m6i.xlarge"
  description = "4 vCPU / 16 GiB. See the sizing note on the node group in main.tf before going smaller."
}

variable "node_capacity_type" {
  type        = string
  default     = "ON_DEMAND"
  description = "SPOT can reclaim the node under the verdict server, and a governed prompt that cannot reach it fails."
  validation {
    condition     = contains(["ON_DEMAND", "SPOT"], var.node_capacity_type)
    error_message = "node_capacity_type must be ON_DEMAND or SPOT."
  }
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "node_min_size" {
  type    = number
  default = 2
}

variable "node_max_size" {
  type        = number
  default     = 3
  description = "An update replaces nodes one at a time and needs room for one more than desired."
}

variable "node_disk_size_gb" {
  type    = number
  default = 64
}

variable "enable_network_policy" {
  type        = bool
  default     = true
  description = <<-D
    Run the vpc-cni add-on with enableNetworkPolicy, so the cluster enforces
    NetworkPolicy. The default VPC CNI accepts a NetworkPolicy and enforces
    none of it. The chart's trusted_header guard is satisfied by
    networkPolicy.enabled with the ingress controller's selectors, and that
    keeps other pods away from the dashboard only when the policy is
    enforced.
  D
}

# --- workload identity ---------------------------------------------------

variable "identity_mode" {
  type        = string
  default     = "pod_identity"
  description = <<-D
    How pods get AWS credentials.

    pod_identity: the eks-pod-identity-agent add-on plus an association per
    service account. store-s3's roles trust pods.eks.amazonaws.com; the
    `writer_assume_role_policy` output is that trust policy.

    irsa: an IAM OIDC provider for the cluster, and a trust policy per
    service account in the `writer_assume_role_policy` and
    `reader_assume_role_policy` outputs. The chart then needs the role ARN
    as an annotation on each service account; `helm_values_hint` lists them.
  D
  validation {
    condition     = contains(["pod_identity", "irsa"], var.identity_mode)
    error_message = "identity_mode must be pod_identity or irsa."
  }
}

variable "namespace" {
  type        = string
  default     = "forgd"
  description = "The namespace the chart is installed into. Part of every association and IRSA subject; a mismatch authenticates as nothing."
}

variable "dashboard_oidc_secret_name" {
  type        = string
  default     = "forgd-dashboard-oidc"
  description = "The secret named by secretName in the dashboard Ingress's auth-idp-oidc annotation, holding the IdP client's clientID and clientSecret. The only secret the Load Balancer Controller may read."
}

variable "writer_service_account" {
  type        = string
  default     = "forgd-verdict-writer"
  description = "The chart's writer service account: <release fullname>-writer, or serviceAccounts.writer.name."
}

variable "reader_service_account" {
  type        = string
  default     = "forgd-verdict-reader"
  description = "The chart's reader service account: <release fullname>-reader, or serviceAccounts.reader.name."
}

variable "writer_role_arn" {
  type        = string
  description = "store-s3's writer_role_arn. The verdict server, collector and ingest job."
}

variable "reader_role_arn" {
  type        = string
  description = "store-s3's reader_role_arn. The dashboard's, and deliberately not the writer's."
}

variable "lb_controller_enabled" {
  type        = bool
  default     = true
  description = "Create the AWS Load Balancer Controller's IAM role. False means supplying an ingress controller yourself, and the chart's Ingress objects do nothing until you do."
}

variable "connector_enabled" {
  type        = bool
  default     = false
  description = "Bind the chart's connector service account to the store's reader identity. Set with connector.enabled in the chart. False leaves the plan exactly as it was."
}

variable "connector_service_account" {
  type        = string
  default     = "forgd-verdict-connector"
  description = "The chart's connector service account: <release fullname>-connector, or serviceAccounts.connector.name. Used only when connector_enabled."
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", var.connector_service_account))
    error_message = "connector_service_account must be a Kubernetes service account name."
  }
}

variable "control_enabled" {
  type        = bool
  default     = false
  description = "Give the chart's control service account store-s3's control role, for dashboard.admins.enabled in the chart: a trust policy in control_assume_role_policy and, under pod_identity, an association. False leaves the plan exactly as it was."
}

variable "control_role_arn" {
  type        = string
  default     = ""
  description = "store-s3's control_role_arn. Required when control_enabled; must differ from writer_role_arn and reader_role_arn."
}

variable "control_service_account" {
  type        = string
  default     = "forgd-verdict-control"
  description = "The chart's control service account: <release fullname>-control, or serviceAccounts.control.name. Used only when control_enabled."
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", var.control_service_account))
    error_message = "control_service_account must be a Kubernetes service account name."
  }
}
