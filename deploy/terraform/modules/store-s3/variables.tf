variable "bucket_name" {
  type        = string
  description = "Globally unique across every AWS account."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "3-63 lowercase letters, digits, dots and hyphens. S3 rejects anything else, and it does so after a plan looks fine."
  }
  # The rest of S3's naming rules, which the pattern above cannot express.
  validation {
    condition     = !can(regex("\\.\\.", var.bucket_name)) && !can(regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$", var.bucket_name)) && !can(regex("^(xn--|sthree-|amzn-s3-demo-)", var.bucket_name)) && !can(regex("(-s3alias|--ol-s3|--x-s3|--table-s3|\\.mrap)$", var.bucket_name))
    error_message = "S3 also rejects adjacent dots, IP-address names, the prefixes xn--, sthree- and amzn-s3-demo-, and the suffixes -s3alias, --ol-s3, --x-s3, --table-s3 and .mrap."
  }
}

variable "key_prefix" {
  type        = string
  default     = ""
  description = "Optional key prefix inside the bucket, without leading or trailing slashes. Both role policies are scoped to it."
  validation {
    # No `*` or `?`: the prefix is interpolated into IAM resource ARNs,
    # where they are wildcards and would widen the grant.
    condition     = can(regex("^([A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*)?$", var.key_prefix))
    error_message = "Path segments of letters, digits, dot, underscore and hyphen, joined by single slashes, with none at either end."
  }
}

variable "kms_key_arn" {
  type        = string
  default     = null
  description = "A customer-managed KMS key. Null means SSE-S3. The key policy must let this account's IAM grant use of it, or both roles get AccessDenied."
}

variable "writer_role_name" {
  type    = string
  default = "forgd-verdict-writer"
}

variable "writer_assume_role_policy" {
  type        = string
  description = "Trust policy JSON for the writer role: an IRSA or Pod Identity principal on EKS, ecs-tasks.amazonaws.com on ECS."
  validation {
    condition     = can(jsondecode(var.writer_assume_role_policy))
    error_message = "Must be a JSON policy document."
  }
}

variable "reader_role_name" {
  type        = string
  default     = "forgd-dashboard-reader"
  description = "The dashboard's role. Reader only: it must not be able to rewrite the evidence."
}

variable "reader_assume_role_policy" {
  type        = string
  description = "Trust policy JSON for the reader role. Trust only the dashboard: anything else that can assume this role reads every finding."
  validation {
    condition     = can(jsondecode(var.reader_assume_role_policy))
    error_message = "Must be a JSON policy document."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "control_enabled" {
  type        = bool
  default     = false
  description = "Create the dashboard's control role, for dashboard admins (docs/OVERRIDES.md): the reader's policy plus PutObject on state/runtime-overrides.json and under audit/runtime-overrides/, where a put without If-None-Match is denied. False leaves the plan exactly as it was."
}

variable "control_role_name" {
  type        = string
  default     = "forgd-dashboard-control"
  description = "The control role's name. Used only when control_enabled."
}

variable "control_assume_role_policy" {
  type        = string
  default     = null
  description = "Trust policy JSON for the control role: cluster-eks's control_assume_role_policy, or ecs-tasks.amazonaws.com on ECS. Trust only the dashboard. Required when control_enabled."
  validation {
    condition     = var.control_assume_role_policy == null || can(jsondecode(var.control_assume_role_policy))
    error_message = "Must be a JSON policy document."
  }
}
