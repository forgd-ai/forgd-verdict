variable "project_id" {
  type        = string
  description = "The project that runs the cluster. Its Workload Identity pool, <project>.svc.id.goog, is the one the store accounts trust."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a project id: 6-30 lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "cluster_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,38}[a-z0-9])?$", var.cluster_name))
    error_message = "cluster_name must start with a lowercase letter, be at most 40 lowercase letters, digits and hyphens, and not end with a hyphen."
  }
}

variable "region" {
  type        = string
  description = "A region, e.g. europe-west2. The cluster is regional; a zone is refused."
  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must be a region such as europe-west2, not a zone such as europe-west2-a."
  }
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "deletion_protection" {
  type        = bool
  default     = true
  description = "While true, Terraform refuses to destroy the cluster, so terraform destroy on this module fails until an apply has set it to false."
}

# --- network -------------------------------------------------------------
# The caller's VPC. This module creates none.

variable "network" {
  type        = string
  description = "The VPC network, by name or self link."
}

variable "endpoint_public_access" {
  type        = bool
  default     = false
  description = "Whether the Kubernetes API's IP endpoint is reachable from outside the VPC. Off, the private endpoint admits the node subnet's ranges and private_access_cidrs, so a bastion in another subnet, or a VPN, Interconnect or peered range, must be listed there. The DNS endpoint admits traffic from outside Google Cloud only with dns_endpoint_allow_external_traffic."
}

variable "dns_endpoint_allow_external_traffic" {
  type        = bool
  default     = false
  description = "Whether the DNS-based API endpoint accepts traffic from outside Google Cloud. A request still needs an IAM credential with container.clusters.connect; this opens no IP range and leaves the IP endpoint as endpoint_public_access sets it. CD from a hosted GitHub runner (ci-gcp, scripts/deploy_gcp.sh) needs it on. The alternative is a self-hosted runner inside the VPC with this left off, the same choice a cluster-eks deployment makes by listing the runner in api_allowed_security_group_ids."
}

variable "private_access_cidrs" {
  type        = list(string)
  default     = []
  description = "Internal ranges, beyond the node subnet, that may reach the private API endpoint: a bastion's subnet, a VPN or Interconnect range. Applied whether or not the public endpoint is on."
  validation {
    condition     = alltrue([for c in var.private_access_cidrs : can(cidrhost(c, 0))])
    error_message = "Every entry in private_access_cidrs must be a CIDR block."
  }
}

variable "private_endpoint_global_access" {
  type        = bool
  default     = false
  description = "Whether the private endpoint accepts connections from other regions of the VPC, and over VPN or Interconnect attached in another region. The source must still be in private_access_cidrs or the node subnet."
}

variable "public_access_cidrs" {
  type        = list(string)
  default     = []
  description = "Who may reach the public API endpoint. Required, non-empty, when endpoint_public_access is true; there is no open default."
  validation {
    condition     = alltrue([for c in var.public_access_cidrs : can(cidrhost(c, 0))])
    error_message = "Every entry in public_access_cidrs must be a CIDR block."
  }
}

variable "subnetwork" {
  type        = string
  description = "The subnet for the nodes, in var.region. The nodes have no public addresses, so it needs Cloud NAT, or another route out, to reach Anthropic's APIs."
}

# --- secrets -------------------------------------------------------------

variable "database_encryption_key_name" {
  type        = string
  default     = null
  description = "A Cloud KMS key, projects/.../locations/<region>/keyRings/.../cryptoKeys/..., in the cluster's region, for application-layer encryption of Kubernetes secrets. Null leaves them under Google-managed encryption. The module grants GKE's service agent use of it; IAM can take a minute to propagate, so a first apply that fails on a KMS permission error succeeds when re-run."
  validation {
    condition     = var.database_encryption_key_name == null || can(regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", var.database_encryption_key_name))
    error_message = "A full crypto key name: projects/P/locations/L/keyRings/R/cryptoKeys/K."
  }
}

# --- workload identity ---------------------------------------------------

variable "namespace" {
  type        = string
  default     = "forgd"
  description = "The namespace the chart is installed into. Part of every Workload Identity member; a mismatch authenticates as nothing."
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a Kubernetes namespace name: at most 63 lowercase letters, digits and hyphens."
  }
}

variable "writer_service_account" {
  type        = string
  default     = "forgd-verdict-writer"
  description = "The chart's writer service account: <release fullname>-writer, or serviceAccounts.writer.name."
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", var.writer_service_account))
    error_message = "writer_service_account must be a Kubernetes service account name."
  }
}

variable "reader_service_account" {
  type        = string
  default     = "forgd-verdict-reader"
  description = "The chart's reader service account: <release fullname>-reader, or serviceAccounts.reader.name."
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", var.reader_service_account))
    error_message = "reader_service_account must be a Kubernetes service account name."
  }
}

variable "writer_email" {
  type        = string
  description = "store-gcs's writer_email. The verdict server, collector, intake and ingest job. It may be in another project than the cluster."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.writer_email))
    error_message = "writer_email must be a service account email, <id>@<project>.iam.gserviceaccount.com. Accounts in domain-scoped projects (example.com:project) are not supported."
  }
}

variable "reader_email" {
  type        = string
  description = "store-gcs's reader_email. The dashboard's, and deliberately not the writer's."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.reader_email))
    error_message = "reader_email must be a service account email, <id>@<project>.iam.gserviceaccount.com. Accounts in domain-scoped projects (example.com:project) are not supported."
  }
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
  description = "Bind the chart's control service account to store-gcs's control account, for dashboard.admins.enabled in the chart. False leaves the plan exactly as it was."
}

variable "control_email" {
  type        = string
  default     = ""
  description = "store-gcs's control_email. Required when control_enabled; must differ from writer_email and reader_email."
  validation {
    condition     = var.control_email == "" || can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.control_email))
    error_message = "control_email must be empty or a service account email, <id>@<project>.iam.gserviceaccount.com. Accounts in domain-scoped projects (example.com:project) are not supported."
  }
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
