variable "resource_group_name" { type = string }
variable "location" { type = string }

variable "cluster_name" {
  type = string
  validation {
    # Also the dns_prefix, which Azure validates after a plan looks fine.
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$", var.cluster_name))
    error_message = "1-63 alphanumerics and hyphens, not starting or ending with a hyphen."
  }
}

variable "sku_tier" {
  type        = string
  default     = "Standard"
  description = <<-DESC
    The AKS pricing tier. Free: no financially backed uptime SLA on the API
    server, and Azure recommends it for development and test clusters of
    fewer than 10 nodes. Standard: a financially backed uptime SLA on the
    API server (99.95% with availability zones, 99.9% without) and up to
    5,000 nodes, at a per-cluster hourly charge. Premium: Standard plus
    Long Term Support, which also needs the AKSLongTermSupport support plan;
    this module does not set one.
  DESC
  validation {
    condition     = contains(["Free", "Standard", "Premium"], var.sku_tier)
    error_message = "Free, Standard or Premium."
  }
}

variable "node_vm_size" {
  type        = string
  default     = "Standard_D4s_v4"
  description = <<-DESC
    4 vCPU / 16 Gi. DSv4 rather than DSv5, and the reason is not preference:
    a fresh subscription has a LIMIT OF ZERO on the Standard DSv5 family in
    every region, so a DSv5 default cannot be created anywhere until someone
    asks for quota. DSv4 ships with a limit of 10.

    Two quotas apply and both bite. The family quota above, and the regional
    total -- `az vm list-usage --location <region>` shows both. The error
    names whichever it hit first, which makes the other one look fine:

      The VM size of <size> is not allowed in your subscription
      in location '<region>'          <- family limit 0

      Insufficient regional vcpu quota left for location <region>.
      left regional vcpu quota <n>, requested quota <m>   <- regional total

    Check both before changing this or node_count. See the arithmetic in
    main.tf for what the chart needs.

    The REGIONAL total can be raised with `az quota update`; a FAMILY
    increase may need a support request instead. So the default pair below (2 x 4 vCPU
    = 8) creates fine at a family limit of 10 but a cluster UPGRADE, which
    surges one node, would want 12 and be refused. Raise the family quota
    before relying on in-place upgrades.
  DESC
}

variable "node_count" {
  type        = number
  default     = 2
  description = "node_count * the size's vCPU must fit the REGIONAL total, and an upgrade transiently needs one more node's worth on top -- max_surge is 1."
}

variable "registry_id" {
  type        = string
  default     = ""
  description = "The registry holding the image. Empty skips the AcrPull grant, which is right only when the image is public."
}

variable "namespace" {
  type        = string
  default     = "forgd"
  description = "Must match the namespace the chart is installed into: it is part of the federated subject, and a mismatch authenticates as nothing."
}

variable "writer_identity_id" {
  type        = string
  description = "store-azure's identity_id, federated to writer_service_account. store-azure sets its role on the findings container: Storage Blob Data Contributor while store-azure's control_enabled is false; with control_enabled, as control_enabled here needs, the custom writer role, blob read, write and add, under a condition that keeps every blob mutation off the runtime overrides object and its audit records."
}

variable "reader_identity_id" {
  type        = string
  description = "store-azure's reader_identity_id. The dashboard's, and deliberately not the writer's."
}

variable "writer_service_account" {
  type        = string
  description = "Must match the chart's writer service account name exactly."
}

variable "reader_service_account" {
  type        = string
  description = "Must match the chart's reader service account name exactly."
}

variable "app_routing_enabled" {
  type        = bool
  default     = true
  description = "The managed nginx add-on. False means supplying an ingress controller yourself, and the chart's Ingress objects do nothing until you do."
}

variable "tags" {
  type    = map(string)
  default = {}
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
  description = "Federate the chart's control service account to store-azure's control identity, for dashboard.admins.enabled in the chart. False leaves the plan exactly as it was."
}

variable "control_identity_id" {
  type        = string
  default     = ""
  description = "store-azure's control_identity_id. Required when control_enabled; must differ from writer_identity_id and reader_identity_id."
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

# --- the API server ------------------------------------------------------

variable "private_cluster_enabled" {
  type        = bool
  default     = true
  description = "The API server gets a private IP in the cluster's network and no public endpoint. Off, it is public, and admits api_server_authorized_ip_ranges or, with allow_unrestricted_public_api_server, every address. Changing it replaces the cluster."
}

variable "api_server_authorized_ip_ranges" {
  type        = list(string)
  default     = []
  description = "The ranges a public API server admits. Only for a public API server: AKS does not take them on a private cluster. There is no 0.0.0.0/0 default."
  validation {
    condition     = alltrue([for c in var.api_server_authorized_ip_ranges : can(cidrhost(c, 0))])
    error_message = "Every entry in api_server_authorized_ip_ranges must be a CIDR block."
  }
  validation {
    condition     = alltrue([for c in var.api_server_authorized_ip_ranges : try(tonumber(split("/", c)[1]) > 0, false)])
    error_message = "api_server_authorized_ip_ranges may not contain a /0 such as 0.0.0.0/0 or ::/0. List the ranges that need the API."
  }
}

variable "allow_unrestricted_public_api_server" {
  type        = bool
  default     = false
  description = "Accept a public API server with no api_server_authorized_ip_ranges, which admits every address. Without it, that combination is refused at plan time."
}

variable "local_account_disabled" {
  type        = bool
  default     = true
  description = "No static admin kubeconfig: every caller authenticates with Entra ID and is authorized by Azure RBAC, so a caller needs an Azure Kubernetes Service RBAC role on the cluster, or membership of entra_admin_group_object_ids. False keeps local accounts and Kubernetes RBAC, with no Entra integration."
}

variable "entra_admin_group_object_ids" {
  type        = list(string)
  default     = []
  description = "Entra groups given cluster-admin when local_account_disabled is true. Ignored otherwise."
}
