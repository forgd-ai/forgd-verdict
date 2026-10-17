variable "subscription_id" { type = string }
variable "resource_group_name" { type = string }

variable "storage_account_name" {
  type        = string
  description = "This stack's OWN account. A root stack owns its findings store outright, so a destroy in another stack cannot reach it."
}

variable "cluster_name" {
  type    = string
  default = "aks-forgd-verdict"
}

# node_vm_size and node_count are deliberately NOT declared here.
#
# Declared here with their own defaults, they would make the module's
# defaults dead: a change to the VM size in the module would change nothing,
# because this file shadows it. Same shape as a `location` variable whose
# default disagrees with the group -- one value in two places, and the copy
# that loses is the one carrying the reasoning.
#
# The module owns them, next to the quota arithmetic that explains them.
# Override with TF_VAR_node_vm_size only after reading that.

variable "registry_id" {
  type        = string
  default     = ""
  description = "Resource id of the registry holding the image, for the kubelet's AcrPull grant."
}

variable "namespace" {
  type    = string
  default = "forgd"
}

variable "tags" {
  type    = map(string)
  default = { project = "forgd-verdict" }
}

variable "enable_azure_monitor" {
  description = <<-TXT
    Adapter 5's Azure Monitor destination. Off by default: it creates a Log
    Analytics workspace, which bills per GB ingested and per GB retained,
    and a fork must choose that rather than inherit it.
  TXT
  type        = bool
  default     = false
}

variable "monitor_retention_days" {
  type    = number
  default = 30
}

variable "monitor_daily_quota_gb" {
  type    = number
  default = 1
}

# The API server. Each default is cluster-aks's; see its variables.tf.

variable "private_cluster_enabled" {
  type    = bool
  default = true
}

variable "api_server_authorized_ip_ranges" {
  type    = list(string)
  default = []
}

variable "allow_unrestricted_public_api_server" {
  type    = bool
  default = false
}

variable "local_account_disabled" {
  type    = bool
  default = true
}

variable "sku_tier" {
  type        = string
  default     = "Standard"
  description = "The cluster's AKS pricing tier; see the cluster-aks variable for the trade-off."
}

variable "entra_admin_group_object_ids" {
  type    = list(string)
  default = []
}

# Null, as in the module, keeps the VNet AKS creates and AKS's ranges.
variable "vnet_subnet_id" {
  type    = string
  default = null
}

variable "pod_cidr" {
  type    = string
  default = null
}

variable "service_cidr" {
  type    = string
  default = null
}

variable "dns_service_ip" {
  type    = string
  default = null
}

# store-azure's default; see its variables.tf. It also sets the provider's
# storage settings in main.tf.
variable "shared_access_key_enabled" {
  type    = bool
  default = false
}

# store-azure's default; see its variables.tf. 0 or null turns container
# soft delete off.
variable "container_delete_retention_days" {
  type     = number
  default  = 30
  nullable = true
}
