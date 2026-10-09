variable "resource_group_name" { type = string }
variable "location" { type = string }

variable "storage_account_name" {
  type        = string
  description = "Globally unique, 3-24 lowercase alphanumerics."
  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "Azure rejects anything else, and it does so after a plan looks fine."
  }
}

variable "container_name" {
  type    = string
  default = "findings"
}

variable "identity_name" {
  type    = string
  default = "mi-forgd-verdict-app"
}

variable "replication" {
  type        = string
  default     = "LRS"
  description = "The storage account's replication. LRS keeps three copies in one datacentre. A rescan reproduces the findings of adapters 3 and 6, which pull from Anthropic; those of adapters 1, 2 and 4 record traffic as it arrived and cannot be reproduced."
}

variable "soft_delete_days" {
  type        = number
  default     = 30
  description = "Recovery from a hand-deleted partition, not from our own writes -- the store never rewrites an object."
}

variable "container_delete_retention_days" {
  type        = number
  default     = 30
  nullable    = true
  description = "Days a deleted container, with every blob in it, stays restorable. Without control_enabled the writer holds Storage Blob Data Contributor, which includes containers/delete, and no lock covers the account. 0 or null turns container soft delete off."
  validation {
    condition     = var.container_delete_retention_days == null ? true : contains(range(0, 366), var.container_delete_retention_days)
    error_message = "A whole number of days from 1 to 365, or 0 or null to turn container soft delete off."
  }
}

variable "public_network_access" {
  type        = bool
  default     = true
  description = "False needs a private endpoint, or the dashboard loses its store with no error that says so."
}

variable "shared_access_key_enabled" {
  type        = bool
  default     = false
  description = "Whether the account accepts requests signed with its shared keys. A shared key bypasses every role assignment and condition on the account, and Contributor can list the keys. No component of forgd-verdict uses one. With it false, Terraform must not use the data plane either: set the provider's storage_use_azuread, or features.storage.data_plane_available = false, as examples/aks does."
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "reader_identity_name" {
  type        = string
  default     = "mi-forgd-dashboard"
  description = "The dashboard's identity. Reader only: it must not be able to rewrite the evidence."
}

variable "control_enabled" {
  type        = bool
  default     = false
  description = "Create the dashboard's control identity, for dashboard admins (docs/OVERRIDES.md): a custom role with blob read, and write and add conditioned on state/runtime-overrides.json and audit/runtime-overrides/, and no delete. It also moves the writer and the reader from Storage Blob Data Contributor and Reader to custom roles with blob data actions only, which needs Microsoft.Authorization/roleDefinitions/write on the resource group, and locks the storage account (storage_account_delete_lock). False leaves the plan exactly as it was."
}

variable "control_identity_name" {
  type        = string
  default     = "mi-forgd-dashboard-control"
  description = "The control identity's name. Used only when control_enabled."
}

variable "control_role_name" {
  type        = string
  default     = null
  description = "The custom role's name, unique in the tenant. Null names it after the storage account. Used only when control_enabled."
}

variable "control_evidence_role_name" {
  type        = string
  default     = null
  description = "Name of the custom role letting the control identity read role assignments and role definitions, assigned on the storage account, which is the narrowest scope whose assignment list includes those inherited from the resource group and subscription. Created only with control_enabled. Null names it after the storage account."
}

variable "writer_role_name" {
  type        = string
  default     = null
  description = "The writer's custom role's name, unique in the tenant. Null names it after the storage account. Used only when control_enabled."
}

variable "reader_role_name" {
  type        = string
  default     = null
  description = "The reader's custom role's name, unique in the tenant. Null names it after the storage account. Used only when control_enabled."
}

variable "storage_account_delete_lock" {
  type        = bool
  default     = true
  description = "While control_enabled, put a CanNotDelete management lock on the storage account. It refuses deleting the account, and deleting any role assignment scoped under it, through Resource Manager; it does not stop blob writes or deletes. Set false to opt out, or before destroying the store or removing one of its role assignments. Ignored while control_enabled is false."
}
