variable "resource_group_name" { type = string }
variable "location" { type = string }

variable "key_vault_name" {
  type        = string
  description = "Globally unique, 3-24 characters: letters, digits and hyphens. A vault of its own, holding only this key."
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.key_vault_name))
    error_message = "Azure rejects anything else, and it does so after a plan looks fine."
  }
}

variable "key_name" {
  type    = string
  default = "forgd-verdict-seal"
}

variable "key_size" {
  type        = number
  default     = 3072
  description = "RSA-3072 or RSA-4096, the sizes privacy.sealing takes."
  validation {
    condition     = contains([3072, 4096], var.key_size)
    error_message = "privacy.sealing takes RSA-3072 or RSA-4096."
  }
}

variable "decrypt_principal_ids" {
  type        = list(string)
  description = "Object ids that may decrypt sealed values: a group of the people who act on findings, so leaving the group removes access. Never a forgd-verdict service identity."
}

variable "service_principal_ids" {
  type        = list(string)
  description = "The principal ids of every forgd-verdict service identity: store-azure's identity_principal_id, reader_identity_principal_id and control_identity_principal_id. The plan fails if any is in decrypt_principal_ids."
}

variable "deployer_object_id" {
  type        = string
  default     = null
  description = "The object id given create, read and delete on the key, and not decrypt. Defaults to the identity running Terraform."
}

variable "sku_name" {
  type        = string
  default     = "standard"
  description = "standard keeps the key in software; premium in an HSM."
  validation {
    condition     = contains(["standard", "premium"], var.sku_name)
    error_message = "standard or premium."
  }
}

variable "soft_delete_retention_days" {
  type        = number
  default     = 90
  description = "Days a deleted key stays recoverable, 7 to 90. Purge protection is on, so nothing shortens it."
  validation {
    condition     = var.soft_delete_retention_days >= 7 && var.soft_delete_retention_days <= 90
    error_message = "From 7 to 90 days."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
