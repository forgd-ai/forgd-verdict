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
  description = "LRS is enough for findings: they are derived data, and a rescan reproduces them."
}

variable "soft_delete_days" {
  type        = number
  default     = 30
  description = "Recovery from a hand-deleted partition, not from our own writes -- the store never rewrites an object."
}

variable "public_network_access" {
  type        = bool
  default     = true
  description = "False needs a private endpoint, or the dashboard loses its store with no error that says so."
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

variable "shared_access_key_enabled" {
  type    = bool
  default = false
}
