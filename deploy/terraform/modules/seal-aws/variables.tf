variable "alias" {
  type        = string
  default     = "forgd-verdict-seal"
  description = "The key's alias, without the alias/ prefix."
}

variable "description" {
  type    = string
  default = "forgd-verdict: seals matched values (privacy.sealing)"
}

variable "key_spec" {
  type        = string
  default     = "RSA_3072"
  description = "RSA_3072 or RSA_4096, the sizes privacy.sealing takes."
  validation {
    condition     = contains(["RSA_3072", "RSA_4096"], var.key_spec)
    error_message = "privacy.sealing takes RSA_3072 or RSA_4096."
  }
}

variable "decrypt_principal_arns" {
  type        = list(string)
  description = "IAM principals that may decrypt sealed values: the role the people who act on findings assume, so removing someone from it removes access. Never a forgd-verdict service role."
}

variable "service_principal_arns" {
  type        = list(string)
  description = "The ARN of every forgd-verdict service role: store-s3's writer, reader and control roles. The key policy denies them kms:Decrypt, and the plan fails if any is in decrypt_principal_arns."
}

variable "deletion_window_in_days" {
  type        = number
  default     = 30
  description = "Days a key scheduled for deletion can still be cancelled, 7 to 30. Deleting it loses every value sealed to it."
  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "From 7 to 30 days."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
