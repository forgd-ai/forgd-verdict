variable "project_id" { type = string }

variable "location" {
  type        = string
  description = "The key ring's location, such as europe-west2 or global."
}

variable "key_ring_name" {
  type    = string
  default = "forgd-verdict-seal"
}

variable "key_name" {
  type    = string
  default = "forgd-verdict-seal"
}

variable "algorithm" {
  type        = string
  default     = "RSA_DECRYPT_OAEP_3072_SHA256"
  description = "RSA_DECRYPT_OAEP_3072_SHA256 or RSA_DECRYPT_OAEP_4096_SHA256, the two privacy.sealing takes."
  validation {
    condition     = contains(["RSA_DECRYPT_OAEP_3072_SHA256", "RSA_DECRYPT_OAEP_4096_SHA256"], var.algorithm)
    error_message = "privacy.sealing takes RSA_DECRYPT_OAEP_3072_SHA256 or RSA_DECRYPT_OAEP_4096_SHA256."
  }
}

variable "protection_level" {
  type    = string
  default = "SOFTWARE"
  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.protection_level)
    error_message = "SOFTWARE or HSM."
  }
}

variable "key_version" {
  type        = number
  default     = 1
  description = "The key version whose public half seals, and whose name goes into privacy.sealing.key.id. Raise it after creating a new version to rotate; the old one goes into privacy.sealing.retired."
}

variable "decrypt_members" {
  type        = list(string)
  description = "Members that may decrypt sealed values, such as group:findings-responders@example.com, so leaving the group removes access. Never a forgd-verdict service account."
}

variable "service_members" {
  type        = list(string)
  description = "Every forgd-verdict service account as a member: store-gcs's writer, reader and control accounts, serviceAccount:<email>. The plan fails if any is in decrypt_members."
}

variable "destroy_scheduled_duration" {
  type        = string
  default     = "2592000s"
  description = "How long a destroyed key version can still be restored, 30 days by default."
}

variable "deletion_policy" {
  type        = string
  default     = "PREVENT"
  description = "PREVENT fails a plan that would destroy the key. Destroying it in Terraform schedules every version for destruction, and with them every value sealed to it."
  validation {
    condition     = contains(["PREVENT", "ABANDON", "DELETE"], var.deletion_policy)
    error_message = "PREVENT, ABANDON or DELETE."
  }
}

variable "labels" {
  type    = map(string)
  default = {}
}
