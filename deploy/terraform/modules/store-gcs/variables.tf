variable "project_id" {
  type        = string
  description = "The project that owns the bucket, both service accounts and the delete role."
}

variable "bucket_name" {
  type        = string
  description = "Globally unique across every Google Cloud project."
  validation {
    # No dots: a dotted name needs domain verification, and it is
    # interpolated into the delete condition, where only these characters
    # are known to be inert.
    condition     = can(regex("^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$", var.bucket_name)) && !startswith(var.bucket_name, "goog") && !can(regex("g(o|0)(o|0)gle", var.bucket_name))
    error_message = "3-63 lowercase letters, digits, hyphens and underscores, starting and ending with a letter or digit, not starting with goog and not containing google."
  }
}

variable "location" {
  type        = string
  description = "A region, dual-region or multi-region, e.g. europe-west2 or EU."
}

variable "key_prefix" {
  type        = string
  default     = ""
  description = "Optional object-name prefix inside the bucket, without leading or trailing slashes. The writer's delete condition is scoped under it."
  validation {
    # The prefix is interpolated into a CEL string in the delete condition,
    # so a quote or backslash would change what the condition matches.
    condition     = can(regex("^([A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*)?$", var.key_prefix))
    error_message = "Path segments of letters, digits, dot, underscore and hyphen, joined by single slashes, with none at either end."
  }
}

variable "kms_key_name" {
  type        = string
  default     = null
  description = "A Cloud KMS key, projects/.../locations/.../keyRings/.../cryptoKeys/..., in the bucket's location. Null means Google-managed encryption. The module grants the project's GCS service agent use of it."
  validation {
    condition     = var.kms_key_name == null || can(regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", var.kms_key_name))
    error_message = "A full crypto key name: projects/P/locations/L/keyRings/R/cryptoKeys/K."
  }
}

variable "writer_account_id" {
  type    = string
  default = "forgd-verdict-writer"
}

variable "reader_account_id" {
  type        = string
  default     = "forgd-dashboard-reader"
  description = "The dashboard's account. Reader only: it must not be able to rewrite the evidence."
}

variable "control_iam_read_role_id" {
  type        = string
  default     = "forgdVerdictStoreControlIamRead"
  description = "Custom role id for the control identity's storage.buckets.getIamPolicy on the bucket, unique in the project. Created only with control_enabled. A deleted custom role keeps its id for 37 days, so a destroy and re-create inside that window needs a new one."
  validation {
    condition     = can(regex("^[A-Za-z0-9_.]{3,64}$", var.control_iam_read_role_id))
    error_message = "3-64 letters, digits, underscores and dots."
  }
}

variable "control_role_read_role_id" {
  type        = string
  default     = "forgdVerdictStoreControlRoleRead"
  description = "Custom role id for the control identity's iam.roles.get on the project, unique in the project. Created only with control_enabled. A deleted custom role keeps its id for 37 days, so a destroy and re-create inside that window needs a new one."
  validation {
    condition     = can(regex("^[A-Za-z0-9_.]{3,64}$", var.control_role_read_role_id))
    error_message = "3-64 letters, digits, underscores and dots."
  }
}

variable "mutable_delete_role_id" {
  type        = string
  default     = "forgdVerdictStoreMutableDelete"
  description = "Custom role id, unique in the project. A deleted custom role keeps its id for 37 days, so a destroy and re-create inside that window needs a new one."
  validation {
    condition     = can(regex("^[A-Za-z0-9_.]{3,64}$", var.mutable_delete_role_id))
    error_message = "3-64 letters, digits, underscores and dots."
  }
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "writer_members" {
  type        = map(string)
  default     = {}
  description = "Extra IAM members by a stable key, e.g. { verdict = \"serviceAccount:verdict@p.iam.gserviceaccount.com\" }. Bindings are keyed on the map key, so adding or removing one member leaves the others in place. Each gets exactly the writer account's bucket bindings: create, read, and delete on the cursors and the two markers, under the same conditions."
  validation {
    condition     = alltrue([for m in values(var.writer_members) : can(regex("^(serviceAccount|user|group|principal|principalSet):[^\\s]+$", m))])
    error_message = "Each writer_members entry must be serviceAccount:, user:, group:, principal: or principalSet: followed by an identity. allUsers, allAuthenticatedUsers and domain: are refused."
  }
}

variable "reader_members" {
  type        = map(string)
  default     = {}
  description = "Extra IAM members by a stable key, as writer_members. Each gets exactly the reader account's bucket binding: get and list, never create or delete."
  validation {
    condition     = alltrue([for m in values(var.reader_members) : can(regex("^(serviceAccount|user|group|principal|principalSet):[^\\s]+$", m))])
    error_message = "Each reader_members entry must be serviceAccount:, user:, group:, principal: or principalSet: followed by an identity. allUsers, allAuthenticatedUsers and domain: are refused."
  }
}

variable "control_enabled" {
  type        = bool
  default     = false
  description = "Create the dashboard's control account, for dashboard admins (docs/OVERRIDES.md). It gets the reader's binding plus create on state/runtime-overrides.json and under audit/runtime-overrides/, and delete on that one object. False leaves the plan exactly as it was."
}

variable "control_account_id" {
  type        = string
  default     = "forgd-dashboard-control"
  description = "The control account's id. Used only when control_enabled."
}

variable "control_members" {
  type        = map(string)
  default     = {}
  description = "Extra IAM members by a stable key, as reader_members, for a dashboard with admins enabled that runs as an account of its own: app-cloudrun's control_members output. Each gets exactly the control account's bindings. A member here must not also be a reader or writer member, and a key must not also be a reader_members key."
  validation {
    condition     = alltrue([for m in values(var.control_members) : can(regex("^(serviceAccount|user|group|principal|principalSet):[^\\s]+$", m))])
    error_message = "Each control_members entry must be serviceAccount:, user:, group:, principal: or principalSet: followed by an identity. allUsers, allAuthenticatedUsers and domain: are refused."
  }
}
