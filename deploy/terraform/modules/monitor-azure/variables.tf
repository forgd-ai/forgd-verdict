variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "workspace_name" {
  type    = string
  default = "log-forgd-verdict"
}

variable "endpoint_name" {
  type    = string
  default = "dce-forgd-verdict"
}

variable "rule_name" {
  type    = string
  default = "dcr-forgd-verdict"
}

variable "table_name" {
  description = "Without the _CL suffix, which Azure requires and this module appends."
  type        = string
  default     = "ForgdVerdict"

  validation {
    # The sink's endpoint carries this name, and Azure answers a send to a
    # name it does not have with 404.
    condition     = can(regex("^[A-Za-z][A-Za-z0-9]{2,44}$", var.table_name))
    error_message = "table_name must be alphanumeric, start with a letter, and exclude the _CL suffix."
  }
}

variable "writer_principal_id" {
  description = "The deployment's managed identity. It gets Monitoring Metrics Publisher on the rule and nothing else."
  type        = string
}

variable "retention_days" {
  description = "Log Analytics bills per GB retained. The blob store is the system of record; this copy is for querying."
  type        = number
  default     = 30
}

variable "daily_quota_gb" {
  description = "The workspace's daily ingestion cap, in GB; -1 is uncapped. Adapter 5 forwards every event it receives, finding or not, so volume follows traffic."
  type        = number
  default     = 1
}

variable "tags" {
  type    = map(string)
  default = {}
}
