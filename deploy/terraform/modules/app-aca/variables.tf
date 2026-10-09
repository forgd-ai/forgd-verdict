variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "environment_name" { type = string }

variable "registry_server" {
  type        = string
  description = "e.g. myacr.azurecr.io"
}

variable "image" {
  type        = string
  description = <<-D
    The base image, tag included. Terraform sets it ONCE. Every container
    ignores later changes to it, because CI rolls images and a release
    should not take a state lock -- see DESIGN.md.
  D
}

variable "ingest_image" {
  type        = string
  description = "The -ingest variant. It carries the Presidio T2 tier; the base image would run the job and find nothing, which reads as a clean scan."
}

variable "identity_id" { type = string }
variable "identity_client_id" { type = string }

variable "store_url" {
  type        = string
  description = "From the store-azure module. Every role that writes findings needs it."
  # Identity-based as this repo emits it, so there is nothing to
  # leak -- but it is a URL a fork could put a credential in, and
  # it goes into base_env as a plain env value.
  sensitive = true
}

# --- secrets -------------------------------------------------------------
# Sourced from TF_VAR_*, never from a file in the repo. A state backend holds
# these in plaintext, so use one that is encrypted and access-controlled, or
# name each in Key Vault with its *_secret_id variable below.

variable "hash_salt" {
  type        = string
  sensitive   = true
  default     = ""
  description = <<-D
    Salts the finding digests. EMPTY MEANS A FINDINGS EXPORT CAN BE
    BRUTE-FORCED back to the matched value for anything low-entropy -- an
    SSN has ~1e9 possibilities. The services warn at startup when it is
    empty; this module refuses instead, because a deployment being created
    from scratch has no reason to start wrong.
  D
}

variable "webhook_secret" {
  type        = string
  sensitive   = true
  default     = "placeholder-not-yet-issued"
  description = "Anthropic shows the signing secret once, after the endpoint exists. The placeholder means every hook request is refused with 401, which is the safe failure."
}

variable "compliance_api_key" {
  type        = string
  sensitive   = true
  default     = "placeholder-not-yet-issued"
  description = "Enterprise only. Do NOT grant delete:compliance_user_data."
}

variable "webhook_secret_previous" {
  type        = string
  sensitive   = true
  default     = ""
  description = "The outgoing signing secret during a rotation, surfaced as WEBHOOK_SECRET_PREVIOUS. Empty outside one."
}

variable "webhook_secrets" {
  type        = map(object({ current = string, previous = optional(string, "") }))
  sensitive   = true
  default     = {}
  description = "org_ids name -> that org's Inference hook signing secrets: current, and previous during that org's own rotation. Surfaced to the verdict server as WEBHOOK_SECRET_<NAME> and WEBHOOK_SECRET_<NAME>_PREVIOUS; list both in policy.yaml's server.secrets."
  validation {
    condition     = alltrue([for k in nonsensitive(keys(var.webhook_secrets)) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each webhook_secrets key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes WEBHOOK_SECRET_<NAME>."
  }
  validation {
    condition     = length(distinct([for k in nonsensitive(keys(var.webhook_secrets)) : upper(replace(k, "-", "_"))])) == length(var.webhook_secrets)
    error_message = "Two webhook_secrets keys map to the same WEBHOOK_SECRET_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "compliance_api_keys" {
  type        = map(string)
  sensitive   = true
  default     = {}
  description = "org_ids name -> that org's Compliance Access Key, surfaced to ingest as ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME> for that org's compliance.orgs entry. No previous slot: an entry takes one key. Do NOT grant delete:compliance_user_data."
  validation {
    condition     = alltrue([for k in nonsensitive(keys(var.compliance_api_keys)) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each compliance_api_keys key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME>."
  }
  validation {
    condition     = length(distinct([for k in nonsensitive(keys(var.compliance_api_keys)) : upper(replace(k, "-", "_"))])) == length(var.compliance_api_keys)
    error_message = "Two compliance_api_keys keys map to the same ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "enable_intake" {
  type        = bool
  default     = false
  description = "Adapter 2's receiving end, for developer laptops: a container app serving /intake and /scan. Off by default, as in the Helm chart, app-ecs and app-cloudrun. Needs intake_fleet_token, intake_fleet_tokens or intake_tokens, or their Key Vault ids."
}

variable "intake_app_name" {
  type    = string
  default = "ca-forgd-intake"
}

variable "intake_fleet_token" {
  type        = string
  sensitive   = true
  default     = ""
  description = "The managed fleet's intake token, surfaced to intake as FORGD_INTAKE_FLEET_TOKEN for policy.yaml's intake.fleet. Used only with enable_intake."
}

variable "intake_fleet_token_previous" {
  type        = string
  sensitive   = true
  default     = ""
  description = "The fleet's previous intake token while a rotation is under way, surfaced as FORGD_INTAKE_FLEET_TOKEN_PREVIOUS. Empty otherwise."
}

variable "intake_fleet_tokens" {
  type        = map(object({ current = string, previous = optional(string, "") }))
  sensitive   = true
  default     = {}
  description = "org_ids name -> that org's fleet intake tokens: current, and previous during a rotation. Surfaced to intake as FORGD_INTAKE_FLEET_TOKEN_<NAME> and FORGD_INTAKE_FLEET_TOKEN_<NAME>_PREVIOUS, for an intake.fleet entry with org: $FORGD_ORG_ID_<NAME>. Used only with enable_intake."
  validation {
    condition     = alltrue([for k in nonsensitive(keys(var.intake_fleet_tokens)) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each intake_fleet_tokens key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes FORGD_INTAKE_FLEET_TOKEN_<NAME>."
  }
  validation {
    condition     = length(distinct([for k in nonsensitive(keys(var.intake_fleet_tokens)) : upper(replace(k, "-", "_"))])) == length(var.intake_fleet_tokens)
    error_message = "Two intake_fleet_tokens keys map to the same FORGD_INTAKE_FLEET_TOKEN_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "intake_tokens" {
  type        = map(string)
  sensitive   = true
  default     = {}
  description = "intake client -> its token, surfaced to intake as FORGD_INTAKE_TOKEN_<NAME>: agents, and laptops outside a fleet. Laptops in a managed fleet use intake_fleet_token. Used only with enable_intake."
  validation {
    condition     = alltrue([for k in nonsensitive(keys(var.intake_tokens)) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each intake_tokens key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes FORGD_INTAKE_TOKEN_<NAME>."
  }
  validation {
    condition     = length(distinct([for k in nonsensitive(keys(var.intake_tokens)) : upper(replace(k, "-", "_"))])) == length(var.intake_tokens)
    error_message = "Two intake_tokens keys map to the same FORGD_INTAKE_TOKEN_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "otel_tokens" {
  type        = map(string)
  sensitive   = true
  default     = { primary = "placeholder-not-yet-issued" }
  description = "name -> bearer token for adapter 4, surfaced to the collector as FORGD_OTEL_TOKEN_<NAME> with the name upper-cased and hyphens as underscores, as the Helm chart does. One per organization: the token is both the authentication and the routing key. Each name needs an org_ids entry with a non-empty id that maps to the same <NAME>; only the placeholder is exempt. With every token in otel_token_secret_ids, set this to {}."
  validation {
    condition     = alltrue([for k in nonsensitive(keys(var.otel_tokens)) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each otel_tokens key must be letters, digits, - or _, and start and end with a letter or digit: it also names a Container Apps secret."
  }
  validation {
    condition     = length(distinct([for k in nonsensitive(keys(var.otel_tokens)) : upper(replace(k, "-", "_"))])) == length(var.otel_tokens)
    error_message = "Two otel_tokens keys map to the same FORGD_OTEL_TOKEN_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "metrics_token" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Empty disables /metrics and /stats entirely, on the verdict server, the collector and the intake, which is the right default when the alternative is publishing an org's deny rate. metrics_token_secret_id names it in Key Vault instead."
}

# --- the same secrets, named in Key Vault ---------------------------------
# Each *_secret_id stands in for the variable it names, and the value never
# passes through Terraform. Setting both is refused.

variable "webhook_secret_id" {
  type        = string
  default     = ""
  description = "The Key Vault secret id, versioned or versionless, holding WEBHOOK_SECRET, in place of webhook_secret: the app reads it through a Key Vault reference as identity_id, and the value is never in the Terraform state. That identity needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = var.webhook_secret_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.webhook_secret_id))
    error_message = "webhook_secret_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "webhook_secret_previous_id" {
  type        = string
  default     = ""
  description = "The Key Vault secret id, versioned or versionless, holding WEBHOOK_SECRET_PREVIOUS, in place of webhook_secret_previous: the app reads it through a Key Vault reference as identity_id, and the value is never in the Terraform state. That identity needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = var.webhook_secret_previous_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.webhook_secret_previous_id))
    error_message = "webhook_secret_previous_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "hash_salt_secret_id" {
  type        = string
  default     = ""
  description = "The Key Vault secret id, versioned or versionless, holding FORGD_HASH_SALT, in place of hash_salt: the app reads it through a Key Vault reference as identity_id, and the value is never in the Terraform state. That identity needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = var.hash_salt_secret_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.hash_salt_secret_id))
    error_message = "hash_salt_secret_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "metrics_token_secret_id" {
  type        = string
  default     = ""
  description = "The Key Vault secret id, versioned or versionless, holding FORGD_METRICS_TOKEN, in place of metrics_token: the app reads it through a Key Vault reference as identity_id, and the value is never in the Terraform state. That identity needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = var.metrics_token_secret_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.metrics_token_secret_id))
    error_message = "metrics_token_secret_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "compliance_key_secret_id" {
  type        = string
  default     = ""
  description = "The Key Vault secret id, versioned or versionless, holding ANTHROPIC_COMPLIANCE_ACCESS_KEY, in place of compliance_api_key: the app reads it through a Key Vault reference as identity_id, and the value is never in the Terraform state. That identity needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = var.compliance_key_secret_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.compliance_key_secret_id))
    error_message = "compliance_key_secret_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "intake_fleet_token_secret_id" {
  type        = string
  default     = ""
  description = "The Key Vault secret id, versioned or versionless, holding FORGD_INTAKE_FLEET_TOKEN, in place of intake_fleet_token: the app reads it through a Key Vault reference as identity_id, and the value is never in the Terraform state. That identity needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant. Used only with enable_intake."
  validation {
    condition     = var.intake_fleet_token_secret_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.intake_fleet_token_secret_id))
    error_message = "intake_fleet_token_secret_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "intake_fleet_token_previous_secret_id" {
  type        = string
  default     = ""
  description = "The Key Vault secret id, versioned or versionless, holding FORGD_INTAKE_FLEET_TOKEN_PREVIOUS, in place of intake_fleet_token_previous: the app reads it through a Key Vault reference as identity_id, and the value is never in the Terraform state. That identity needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant. Used only with enable_intake."
  validation {
    condition     = var.intake_fleet_token_previous_secret_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.intake_fleet_token_previous_secret_id))
    error_message = "intake_fleet_token_previous_secret_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "dashboard_auth_client_secret_secret_id" {
  type        = string
  default     = ""
  description = "The Key Vault secret id, versioned or versionless, holding the dashboard's Entra client secret, in place of dashboard_auth_client_secret: the app reads it through a Key Vault reference as reader_identity_id, and the value is never in the Terraform state. That identity needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant. Used only with dashboard_auth_client_id."
  validation {
    condition     = var.dashboard_auth_client_secret_secret_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.dashboard_auth_client_secret_secret_id))
    error_message = "dashboard_auth_client_secret_secret_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "dashboard_form_key_secret_id" {
  type        = string
  default     = ""
  description = "The Key Vault secret id, versioned or versionless, holding FORGD_DASHBOARD_FORM_KEY, in place of dashboard_form_key: the app reads it through a Key Vault reference as control_identity_id, and the value is never in the Terraform state. That identity needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant. Used only with dashboard_admins_enabled."
  validation {
    condition     = var.dashboard_form_key_secret_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.dashboard_form_key_secret_id))
    error_message = "dashboard_form_key_secret_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "webhook_secret_ids" {
  type        = map(object({ current = string, previous = optional(string, "") }))
  default     = {}
  description = "webhook_secrets, by Key Vault secret id: name -> current and previous ids, read through Key Vault references as identity_id, so no value is in the Terraform state. A name may be in webhook_secrets or here, not both. Each name becomes WEBHOOK_SECRET_<NAME> as it does from webhook_secrets. identity_id needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = alltrue([for k in keys(var.webhook_secret_ids) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each webhook_secret_ids key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes WEBHOOK_SECRET_<NAME>."
  }
  validation {
    condition     = alltrue(flatten([for k, v in var.webhook_secret_ids : [can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", v.current)), v.previous == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", v.previous))]]))
    error_message = "In webhook_secret_ids, current and previous must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "compliance_key_secret_ids" {
  type        = map(string)
  default     = {}
  description = "compliance_api_keys, by Key Vault secret id: name -> id, read through Key Vault references as identity_id, so no value is in the Terraform state. A name may be in compliance_api_keys or here, not both. Each name becomes ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME> as it does from compliance_api_keys. identity_id needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = alltrue([for k in keys(var.compliance_key_secret_ids) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each compliance_key_secret_ids key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME>."
  }
  validation {
    condition     = alltrue([for k, v in var.compliance_key_secret_ids : can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", v))])
    error_message = "In compliance_key_secret_ids, each value must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "intake_fleet_token_secret_ids" {
  type        = map(object({ current = string, previous = optional(string, "") }))
  default     = {}
  description = "intake_fleet_tokens, by Key Vault secret id: name -> current and previous ids, read through Key Vault references as identity_id, so no value is in the Terraform state. A name may be in intake_fleet_tokens or here, not both. Each name becomes FORGD_INTAKE_FLEET_TOKEN_<NAME> as it does from intake_fleet_tokens. identity_id needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = alltrue([for k in keys(var.intake_fleet_token_secret_ids) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each intake_fleet_token_secret_ids key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes FORGD_INTAKE_FLEET_TOKEN_<NAME>."
  }
  validation {
    condition     = alltrue(flatten([for k, v in var.intake_fleet_token_secret_ids : [can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", v.current)), v.previous == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", v.previous))]]))
    error_message = "In intake_fleet_token_secret_ids, current and previous must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "intake_token_secret_ids" {
  type        = map(string)
  default     = {}
  description = "intake_tokens, by Key Vault secret id: name -> id, read through Key Vault references as identity_id, so no value is in the Terraform state. A name may be in intake_tokens or here, not both. Each name becomes FORGD_INTAKE_TOKEN_<NAME> as it does from intake_tokens. identity_id needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = alltrue([for k in keys(var.intake_token_secret_ids) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each intake_token_secret_ids key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes FORGD_INTAKE_TOKEN_<NAME>."
  }
  validation {
    condition     = alltrue([for k, v in var.intake_token_secret_ids : can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", v))])
    error_message = "In intake_token_secret_ids, each value must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "otel_token_secret_ids" {
  type        = map(string)
  default     = {}
  description = "otel_tokens, by Key Vault secret id: name -> id, read through Key Vault references as identity_id, so no value is in the Terraform state. A name may be in otel_tokens or here, not both. Each name becomes FORGD_OTEL_TOKEN_<NAME> as it does from otel_tokens. identity_id needs Key Vault Secrets User (or get on secrets) on the vault, which this module does not grant."
  validation {
    condition     = alltrue([for k in keys(var.otel_token_secret_ids) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each otel_token_secret_ids key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes FORGD_OTEL_TOKEN_<NAME>."
  }
  validation {
    condition     = alltrue([for k, v in var.otel_token_secret_ids : can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", v))])
    error_message = "In otel_token_secret_ids, each value must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

# --- behaviour -----------------------------------------------------------

variable "policy_yaml" {
  type        = string
  description = <<-D
    The contents of policy.yaml, mounted rather than baked. Changing a
    detector threshold should be a config change, never an image rebuild.
    Pass it as file(...) pointing at the repo root policy.yaml.
  D
}

variable "verdict_mode" {
  type        = string
  default     = "observe"
  description = "observe | enforce. observe records what it would have denied and denies nothing."
  validation {
    condition     = contains(["observe", "enforce", "archive"], var.verdict_mode)
    error_message = "verdict_mode must be observe, enforce or archive."
  }
}

variable "otel_fleets" {
  description = "fleet name -> the org_ids names its exporter token is valid for. The token is otel_tokens[<fleet>], surfaced to the collector as FORGD_OTEL_TOKEN_<FLEET> for an otel.orgs entry with ids: [$FORGD_ORG_ID_<NAME>, ...]. Every name must be an org_ids key with an id, never an org id itself, and a fleet cannot share a name with an org."
  type        = map(list(string))
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.otel_fleets) : can(regex("^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$", k))])
    error_message = "Each otel_fleets key must be letters, digits, hyphens or underscores, starting and ending with a letter or digit: it becomes FORGD_OTEL_TOKEN_<NAME>."
  }
}

variable "org_ids" {
  type        = map(string)
  default     = {}
  description = "name -> organization UUID (8-4-4-4-12 hex, any case), surfaced as FORGD_ORG_ID_<NAME> with the name upper-cased and hyphens as underscores, as the Helm chart does. An empty or non-UUID value is refused. Not in policy.yaml: an org id names a customer and the policy file is committed."
  validation {
    condition     = alltrue([for k in keys(var.org_ids) : can(regex("^[A-Za-z0-9_-]+$", k))])
    error_message = "Each org_ids key must be letters, digits, - or _."
  }
  validation {
    condition     = alltrue([for id in values(var.org_ids) : can(regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$", id))])
    error_message = "org_ids.${join(", org_ids.", [for k, id in var.org_ids : k if !can(regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$", id))])} is not an organization UUID (8-4-4-4-12 hex). The collector cross-checks a batch's organization.id against it, and an empty id disables that check."
  }
  validation {
    condition     = length(distinct([for k in keys(var.org_ids) : upper(replace(k, "-", "_"))])) == length(var.org_ids)
    error_message = "Two org_ids keys map to the same FORGD_ORG_ID_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "ingest_cron" {
  type    = string
  default = "0 */6 * * *"
}

variable "tags" {
  type    = map(string)
  default = {}
}

# --- resource names ------------------------------------------------------
variable "verdict_app_name" {
  type    = string
  default = "ca-forgd-verdict"
}
variable "collector_app_name" {
  type    = string
  default = "ca-forgd-collector"
}
variable "dashboard_app_name" {
  type    = string
  default = "ca-forgd-dashboard"
}
variable "ingest_job_name" {
  type    = string
  default = "cj-forgd-ingest"
}

variable "reader_identity_id" {
  type        = string
  description = <<-D
    store-azure's reader identity, with Storage Blob Data Reader, or its
    custom reader role while control_enabled is true: blob read only. The connector runs as it, and so does the dashboard unless
    dashboard_admins_enabled. With admins on, the dashboard runs as
    control_identity_id and keeps the reader attached only to pull the image.
  D
}
variable "reader_identity_client_id" { type = string }

variable "registry_id" {
  type        = string
  description = "The registry's resource id, so AcrPull can be granted on it. Without that grant no revision can provision, and the failure arrives at apply rather than at plan."
}
variable "identity_principal_id" { type = string }
variable "reader_identity_principal_id" { type = string }

# --- the dashboard's Entra front end -------------------------------------
variable "dashboard_auth_client_id" {
  type        = string
  default     = ""
  description = <<-D
    Entra app registration for the dashboard's sign-in. EMPTY means no
    platform auth is configured, which is correct only when something else
    fronts it -- an ALB, an oauth2-proxy, or the app's own `oidc_jwt` mode.

    With the app in `trusted_header` mode and this empty, the module sets
    FORGD_DASHBOARD_STRIPPED_BY to an empty string, and the dashboard
    refuses to start: no proxy strips inbound copies of the header.

    The app registration needs `https://<dashboard-fqdn>/.auth/login/aad/callback`
    as a redirect URI, which Terraform cannot add for you because the FQDN
    does not exist until the app does.
  D
}

variable "dashboard_auth_tenant_id" {
  type    = string
  default = ""
}

variable "dashboard_auth_client_secret" {
  type      = string
  sensitive = true
  default   = ""
}

# --- the findings connector ----------------------------------------------
variable "connector_enabled" {
  type        = bool
  default     = false
  description = "Run the findings connector, a read-only MCP server over the store added to Claude as a custom connector. See docs/CONNECTOR.md. False leaves the plan exactly as it was."
}

variable "connector_app_name" {
  type    = string
  default = "ca-forgd-connector"
}

variable "connector_resource" {
  type        = string
  default     = ""
  description = <<-D
    The canonical MCP URL, the one entered in Claude. Empty derives
    https://<connector_app_name>.<environment default domain>/mcp, the host
    Container Apps serves the connector on.

    Set, it must be a lowercase https URL ending in /mcp, checked at plan,
    and must equal https://<connector_custom_host>/mcp when
    connector_custom_host is set, else the derived default. Against a custom
    host the equality is checked at plan. Against the default it needs the
    environment's default domain, which is unknown until the environment
    exists, so on the first apply it is checked at apply, before the
    connector is created.
  D
}

variable "connector_custom_host" {
  type        = string
  default     = ""
  description = <<-D
    A hostname you bind to the connector app yourself, e.g.
    mcp.example.com. This module creates no custom-domain binding and no
    certificate; it only matches connector_resource against this host.
    Set, connector_resource must be set to https://<this host>/mcp.
  D
  validation {
    condition     = var.connector_custom_host == "" || can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.connector_custom_host))
    error_message = "connector_custom_host must be a lowercase hostname, with no scheme, port or path."
  }
}

variable "connector_scopes" {
  type        = list(string)
  default     = []
  description = "What Claude requests at sign-in. On Entra, the full name under the Application ID URI."
}

variable "connector_required_scope" {
  type        = string
  default     = ""
  description = "Checked against the token's scp or scope claim; on Entra, the short name, e.g. findings.read. Required when connector_enabled, here or as connector.required_scope in policy.yaml."
}

variable "connector_allowed_origins" {
  type        = list(string)
  default     = []
  description = "Browser origins allowed on a request that carries Origin. Empty is https://claude.ai."
}

variable "connector_issuer" {
  type        = string
  default     = ""
  description = "e.g. https://login.microsoftonline.com/<tenant>/v2.0. Required unless connector_issuers is set."
}

variable "connector_jwks_url" {
  type        = string
  default     = ""
  description = "e.g. https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys. Required unless connector_issuers is set."
}

variable "connector_audience" {
  type        = list(string)
  default     = []
  description = "Accepted token audiences. Required unless connector_issuers is set."
}

variable "connector_groups_claim" {
  type        = string
  default     = ""
  description = "Empty is groups."
}

variable "connector_issuers" {
  type = list(object({
    issuer       = string
    jwks_url     = string
    audience     = list(string)
    groups_claim = optional(string, "")
  }))
  default     = []
  description = "More identity providers, in place of connector_issuer, connector_jwks_url and connector_audience. The first is the one Claude signs in with."
}

variable "connector_source_ranges" {
  type        = list(string)
  default     = []
  description = <<-D
    An optional allowlist on the connector's ingress, off by default.
    Anthropic's published egress range is 160.79.104.0/21 today, and it has
    changed before; a stale entry fails in Claude as "Couldn't reach the MCP
    server". It also cuts off Claude Code, which connects from the user's
    machine.
  D
}

# --- dashboard admins ----------------------------------------------------
variable "overrides_writer_lockout" {
  type        = bool
  default     = false
  description = "store-azure's overrides_writer_lockout output: whether the store module's control_enabled takes the writers' writes to the runtime overrides away. dashboard_admins_enabled is refused unless it is true. The services also prove it at runtime (docs/OVERRIDES.md)."
}

variable "dashboard_admins_enabled" {
  type        = bool
  default     = false
  description = "Runtime overrides from the dashboard (docs/OVERRIDES.md). True runs the dashboard as control_client_id and gives it FORGD_DASHBOARD_FORM_KEY and FORGD_OVERRIDES_SIGNING_KEY, and gives every role FORGD_OVERRIDES_VERIFY_KEY. The policy's dashboard.admins says who is an admin. False leaves the plan exactly as it was."
}

variable "overrides_writer_identities" {
  type        = list(string)
  default     = []
  description = "store-azure's overrides_writer_identities output: the writer principal ids whose lockout the dashboard verifies from their role assignments, as FORGD_OVERRIDES_WRITER_IDENTITIES. Required when dashboard_admins_enabled."
}

variable "overrides_storage_account_id" {
  type        = string
  default     = ""
  description = "store-azure's storage_account_id output, the scope at which the dashboard lists the writers' role assignments, as FORGD_OVERRIDES_STORAGE_ACCOUNT_ID. Required when dashboard_admins_enabled."
}

variable "control_identity_id" {
  type        = string
  default     = ""
  description = "store-azure's control_identity_id. Required when dashboard_admins_enabled; must differ from identity_id and reader_identity_id."
}

variable "control_client_id" {
  type        = string
  default     = ""
  description = "store-azure's control_identity_client_id. Required when dashboard_admins_enabled; must differ from identity_client_id and reader_identity_client_id."
}

variable "dashboard_form_key" {
  type        = string
  sensitive   = true
  default     = ""
  description = "FORGD_DASHBOARD_FORM_KEY, the HMAC key for the dashboard's admin form tokens. Required, at least 32 characters, when dashboard_admins_enabled. openssl rand -base64 32"
}

variable "dashboard_signing_key_secret_id" {
  type        = string
  default     = ""
  description = <<-D
    The Key Vault secret id, versioned or versionless, holding
    FORGD_OVERRIDES_SIGNING_KEY: the Ed25519 private key the dashboard signs
    every runtime-override record with. Only the dashboard gets it, as a
    Key Vault reference Container Apps reads with control_identity_id. That
    identity needs Key Vault Secrets User (or get on secrets) on the vault,
    which this module does not grant. Required when dashboard_admins_enabled.
  D
  validation {
    condition     = var.dashboard_signing_key_secret_id == "" || can(regex("^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[0-9a-f]{32})?$", var.dashboard_signing_key_secret_id))
    error_message = "dashboard_signing_key_secret_id must be a Key Vault secret id: https://<vault>.vault.azure.net/secrets/<name>, optionally followed by /<32 hex digit version>."
  }
}

variable "overrides_verify_keys" {
  type        = list(string)
  default     = []
  description = <<-D
    The Ed25519 public keys every role verifies runtime-override records
    against, each 32 bytes as unpadded URL-safe base64 (43 characters), set
    comma-separated as FORGD_OVERRIDES_VERIFY_KEY. Required when
    dashboard_admins_enabled. This module cannot check that the public half
    of the signing key is listed; the dashboard refuses to start when it is
    not.
  D
  validation {
    condition     = alltrue([for k in var.overrides_verify_keys : can(regex("^[A-Za-z0-9_-]{43}$", k))])
    error_message = "Each overrides_verify_keys entry must be an Ed25519 public key as unpadded URL-safe base64: exactly 43 characters from A-Z, a-z, 0-9, - and _."
  }
}
