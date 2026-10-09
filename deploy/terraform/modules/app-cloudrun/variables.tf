variable "project_id" {
  type        = string
  description = "The project that runs the services, the job and the service accounts. The secrets may live in another project; their ids say which."
}

variable "region" {
  type        = string
  description = "The Cloud Run and Cloud Scheduler region, e.g. europe-west2."
}

variable "name_prefix" {
  type        = string
  default     = "forgd-verdict"
  description = "Prefixes every service, the job and every service account. A service account id is at most 30 characters, and the longest suffix here is -scheduler."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,18}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must start with a letter, be lowercase letters, digits and hyphens, not end with a hyphen, and be 6-20 characters, so that <prefix>-scheduler fits a 30-character service account id."
  }
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "enable_intake" {
  type        = bool
  default     = false
  description = "Adapter 2's receiving end, for developer laptops. Off by default, as in the Helm chart and app-ecs."
}

# --- images --------------------------------------------------------------

variable "image" {
  type        = string
  description = <<-D
    The base image, tag included. Terraform sets it ONCE. Every service
    ignores later changes to it, because CI rolls images and a release
    should not take a state lock.
  D
}

variable "ingest_image" {
  type        = string
  description = "The -ingest variant. It carries the Presidio T2 tier; the base image would run the job and find nothing, which reads as a clean scan."
}

# --- the store -----------------------------------------------------------
# store-gcs's store_url. This module creates no bucket IAM: store-gcs binds
# the accounts in this module's writer_members and reader_members outputs.

variable "store_url" {
  type        = string
  description = "store-gcs's store_url. It goes into every container as a plain environment value, so it must name a bucket, never carry a credential."
  validation {
    condition     = startswith(var.store_url, "gs://")
    error_message = "store_url must be a gs:// URL, from the store-gcs module."
  }
}

# --- secrets -------------------------------------------------------------
# Secret Manager secret ids, projects/<project>/secrets/<name>, never values.
# Cloud Run resolves the latest version of each at instance start, so no
# secret value is a Terraform variable or reaches state. Create the secrets,
# each with a version, before the apply, with a placeholder where a value is
# not yet issued: a secret with no version stops the revision from starting.

variable "hash_salt_secret_id" {
  type        = string
  description = <<-D
    Salts the finding digests. An empty salt means a findings export can be
    brute-forced back to the matched value for anything low-entropy -- an
    SSN has ~1e9 possibilities. This module cannot see the value to refuse a
    short one; make it at least 16 characters (openssl rand -base64 32).
  D
  validation {
    condition     = can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", var.hash_salt_secret_id))
    error_message = "hash_salt_secret_id must be a secret id, projects/<project>/secrets/<name>."
  }
}

variable "webhook_secret_id" {
  type        = string
  default     = ""
  description = "The Inference hooks signing secret. Anthropic shows it once, after the endpoint exists, so create the secret with a placeholder version first: every hook request is then refused with 401, which is the safe failure. May be empty when webhook_secret_ids names an org."
  validation {
    condition     = var.webhook_secret_id == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", var.webhook_secret_id))
    error_message = "webhook_secret_id must be empty or a secret id, projects/<project>/secrets/<name>."
  }
}

variable "webhook_secret_previous_id" {
  type        = string
  default     = ""
  description = "The outgoing signing secret during a rotation. Empty outside one."
  validation {
    condition     = var.webhook_secret_previous_id == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", var.webhook_secret_previous_id))
    error_message = "webhook_secret_previous_id must be empty or a secret id, projects/<project>/secrets/<name>."
  }
}

variable "otel_token_secret_ids" {
  type        = map(string)
  description = "name -> secret id, surfaced to the collector as FORGD_OTEL_TOKEN_<NAME>. One per organization: the token is both the authentication and the routing key. Each name needs an org_ids entry with a non-empty id that maps to the same <NAME>."
  validation {
    condition     = length(var.otel_token_secret_ids) > 0
    error_message = "otel_token_secret_ids needs at least one entry, or the collector accepts nothing."
  }
  validation {
    condition = alltrue([for name, id in var.otel_token_secret_ids :
      can(regex("^[A-Za-z0-9_-]+$", name)) &&
      can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", id))
    ])
    error_message = "Each otel_token_secret_ids key must be letters, digits, - or _, and each value a secret id, projects/<project>/secrets/<name>."
  }
  validation {
    condition     = length(distinct([for k in keys(var.otel_token_secret_ids) : upper(replace(k, "-", "_"))])) == length(var.otel_token_secret_ids)
    error_message = "Two otel_token_secret_ids keys map to the same FORGD_OTEL_TOKEN_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "compliance_key_secret_id" {
  type        = string
  default     = ""
  description = "The Compliance Access Key, for ingest. Enterprise only. Do NOT grant delete:compliance_user_data. May be empty when compliance_key_secret_ids names an org."
  validation {
    condition     = var.compliance_key_secret_id == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", var.compliance_key_secret_id))
    error_message = "compliance_key_secret_id must be empty or a secret id, projects/<project>/secrets/<name>."
  }
}

variable "metrics_token_secret_id" {
  type        = string
  default     = ""
  description = "Empty disables /metrics and /stats entirely, which is the right default when the alternative is publishing an org's deny rate."
  validation {
    condition     = var.metrics_token_secret_id == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", var.metrics_token_secret_id))
    error_message = "metrics_token_secret_id must be empty or a secret id, projects/<project>/secrets/<name>."
  }
}

variable "intake_fleet_token_secret_id" {
  type        = string
  default     = ""
  description = "Secret id of the managed fleet's intake token, surfaced to intake as FORGD_INTAKE_FLEET_TOKEN for policy.yaml's intake.fleet. Used only with enable_intake."
  validation {
    condition     = var.intake_fleet_token_secret_id == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", var.intake_fleet_token_secret_id))
    error_message = "intake_fleet_token_secret_id must be empty or a secret id, projects/<project>/secrets/<name>."
  }
}

variable "intake_fleet_token_previous_secret_id" {
  type        = string
  default     = ""
  description = "Secret id of the fleet's previous intake token while a rotation is under way, surfaced as FORGD_INTAKE_FLEET_TOKEN_PREVIOUS. Empty otherwise."
  validation {
    condition     = var.intake_fleet_token_previous_secret_id == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", var.intake_fleet_token_previous_secret_id))
    error_message = "intake_fleet_token_previous_secret_id must be empty or a secret id, projects/<project>/secrets/<name>."
  }
}

variable "intake_token_secret_ids" {
  type        = map(string)
  default     = {}
  description = "intake client -> secret id, surfaced to intake as FORGD_INTAKE_TOKEN_<NAME>: agents, and laptops outside a fleet. Laptops in a managed fleet use intake_fleet_token_secret_id. Used only with enable_intake."
  validation {
    condition = alltrue([for name, id in var.intake_token_secret_ids :
      can(regex("^[A-Za-z0-9_-]+$", name)) &&
      can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", id))
    ])
    error_message = "Each intake_token_secret_ids key must be letters, digits, - or _, and each value a secret id, projects/<project>/secrets/<name>."
  }
  validation {
    condition     = length(distinct([for k in keys(var.intake_token_secret_ids) : upper(replace(k, "-", "_"))])) == length(var.intake_token_secret_ids)
    error_message = "Two intake_token_secret_ids keys map to the same FORGD_INTAKE_TOKEN_<NAME> once upper-cased with hyphens as underscores."
  }
}

# --- the dashboard's sign-in ---------------------------------------------

variable "dashboard_iap_members" {
  type        = list(string)
  description = <<-D
    Who IAP lets through to the dashboard, as IAM members: user:, group:,
    domain: or serviceAccount:. Bound on the dashboard service only. There is
    no default: an empty list would make a dashboard nobody can open, and a
    broad one would publish the findings.
  D
  validation {
    condition     = length(var.dashboard_iap_members) > 0
    error_message = "dashboard_iap_members needs at least one member, e.g. group:security@example.com."
  }
  validation {
    condition     = alltrue([for m in var.dashboard_iap_members : can(regex("^(user|group|domain|serviceAccount):[^\\s]+$", m))])
    error_message = "Each dashboard_iap_members entry must be user:, group:, domain: or serviceAccount: followed by an identity. allUsers and allAuthenticatedUsers are refused."
  }
}

# --- behaviour -----------------------------------------------------------

variable "policy_yaml" {
  type        = string
  description = <<-D
    The contents of policy.yaml, passed rather than baked. Changing a
    detector threshold should be a config change, never an image rebuild.
    Pass it as file(...) pointing at the repo root policy.yaml.
  D
}

variable "verdict_mode" {
  type        = string
  default     = "observe"
  description = "observe | enforce | archive. observe records what it would have denied and denies nothing."
  validation {
    condition     = contains(["observe", "enforce", "archive"], var.verdict_mode)
    error_message = "verdict_mode must be observe, enforce or archive."
  }
}

variable "webhook_secret_ids" {
  type        = map(object({ current = string, previous = optional(string, "") }))
  default     = {}
  description = "org_ids name -> that org's Inference hook signing secret ids: current, and previous during that org's own rotation. Surfaced to the verdict server as WEBHOOK_SECRET_<NAME> and WEBHOOK_SECRET_<NAME>_PREVIOUS; list both in policy.yaml's server.secrets."
  validation {
    condition = alltrue([for k, s in var.webhook_secret_ids :
      can(regex("^[A-Za-z0-9_-]+$", k)) && can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", s.current)) &&
      (s.previous == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", s.previous)))
    ])
    error_message = "Each webhook_secret_ids key must be letters, digits, - or _, each current a secret id, projects/<project>/secrets/<name>, and each previous empty or one."
  }
  validation {
    condition     = length(distinct([for k in keys(var.webhook_secret_ids) : upper(replace(k, "-", "_"))])) == length(var.webhook_secret_ids)
    error_message = "Two webhook_secret_ids keys map to the same WEBHOOK_SECRET_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "compliance_key_secret_ids" {
  type        = map(string)
  default     = {}
  description = "org_ids name -> that org's Compliance Access Key secret id, surfaced to ingest as ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME> for that org's compliance.orgs entry. No previous slot: an entry takes one key. Do NOT grant delete:compliance_user_data."
  validation {
    condition = alltrue([for k, id in var.compliance_key_secret_ids :
      can(regex("^[A-Za-z0-9_-]+$", k)) && can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", id))
    ])
    error_message = "Each compliance_key_secret_ids key must be letters, digits, - or _, and each value a secret id, projects/<project>/secrets/<name>."
  }
  validation {
    condition     = length(distinct([for k in keys(var.compliance_key_secret_ids) : upper(replace(k, "-", "_"))])) == length(var.compliance_key_secret_ids)
    error_message = "Two compliance_key_secret_ids keys map to the same ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "intake_fleet_token_secret_ids" {
  type        = map(object({ current = string, previous = optional(string, "") }))
  default     = {}
  description = "org_ids name -> that org's fleet intake token secret ids: current, and previous during a rotation. Surfaced to intake as FORGD_INTAKE_FLEET_TOKEN_<NAME> and FORGD_INTAKE_FLEET_TOKEN_<NAME>_PREVIOUS, for an intake.fleet entry with org: $FORGD_ORG_ID_<NAME>. Used only with enable_intake."
  validation {
    condition = alltrue([for k, s in var.intake_fleet_token_secret_ids :
      can(regex("^[A-Za-z0-9_-]+$", k)) && can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", s.current)) &&
      (s.previous == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", s.previous)))
    ])
    error_message = "Each intake_fleet_token_secret_ids key must be letters, digits, - or _, each current a secret id, projects/<project>/secrets/<name>, and each previous empty or one."
  }
  validation {
    condition     = length(distinct([for k in keys(var.intake_fleet_token_secret_ids) : upper(replace(k, "-", "_"))])) == length(var.intake_fleet_token_secret_ids)
    error_message = "Two intake_fleet_token_secret_ids keys map to the same FORGD_INTAKE_FLEET_TOKEN_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "otel_fleets" {
  description = "fleet name -> the org_ids names its exporter token is valid for. The token is otel_token_secret_ids[<fleet>], surfaced to the collector as FORGD_OTEL_TOKEN_<FLEET> for an otel.orgs entry with ids: [$FORGD_ORG_ID_<NAME>, ...]. Every name must be an org_ids key with an id, never an org id itself, and a fleet cannot share a name with an org."
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

variable "ingest_schedule" {
  type        = string
  default     = "0 */6 * * *"
  description = "Cloud Scheduler cron expression, five fields."
}

variable "ingest_schedule_timezone" {
  type    = string
  default = "Etc/UTC"
}

variable "deletion_protection" {
  type        = bool
  default     = true
  description = "Set on every service and the ingest job. While true, Terraform refuses to destroy them, so terraform destroy on this module, or turning enable_intake off, fails until an apply has set it to false."
}

# --- the findings connector ----------------------------------------------

variable "connector_enabled" {
  type        = bool
  default     = false
  description = "Run the findings connector, a read-only MCP server over the store added to Claude as a custom connector. See docs/CONNECTOR.md. False leaves the plan exactly as it was."
}

variable "connector_resource" {
  type        = string
  default     = ""
  description = <<-D
    The canonical MCP URL, the one entered in Claude. Empty derives
    https://<name_prefix>-connector-<project number>.<region>.run.app/mcp,
    Cloud Run's deterministic URL for the service. Set, it must be a
    lowercase https URL ending in /mcp and equal that derived URL, checked
    at plan.
  D
}

variable "connector_scopes" {
  type        = list(string)
  default     = []
  description = "What Claude requests at sign-in."
}

variable "connector_required_scope" {
  type        = string
  default     = ""
  description = "Checked against the token's scp or scope claim, e.g. findings.read. Required when connector_enabled, here or as connector.required_scope in policy.yaml."
}

variable "connector_allowed_origins" {
  type        = list(string)
  default     = []
  description = "Browser origins allowed on a request that carries Origin. Empty is https://claude.ai."
}

variable "connector_issuer" {
  type        = string
  default     = ""
  description = "The identity provider's issuer. Required unless connector_issuers is set."
}

variable "connector_jwks_url" {
  type        = string
  default     = ""
  description = "The identity provider's JWKS URL. Required unless connector_issuers is set."
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

# --- dashboard admins ----------------------------------------------------
variable "overrides_writer_lockout" {
  type        = bool
  default     = false
  description = "store-gcs's overrides_writer_lockout output: whether the store module's control_enabled takes the writers' writes to the runtime overrides away. dashboard_admins_enabled is refused unless it is true. The services also prove it at runtime (docs/OVERRIDES.md)."
}

variable "dashboard_admins_enabled" {
  type        = bool
  default     = false
  description = "Runtime overrides from the dashboard (docs/OVERRIDES.md). Refused at plan while the dashboard signs in through IAP, which is the only sign-in this module offers: IAP tokens carry no groups. The wiring moves the dashboard's account from reader_members to control_members and gives it FORGD_DASHBOARD_FORM_KEY and FORGD_OVERRIDES_SIGNING_KEY, and gives every service FORGD_OVERRIDES_VERIFY_KEY. False leaves the plan exactly as it was."
}

variable "dashboard_form_key_secret_id" {
  type        = string
  default     = ""
  description = "The secret holding FORGD_DASHBOARD_FORM_KEY, the HMAC key for the dashboard's admin form tokens, at least 32 characters. Required when dashboard_admins_enabled."
  validation {
    condition     = var.dashboard_form_key_secret_id == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", var.dashboard_form_key_secret_id))
    error_message = "dashboard_form_key_secret_id must be empty or a secret id, projects/<project>/secrets/<name>."
  }
}

variable "dashboard_signing_key_secret_id" {
  type        = string
  default     = ""
  description = "The secret holding FORGD_OVERRIDES_SIGNING_KEY, the Ed25519 private key the dashboard signs every runtime-override record with: 32 raw bytes, unpadded URL-safe base64. Only the dashboard's account can read it. Required when dashboard_admins_enabled."
  validation {
    condition     = var.dashboard_signing_key_secret_id == "" || can(regex("^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]{1,255}$", var.dashboard_signing_key_secret_id))
    error_message = "dashboard_signing_key_secret_id must be empty or a secret id, projects/<project>/secrets/<name>."
  }
}

variable "overrides_verify_keys" {
  type        = list(string)
  default     = []
  description = "The Ed25519 public keys every service verifies runtime-override records with, as FORGD_OVERRIDES_VERIFY_KEY: each 32 raw bytes, unpadded URL-safe base64, 43 characters. Required when dashboard_admins_enabled. The module cannot check that the signing key's public half is listed; the dashboard refuses to start when it is not."
  validation {
    condition     = alltrue([for k in var.overrides_verify_keys : can(regex("^[A-Za-z0-9_-]{43}$", k))])
    error_message = "overrides_verify_keys must list Ed25519 public keys, each 32 raw bytes in unpadded URL-safe base64: 43 characters of A-Z, a-z, 0-9, - and _."
  }
}
