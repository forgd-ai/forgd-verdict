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
# these in plaintext, so use one that is encrypted and access-controlled.

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
  validation {
    condition     = length(var.hash_salt) >= 16
    error_message = "Set TF_VAR_hash_salt to at least 16 characters: openssl rand -base64 32"
  }
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

variable "otel_token" {
  type        = string
  sensitive   = true
  default     = "placeholder-not-yet-issued"
  description = "Bearer token for adapter 4. Both the authentication and the routing key."
}

variable "metrics_token" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Empty disables /metrics entirely, which is the right default when the alternative is publishing an org's deny rate."
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

variable "org_ids" {
  type        = map(string)
  default     = {}
  description = "name -> organization UUID, surfaced as FORGD_ORG_ID_<NAME>. Not in policy.yaml: an org id names a customer and the policy file is committed."
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
  description = "The dashboard's identity. Storage Blob Data Reader."
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

    With the app in `trusted_header` mode and nothing in front, the
    dashboard refuses every request with its own 401: correct, and
    unusable.

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
