variable "name_prefix" {
  type        = string
  default     = "forgd-verdict"
  description = "Prefixes the cluster, ALB, target groups, roles and log groups. ALB and target group names are capped at 32 characters, and the longest suffix here is -collector."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,21}$", var.name_prefix))
    error_message = "name_prefix must be lowercase letters, digits and hyphens, at most 22 characters, so that <prefix>-collector fits a 32-character target group name."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}

# --- network -------------------------------------------------------------
# The caller's VPC. This module creates none.

variable "vpc_id" { type = string }

variable "subnet_ids" {
  type        = list(string)
  description = "PRIVATE subnets for the tasks. They need a route out -- a NAT gateway or VPC endpoints for ECR, Secrets Manager, Logs and S3 -- plus a NAT for Anthropic's APIs. Tasks get no public IP."
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnets for the internet-facing ALB, in at least two availability zones."
}

variable "alb_ingress_cidrs" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = <<-D
    Who may reach the ALB. The internet, because Anthropic calls the verdict
    server and pushes to the collector from addresses this module cannot
    enumerate. Narrow it only if you know every caller's range -- a verdict
    server Anthropic cannot reach fails every governed prompt.
  D
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate for the HTTPS listener. It must cover every host below."
}

variable "ssl_policy" {
  type    = string
  default = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

# --- hosts ---------------------------------------------------------------
# One hostname per service; the ALB routes on the Host header. Point each at
# the ALB's DNS name (alb_dns_name, alb_zone_id).

variable "verdict_host" {
  type        = string
  description = "e.g. verdict.example.com. The Inference hooks endpoint is https://<this>/hook."
  validation {
    condition     = length(var.verdict_host) <= 253 && can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.verdict_host))
    error_message = "verdict_host must be a lowercase DNS hostname such as svc.example.com: no scheme, port, path or wildcard."
  }
}

variable "collector_host" {
  type        = string
  description = "e.g. otel.example.com. Anthropic appends /v1/logs and /v1/traces."
  validation {
    condition     = length(var.collector_host) <= 253 && can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.collector_host))
    error_message = "collector_host must be a lowercase DNS hostname such as svc.example.com: no scheme, port, path or wildcard."
  }
}

variable "dashboard_host" {
  type        = string
  description = "e.g. findings.example.com. The only host behind sign-in."
  validation {
    condition     = length(var.dashboard_host) <= 253 && can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.dashboard_host))
    error_message = "dashboard_host must be a lowercase DNS hostname such as svc.example.com: no scheme, port, path or wildcard."
  }
}

variable "intake_host" {
  type        = string
  default     = ""
  description = "Required when enable_intake is true."
  validation {
    condition     = var.intake_host == "" || (length(var.intake_host) <= 253 && can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.intake_host)))
    error_message = "intake_host must be a lowercase DNS hostname such as svc.example.com: no scheme, port, path or wildcard."
  }
}

variable "enable_intake" {
  type        = bool
  default     = false
  description = "Adapter 2's receiving end, for developer laptops. Off by default, as in the Helm chart."
}

# --- images --------------------------------------------------------------

variable "image" {
  type        = string
  description = <<-D
    The base image, tag included. Terraform sets it in the FIRST task
    definition revision only; CI owns image rolls after that. Read the note
    above the services in main.tf before changing a task definition here.
  D
}

variable "ingest_image" {
  type        = string
  description = "The -ingest variant. It carries the Presidio T2 tier; the base image would run the task and find nothing, which reads as a clean scan."
}

variable "cpu_architecture" {
  type        = string
  default     = "X86_64"
  description = "X86_64 or ARM64. Must match the architecture the images were built for, or every task fails with `exec format error`."
  validation {
    condition     = contains(["X86_64", "ARM64"], var.cpu_architecture)
    error_message = "cpu_architecture must be X86_64 or ARM64."
  }
}

# --- identity ------------------------------------------------------------
# From the store-s3 module. Their trust policies must admit
# ecs-tasks.amazonaws.com; see deploy/terraform/README.md.

variable "writer_role_arn" {
  type        = string
  description = "store-s3's writer role. The task role for verdict, collector, intake and ingest."
}

variable "reader_role_arn" {
  type        = string
  description = "store-s3's reader role. The dashboard's task role: this is the one internet-facing service a human signs into, and a compromise that could rewrite findings would be rewriting the evidence."
}

variable "store_url" {
  type        = string
  description = "store-s3's store_url. It goes into every task as a plain environment value, so it must name a bucket, never carry a credential."
  validation {
    condition     = startswith(var.store_url, "s3://")
    error_message = "store_url must be an s3:// URL, from the store-s3 module."
  }
}

# --- secrets -------------------------------------------------------------
# Secrets Manager ARNs, never values. The ECS agent fetches each one at task
# start, so no secret value is a Terraform variable or reaches state. Create
# the secrets before the apply, with a placeholder where a value is not yet
# issued.
#
# The FULL ARN, random suffix included. The execution role's policy names
# these ARNs exactly, and a partial ARN (no suffix) matches no secret in
# IAM, so every task would fail to start with AccessDenied.

variable "hash_salt_secret_arn" {
  type        = string
  description = <<-D
    Salts the finding digests. An empty salt means a findings export can be
    brute-forced back to the matched value for anything low-entropy -- an
    SSN has ~1e9 possibilities. This module cannot see the value to refuse a
    short one, as app-aca does; make it at least 16 characters (openssl rand
    -base64 32).
  D
  validation {
    condition     = can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.hash_salt_secret_arn))
    error_message = "hash_salt_secret_arn must be a full Secrets Manager secret ARN, including its six-character suffix."
  }
}

variable "webhook_secret_arn" {
  type        = string
  default     = ""
  description = "The Inference hooks signing secret. Anthropic shows it once, after the endpoint exists, so create the secret with a placeholder first: every hook request is then refused with 401, which is the safe failure. May be empty when webhook_secret_arns names an org."
  validation {
    condition     = var.webhook_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.webhook_secret_arn))
    error_message = "webhook_secret_arn must be empty or a full Secrets Manager secret ARN, including its six-character suffix."
  }
}

variable "webhook_secret_previous_arn" {
  type        = string
  default     = ""
  description = "The outgoing signing secret during a rotation. Empty outside one."
  validation {
    condition     = var.webhook_secret_previous_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.webhook_secret_previous_arn))
    error_message = "webhook_secret_previous_arn must be empty or a full Secrets Manager secret ARN."
  }
}

variable "otel_token_secret_arns" {
  type        = map(string)
  description = "name -> secret ARN, surfaced to the collector as FORGD_OTEL_TOKEN_<NAME>. One per organization: the token is both the authentication and the routing key. Each name needs an org_ids entry with a non-empty id that maps to the same <NAME>."
  validation {
    condition     = length(var.otel_token_secret_arns) > 0
    error_message = "otel_token_secret_arns needs at least one entry, or the collector accepts nothing."
  }
  validation {
    condition = alltrue([for name, arn in var.otel_token_secret_arns :
      can(regex("^[A-Za-z0-9_-]+$", name)) &&
      can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", arn))
    ])
    error_message = "Each otel_token_secret_arns key must be letters, digits, - or _, and each value a full Secrets Manager secret ARN."
  }
  validation {
    condition     = length(distinct([for k in keys(var.otel_token_secret_arns) : upper(replace(k, "-", "_"))])) == length(var.otel_token_secret_arns)
    error_message = "Two otel_token_secret_arns keys map to the same FORGD_OTEL_TOKEN_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "compliance_key_secret_arn" {
  type        = string
  default     = ""
  description = "The Compliance Access Key, for ingest. Enterprise only. Do NOT grant delete:compliance_user_data. May be empty when compliance_key_secret_arns names an org."
  validation {
    condition     = var.compliance_key_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.compliance_key_secret_arn))
    error_message = "compliance_key_secret_arn must be empty or a full Secrets Manager secret ARN, including its six-character suffix."
  }
}

variable "metrics_token_secret_arn" {
  type        = string
  default     = ""
  description = "Empty disables /metrics and /stats entirely, which is the right default when the alternative is publishing an org's deny rate."
  validation {
    condition     = var.metrics_token_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.metrics_token_secret_arn))
    error_message = "metrics_token_secret_arn must be empty or a full Secrets Manager secret ARN."
  }
}

variable "intake_fleet_token_secret_arn" {
  type        = string
  default     = ""
  description = "Secret ARN of the managed fleet's intake token, surfaced to intake as FORGD_INTAKE_FLEET_TOKEN for policy.yaml's intake.fleet. Used only with enable_intake."
  validation {
    condition     = var.intake_fleet_token_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.intake_fleet_token_secret_arn))
    error_message = "intake_fleet_token_secret_arn must be empty or a full Secrets Manager secret ARN."
  }
}

variable "intake_fleet_token_previous_secret_arn" {
  type        = string
  default     = ""
  description = "Secret ARN of the fleet's previous intake token while a rotation is under way, surfaced as FORGD_INTAKE_FLEET_TOKEN_PREVIOUS. Empty otherwise."
  validation {
    condition     = var.intake_fleet_token_previous_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.intake_fleet_token_previous_secret_arn))
    error_message = "intake_fleet_token_previous_secret_arn must be empty or a full Secrets Manager secret ARN."
  }
}

variable "intake_token_secret_arns" {
  type        = map(string)
  default     = {}
  description = "intake client -> secret ARN, surfaced to intake as FORGD_INTAKE_TOKEN_<NAME>: agents, and laptops outside a fleet. Laptops in a managed fleet use intake_fleet_token_secret_arn. Used only with enable_intake."
  validation {
    condition = alltrue([for name, arn in var.intake_token_secret_arns :
      can(regex("^[A-Za-z0-9_-]+$", name)) &&
      can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", arn))
    ])
    error_message = "Each intake_token_secret_arns key must be letters, digits, - or _, and each value a full Secrets Manager secret ARN."
  }
  validation {
    condition     = length(distinct([for k in keys(var.intake_token_secret_arns) : upper(replace(k, "-", "_"))])) == length(var.intake_token_secret_arns)
    error_message = "Two intake_token_secret_arns keys map to the same FORGD_INTAKE_TOKEN_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "secrets_kms_key_arns" {
  type        = list(string)
  default     = []
  description = "Customer-managed KMS keys the secrets above are encrypted with. Empty when they use the AWS-managed key, which needs no grant."
}

# --- the dashboard's sign-in ---------------------------------------------
# The ALB runs the OIDC flow for the dashboard host. Register
# https://<dashboard_host>/oauth2/idpresponse as the client's redirect URI.

variable "oidc_issuer" {
  type        = string
  description = "The IdP's issuer, exactly as it appears in its tokens. The dashboard checks it too."
}

variable "oidc_authorization_endpoint" { type = string }
variable "oidc_token_endpoint" { type = string }
variable "oidc_user_info_endpoint" { type = string }

variable "oidc_client_id" {
  type        = string
  description = "The IdP client id. Also the dashboard's audience: ALB tokens carry no `aud`, and the app checks this against their `client` header."
}

variable "oidc_client_secret" {
  type        = string
  sensitive   = true
  description = <<-D
    The ONE secret this module takes as a value. `authenticate-oidc` accepts
    nothing else -- no Secrets Manager reference -- so it is in state. Source
    it from TF_VAR_oidc_client_secret and keep state in an encrypted,
    access-controlled backend.
  D
}

variable "oidc_scope" {
  type    = string
  default = "openid email profile"
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

variable "webhook_secret_arns" {
  type        = map(object({ current = string, previous = optional(string, "") }))
  default     = {}
  description = "org_ids name -> that org's Inference hook signing secret ARNs: current, and previous during that org's own rotation. Surfaced to the verdict server as WEBHOOK_SECRET_<NAME> and WEBHOOK_SECRET_<NAME>_PREVIOUS; list both in policy.yaml's server.secrets."
  validation {
    condition = alltrue([for k, s in var.webhook_secret_arns :
      can(regex("^[A-Za-z0-9_-]+$", k)) && can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", s.current)) &&
      (s.previous == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", s.previous)))
    ])
    error_message = "Each webhook_secret_arns key must be letters, digits, - or _, each current a full Secrets Manager secret ARN, and each previous empty or one."
  }
  validation {
    condition     = length(distinct([for k in keys(var.webhook_secret_arns) : upper(replace(k, "-", "_"))])) == length(var.webhook_secret_arns)
    error_message = "Two webhook_secret_arns keys map to the same WEBHOOK_SECRET_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "compliance_key_secret_arns" {
  type        = map(string)
  default     = {}
  description = "org_ids name -> that org's Compliance Access Key ARN, surfaced to ingest as ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME> for that org's compliance.orgs entry. No previous slot: an entry takes one key. Do NOT grant delete:compliance_user_data."
  validation {
    condition = alltrue([for k, arn in var.compliance_key_secret_arns :
      can(regex("^[A-Za-z0-9_-]+$", k)) && can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", arn))
    ])
    error_message = "Each compliance_key_secret_arns key must be letters, digits, - or _, and each value a full Secrets Manager secret ARN."
  }
  validation {
    condition     = length(distinct([for k in keys(var.compliance_key_secret_arns) : upper(replace(k, "-", "_"))])) == length(var.compliance_key_secret_arns)
    error_message = "Two compliance_key_secret_arns keys map to the same ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "intake_fleet_token_secret_arns" {
  type        = map(object({ current = string, previous = optional(string, "") }))
  default     = {}
  description = "org_ids name -> that org's fleet intake token ARNs: current, and previous during a rotation. Surfaced to intake as FORGD_INTAKE_FLEET_TOKEN_<NAME> and FORGD_INTAKE_FLEET_TOKEN_<NAME>_PREVIOUS, for an intake.fleet entry with org: $FORGD_ORG_ID_<NAME>. Used only with enable_intake."
  validation {
    condition = alltrue([for k, s in var.intake_fleet_token_secret_arns :
      can(regex("^[A-Za-z0-9_-]+$", k)) && can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", s.current)) &&
      (s.previous == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", s.previous)))
    ])
    error_message = "Each intake_fleet_token_secret_arns key must be letters, digits, - or _, each current a full Secrets Manager secret ARN, and each previous empty or one."
  }
  validation {
    condition     = length(distinct([for k in keys(var.intake_fleet_token_secret_arns) : upper(replace(k, "-", "_"))])) == length(var.intake_fleet_token_secret_arns)
    error_message = "Two intake_fleet_token_secret_arns keys map to the same FORGD_INTAKE_FLEET_TOKEN_<NAME> once upper-cased with hyphens as underscores."
  }
}

variable "otel_fleets" {
  description = "fleet name -> the org_ids names its exporter token is valid for. The token is otel_token_secret_arns[<fleet>], surfaced to the collector as FORGD_OTEL_TOKEN_<FLEET> for an otel.orgs entry with ids: [$FORGD_ORG_ID_<NAME>, ...]. Every name must be an org_ids key with an id, never an org id itself, and a fleet cannot share a name with an org."
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
  default     = "cron(0 */6 * * ? *)"
  description = "EventBridge Scheduler expression. Six fields, not five: the day-of-month or day-of-week must be `?`."
}

variable "ingest_schedule_timezone" {
  type    = string
  default = "UTC"
}

variable "log_retention_days" {
  type        = number
  default     = 90
  description = "CloudWatch retention for every role's log group. Logs carry detector names and locators, never matched content."
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a value CloudWatch Logs accepts, e.g. 30, 90, 365."
  }
}

# --- the findings connector ----------------------------------------------

variable "connector_enabled" {
  type        = bool
  default     = false
  description = "Run the findings connector, a read-only MCP server over the store added to Claude as a custom connector. See docs/CONNECTOR.md. False leaves the plan exactly as it was."
}

variable "connector_host" {
  type        = string
  default     = ""
  description = "The connector's hostname on the ALB, covered by certificate_arn. Required when connector_enabled is true."
  validation {
    condition     = var.connector_host == "" || (length(var.connector_host) <= 253 && can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.connector_host)))
    error_message = "connector_host must be a lowercase DNS hostname such as svc.example.com: no scheme, port, path or wildcard."
  }
}

variable "connector_resource" {
  type        = string
  default     = ""
  description = "The canonical MCP URL, the one entered in Claude. Empty derives https://<connector_host>/mcp; set, it must be a lowercase https URL ending in /mcp and equal that, checked at plan."
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

variable "connector_source_ranges" {
  type        = list(string)
  default     = []
  description = <<-D
    An optional allowlist on the connector's listener rule, off by default,
    as CIDRs. Anthropic's published egress range is 160.79.104.0/21 today,
    and it has changed before; a stale entry fails in Claude as "Couldn't
    reach the MCP server". It also cuts off Claude Code, which connects from
    the user's machine. alb_ingress_cidrs still applies first.
  D
  validation {
    condition     = length(var.connector_source_ranges) <= 4 && alltrue([for c in var.connector_source_ranges : can(cidrhost(c, 0))])
    error_message = "connector_source_ranges takes at most 4 CIDRs, the ALB's limit of 5 condition values per rule less the host."
  }
}

# --- dashboard admins ----------------------------------------------------
variable "overrides_writer_lockout" {
  type        = bool
  default     = false
  description = "store-s3's overrides_writer_lockout output: whether the store module's control_enabled takes the writers' writes to the runtime overrides away. dashboard_admins_enabled is refused unless it is true. The services also prove it at runtime (docs/OVERRIDES.md)."
}

variable "dashboard_admins_enabled" {
  type        = bool
  default     = false
  description = "Runtime overrides from the dashboard (docs/OVERRIDES.md). True runs the dashboard task as control_role_arn and gives it FORGD_DASHBOARD_FORM_KEY and FORGD_OVERRIDES_SIGNING_KEY, and gives every container FORGD_OVERRIDES_VERIFY_KEY. The policy's dashboard.admins says who is an admin. False leaves the plan exactly as it was."
}

variable "overrides_writer_identities" {
  type        = list(string)
  default     = []
  description = "store-s3's overrides_writer_identities output: the writer role ARNs whose lockout the dashboard verifies from the bucket policy, as FORGD_OVERRIDES_WRITER_IDENTITIES. Required, including writer_role_arn, when dashboard_admins_enabled."
}

variable "control_role_arn" {
  type        = string
  default     = ""
  description = "store-s3's control_role_arn, the dashboard's task role when dashboard_admins_enabled. Must differ from reader_role_arn and writer_role_arn."
}

variable "dashboard_form_key_secret_arn" {
  type        = string
  default     = ""
  description = "The secret holding FORGD_DASHBOARD_FORM_KEY, the HMAC key for the dashboard's admin form tokens, at least 32 characters (openssl rand -base64 32). Required when dashboard_admins_enabled."
  validation {
    condition     = var.dashboard_form_key_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.dashboard_form_key_secret_arn))
    error_message = "dashboard_form_key_secret_arn must be empty or a full Secrets Manager secret ARN, including its six-character suffix."
  }
}

variable "dashboard_signing_key_secret_arn" {
  type        = string
  default     = ""
  description = "The secret holding FORGD_OVERRIDES_SIGNING_KEY, the Ed25519 private key the dashboard signs every runtime-override record with: the raw 32 bytes in unpadded URL-safe base64, 43 characters. Only the dashboard's container and execution role get it. Required when dashboard_admins_enabled."
  validation {
    condition     = var.dashboard_signing_key_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.dashboard_signing_key_secret_arn))
    error_message = "dashboard_signing_key_secret_arn must be empty or a full Secrets Manager secret ARN, including its six-character suffix."
  }
}

variable "overrides_verify_keys" {
  type        = list(string)
  default     = []
  description = "The Ed25519 public keys every service verifies runtime-override records with, each the raw 32 bytes in unpadded URL-safe base64, 43 characters. Every container gets them comma-separated as FORGD_OVERRIDES_VERIFY_KEY. Required, non-empty, when dashboard_admins_enabled. List the public half of dashboard_signing_key_secret_arn's key. The module cannot check that; the app refuses a signing key whose public half this list does not include. A second key lets a rotation overlap."
  validation {
    condition     = alltrue([for k in var.overrides_verify_keys : can(regex("^[A-Za-z0-9_-]{43}$", k))])
    error_message = "Each overrides_verify_keys entry must be an Ed25519 public key: 32 bytes in unpadded URL-safe base64, exactly 43 characters of A-Z, a-z, 0-9, - and _."
  }
}
