# Five roles as Cloud Run services, and ingest as a scheduled Cloud Run
# job, from one image.
#
# `FORGD_ROLE` selects the role, so the services cannot drift to different
# versions of the scan core:
#
#   server     adapter 1, the verdict server. Anthropic calls IN.
#   collect    adapter 4, the OTLP collector. Anthropic pushes IN.
#   dashboard  read-only over the findings store. Holds no credential.
#   intake     adapter 2's receiving end, optional. Laptops POST IN.
#   connector  the findings connector for Claude, optional. Claude calls IN.
#   ingest     adapter 3, a scheduled job. Holds the Compliance Access Key.
#
# Each service is ONE container. deploy/entrypoint.sh starts gitleaksd inside
# it for the roles that scan on a path someone waits on, and binds the app
# only once the socket exists, as on Container Apps, ECS and the Helm chart.
#
# THREE OF THESE MUST NEVER SIT BEHIND A PLATFORM AUTH PROVIDER. Anthropic
# authenticates to the verdict server with a webhook signature and to the
# collector with an OTLP header, and a laptop authenticates to intake with a
# bearer token, so an IAP sign-in or an IAM invoker check turns every
# governed prompt, export or spool upload into a delivery failure rather
# than a deny. Those three allow unauthenticated invocation and have IAP
# off; IAP is on the dashboard and nowhere else. tests/test_app_cloudrun.py
# fails otherwise.
#
# Each role runs as its own service account, which reads that role's secrets
# and nothing else. This module grants none of them store access: it outputs
# them as writer_members and reader_members for store-gcs to bind.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source = "hashicorp/google"
      # 7.0 is the first major with `iap_enabled` on
      # google_cloud_run_v2_service; store-gcs is on 8.
      version = "~> 8.0"
    }
  }
}

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  # The same name rule as the Helm chart and app-ecs: upper case, hyphens to
  # underscores, because an environment variable name cannot hold a hyphen
  # and policy.yaml refers to these as $FORGD_ORG_ID_<NAME>.
  org_env = { for name, id in var.org_ids : "FORGD_ORG_ID_${upper(replace(name, "-", "_"))}" => id }

  # policy.yaml travels compressed, as on the other targets. The entrypoint
  # decodes it and refuses to start if it does not.
  policy_gz = base64gzip(var.policy_yaml)

  # Every role honours runtime overrides only while this is "true".
  # FORGD_OVERRIDES_WRITER_ROLES lists one writer role per distinct store
  # identity. Each role here runs as its own service account
  # (google_service_account.role), so every writer role is listed, ingest
  # included. The dashboard and the connector only read.
  # FORGD_OVERRIDES_VERIFY_KEY lists the public keys every role verifies the
  # override records with.
  overrides_env = var.dashboard_admins_enabled ? {
    FORGD_OVERRIDES_ENABLED      = "true"
    FORGD_OVERRIDES_WRITER_ROLES = join(",", local.writer_roles)
    FORGD_OVERRIDES_VERIFY_KEY   = join(",", var.overrides_verify_keys)
  } : {}

  # The path each startup and readiness probe requests. /healthz answers 200
  # however the runtime overrides read; /readyz answers 503 until they are
  # confirmed.
  ready_path = var.dashboard_admins_enabled ? "/readyz" : "/healthz"

  base_env = merge({
    FORGD_VERDICT_STORE     = var.store_url
    FORGD_VERDICT_LOG_LEVEL = "INFO"
    FORGD_POLICY_INLINE_GZ  = local.policy_gz
  }, local.org_env, local.overrides_env)

  gitleaks_env = { FORGD_GITLEAKS_SOCKET = "/run/forgd/gitleaksd.sock" }

  # Every environment entry and every secret is built from a map, name =>
  # value or name => secret id, so the two cannot be confused: a secret goes
  # in as `value_source.secret_key_ref`, which Cloud Run resolves at instance
  # start. Neither Terraform nor its state holds the value.
  metrics_secret = var.metrics_token_secret_id == "" ? {} : { FORGD_METRICS_TOKEN = var.metrics_token_secret_id }
  salt_secret    = { FORGD_HASH_SALT = var.hash_salt_secret_id }

  otel_secrets = { for name, id in var.otel_token_secret_ids : "FORGD_OTEL_TOKEN_${upper(replace(name, "-", "_"))}" => id }
  # Token names with no non-empty org id under the same env name.
  org_id_by_env = { for name, id in var.org_ids : upper(replace(name, "-", "_")) => id }
  otel_tokens_without_org = [
    for name in keys(var.otel_token_secret_ids) : name
    if lookup(local.org_id_by_env, upper(replace(name, "-", "_")), "") == "" && !contains(keys(local.otel_fleet_by_env), upper(replace(name, "-", "_")))
  ]
  # A fleet exporter token: one token for a set of orgs, each named by its
  # org_ids key. Each problem is one sentence of the refusal.
  otel_fleet_by_env = { for name, members in var.otel_fleets : upper(replace(name, "-", "_")) => members }
  otel_fleet_problems = concat(
    [for name, members in var.otel_fleets : "otel_fleets.${name} names no org" if length(members) == 0],
    [for name, _ in var.otel_fleets : "otel_fleets.${name} has the name of an org_ids entry, so FORGD_OTEL_TOKEN_${upper(replace(name, "-", "_"))} would be both" if contains(keys(local.org_id_by_env), upper(replace(name, "-", "_")))],
    [for name, members in var.otel_fleets : "otel_fleets.${name} lists an org id; list each org by its org_ids name" if anytrue([for o in members : can(regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$", o))])],
    flatten([for name, members in var.otel_fleets : [
      for o in members : "otel_fleets.${name} names ${o}, which has no non-empty org_ids entry"
      if !can(regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$", o)) && lookup(local.org_id_by_env, upper(replace(o, "-", "_")), "") == ""
    ]]),
    [for name, _ in var.otel_fleets : "otel_fleets.${name} has no token in otel_token_secret_ids" if !contains([for name in keys(var.otel_token_secret_ids) : upper(replace(name, "-", "_"))], upper(replace(name, "-", "_")))],
  )
  # Per-org secrets, keyed by org_ids name. Each name makes <PREFIX>_<NAME>
  # and, for the two with a previous slot, <PREFIX>_<NAME>_PREVIOUS.
  webhook_org_secrets = merge(concat([{}], [for name, s in var.webhook_secret_ids : merge(
    { "WEBHOOK_SECRET_${upper(replace(name, "-", "_"))}" = s.current },
    s.previous == "" ? {} : { "WEBHOOK_SECRET_${upper(replace(name, "-", "_"))}_PREVIOUS" = s.previous },
  )])...)
  compliance_org_secrets = { for name, id in var.compliance_key_secret_ids : "ANTHROPIC_COMPLIANCE_ACCESS_KEY_${upper(replace(name, "-", "_"))}" => id }
  intake_fleet_org_secrets = merge(concat([{}], [for name, s in var.intake_fleet_token_secret_ids : merge(
    { "FORGD_INTAKE_FLEET_TOKEN_${upper(replace(name, "-", "_"))}" = s.current },
    s.previous == "" ? {} : { "FORGD_INTAKE_FLEET_TOKEN_${upper(replace(name, "-", "_"))}_PREVIOUS" = s.previous },
  )])...)
  # Every variable each map could set, its single slots included, so a
  # repeat is a collision whether or not a previous value is set now.
  org_secret_vars = {
    webhook_secret_ids = concat(["WEBHOOK_SECRET", "WEBHOOK_SECRET_PREVIOUS"], flatten([
    for name in keys(var.webhook_secret_ids) : ["WEBHOOK_SECRET_${upper(replace(name, "-", "_"))}", "WEBHOOK_SECRET_${upper(replace(name, "-", "_"))}_PREVIOUS"]]))
    compliance_key_secret_ids = concat(["ANTHROPIC_COMPLIANCE_ACCESS_KEY"], [
    for name in keys(var.compliance_key_secret_ids) : "ANTHROPIC_COMPLIANCE_ACCESS_KEY_${upper(replace(name, "-", "_"))}"])
    intake_fleet_token_secret_ids = concat(["FORGD_INTAKE_FLEET_TOKEN", "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS"], flatten([
    for name in keys(var.intake_fleet_token_secret_ids) : ["FORGD_INTAKE_FLEET_TOKEN_${upper(replace(name, "-", "_"))}", "FORGD_INTAKE_FLEET_TOKEN_${upper(replace(name, "-", "_"))}_PREVIOUS"]]))
  }
  org_secret_names = {
    webhook_secret_ids            = keys(var.webhook_secret_ids)
    compliance_key_secret_ids     = keys(var.compliance_key_secret_ids)
    intake_fleet_token_secret_ids = keys(var.intake_fleet_token_secret_ids)
  }
  org_secret_problems = concat(
    flatten([for v, names in local.org_secret_names : [
      for name in names : "${v}.${name} has no org_ids entry; each key is an org's org_ids name"
      if !contains(keys(local.org_id_by_env), upper(replace(name, "-", "_")))
    ]]),
    flatten([for v, vars in local.org_secret_vars : [
      for x in distinct(vars) : "${v} collides on ${x}: give one of the orgs another org_ids name"
      if length([for y in vars : y if y == x]) > 1
    ]]),
  )
  intake_secrets = merge(
    { for name, id in var.intake_token_secret_ids : "FORGD_INTAKE_TOKEN_${upper(replace(name, "-", "_"))}" => id },
    var.intake_fleet_token_secret_id == "" ? {} : { FORGD_INTAKE_FLEET_TOKEN = var.intake_fleet_token_secret_id },
    var.intake_fleet_token_previous_secret_id == "" ? {} : { FORGD_INTAKE_FLEET_TOKEN_PREVIOUS = var.intake_fleet_token_previous_secret_id },
    local.intake_fleet_org_secrets,
  )

  verdict_secrets = merge(
    var.webhook_secret_id == "" ? {} : { WEBHOOK_SECRET = var.webhook_secret_id },
    local.webhook_org_secrets,
    var.webhook_secret_previous_id == "" ? {} : { WEBHOOK_SECRET_PREVIOUS = var.webhook_secret_previous_id },
    local.salt_secret,
    local.metrics_secret,
  )
  collector_secrets = merge(local.otel_secrets, local.salt_secret, local.metrics_secret)
  intake_all        = merge(local.intake_secrets, local.salt_secret, local.metrics_secret)
  ingest_secrets = merge(
    var.compliance_key_secret_id == "" ? {} : { ANTHROPIC_COMPLIANCE_ACCESS_KEY = var.compliance_key_secret_id },
    local.compliance_org_secrets,
    local.salt_secret,
  )
  dashboard_secrets = var.dashboard_admins_enabled ? {
    FORGD_DASHBOARD_FORM_KEY    = var.dashboard_form_key_secret_id
    FORGD_OVERRIDES_SIGNING_KEY = var.dashboard_signing_key_secret_id
  } : {}

  # role => the secrets its container names. The containers and the
  # accessor bindings both read this map, so the two cannot disagree, and
  # the dashboard's account cannot read the webhook secret, the Compliance
  # key or an OTel token.
  role_secrets = merge({
    verdict   = local.verdict_secrets
    collector = local.collector_secrets
    dashboard = local.dashboard_secrets
    ingest    = local.ingest_secrets
  }, var.enable_intake ? { intake = local.intake_all } : {})

  roles = var.enable_intake ? ["verdict", "collector", "dashboard", "intake", "ingest"] : ["verdict", "collector", "dashboard", "ingest"]

  # The roles store-gcs binds as writers. Every role but the dashboard.
  writer_roles = [for r in local.roles : r if r != "dashboard"]

  # One binding per (role, secret), keyed so that a secret passed under two
  # names is still one binding.
  secret_access = { for pair in distinct(flatten([
    for role in local.roles : [for id in values(local.role_secrets[role]) : { role = role, secret = id }]
  ])) : "${pair.role} ${pair.secret}" => pair }

  names = { for r in ["verdict", "collector", "dashboard", "intake", "ingest"] : r => "${var.name_prefix}-${r}" }

  # Anthropic and laptops call these with their own credential. The ONLY
  # services that allow unauthenticated invocation.
  public_services = var.enable_intake ? ["verdict", "collector", "intake"] : ["verdict", "collector"]

  # IAP's audience for a service it fronts directly. The dashboard verifies
  # it on every token.
  dashboard_iap_audience = "/projects/${data.google_project.this.number}/locations/${var.region}/services/${local.names["dashboard"]}"

  iap_service_agent = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-iap.iam.gserviceaccount.com"
}

# --- identities ----------------------------------------------------------
#
# One per role. The service runs as it, Cloud Run resolves the role's secrets
# as it, and store-gcs binds it to the bucket through writer_members or
# reader_members.
resource "google_service_account" "role" {
  for_each = toset(local.roles)

  project      = var.project_id
  account_id   = local.names[each.key]
  display_name = "forgd-verdict ${each.key}"
}

# Each role's secrets exactly, one binding per secret. The dashboard's
# account gets none.
resource "google_secret_manager_secret_iam_member" "access" {
  for_each = local.secret_access

  secret_id = each.value.secret
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.role[each.value.role].member
}

# --- adapter 1: the verdict server ---------------------------------------
resource "google_cloud_run_v2_service" "verdict" {
  project             = var.project_id
  deletion_protection = var.deletion_protection
  name                = local.names["verdict"]
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  iap_enabled         = false
  labels              = var.labels

  template {
    service_account = google_service_account.role["verdict"].email

    # min 1: the org's verdict timeout covers
    # connection through response, so a cold start on the first governed
    # prompt after an idle period is a WEBHOOK FAILURE rather than a slow
    # allow. max 1 because the session cache and the webhook-id dedupe
    # store are per-process.
    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      name  = "verdict"
      image = var.image

      ports {
        container_port = 8000
      }

      # cpu_idle = false keeps CPU allocated between requests, which the
      # store writer thread and gitleaksd need.
      resources {
        # Holds up to twice server.preauth_body_budget_bytes (256 MiB) of
        # unsigned request body; see docs/SERVER.md#memory.
        limits = {
          cpu    = "1"
          memory = "2Gi"
        }
        cpu_idle          = false
        startup_cpu_boost = true
      }

      # gitleaksd compiles its rule set before the socket appears, and the
      # entrypoint binds the app only after it does, up to 60 s.
      startup_probe {
        http_get {
          path = local.ready_path
        }
        period_seconds    = 5
        timeout_seconds   = 4
        failure_threshold = 24
      }

      # With dashboard_admins_enabled, a failing readiness probe stops new
      # traffic to the instance without shutting it down; traffic returns
      # when it passes again.
      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          http_get {
            path = local.ready_path
          }
          period_seconds    = 10
          timeout_seconds   = 4
          failure_threshold = 3
        }
      }

      # /livez answers 503 only when gitleaksd stops answering; a restart
      # restarts the daemon with the app.
      liveness_probe {
        http_get {
          path = "/livez"
        }
        period_seconds    = 10
        timeout_seconds   = 5
        failure_threshold = 6
      }

      dynamic "env" {
        for_each = merge(local.base_env, local.gitleaks_env, {
          FORGD_ROLE         = "server"
          FORGD_VERDICT_MODE = var.verdict_mode
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.role_secrets["verdict"]
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.access]

  # CI rolls images; Terraform sets the first one and then keeps out of the
  # way. `client` and `client_version` are what gcloud stamps on a deploy.
  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]

    precondition {
      condition     = var.webhook_secret_id != "" || length(var.webhook_secret_ids) > 0
      error_message = "webhook_secret_id is empty and webhook_secret_ids names no org: the verdict server would have no signing secret, and the signature check is the only thing authenticating Anthropic."
    }
    precondition {
      condition     = var.compliance_key_secret_id != "" || length(var.compliance_key_secret_ids) > 0
      error_message = "compliance_key_secret_id is empty and compliance_key_secret_ids names no org: the ingest job would have no key."
    }
    precondition {
      condition     = length(local.org_secret_problems) == 0
      error_message = "${join("; ", local.org_secret_problems)}."
    }
  }
}

# --- adapter 4: the OTLP collector ---------------------------------------
resource "google_cloud_run_v2_service" "collector" {
  project             = var.project_id
  deletion_protection = var.deletion_protection
  name                = local.names["collector"]
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  iap_enabled         = false
  labels              = var.labels

  template {
    service_account = google_service_account.role["collector"].email

    # max 1 because the store sink queue is per-process, and backpressure --
    # the 503 that makes an exporter hold its batch -- only means anything
    # with one queue.
    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      name  = "collector"
      image = var.image

      ports {
        container_port = 8100
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "2Gi"
        }
        cpu_idle          = false
        startup_cpu_boost = true
      }

      startup_probe {
        http_get {
          path = local.ready_path
        }
        period_seconds    = 5
        timeout_seconds   = 4
        failure_threshold = 24
      }

      # With dashboard_admins_enabled, a failing readiness probe stops new
      # traffic to the instance without shutting it down; traffic returns
      # when it passes again.
      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          http_get {
            path = local.ready_path
          }
          period_seconds    = 10
          timeout_seconds   = 4
          failure_threshold = 3
        }
      }

      liveness_probe {
        http_get {
          path = "/livez"
        }
        period_seconds    = 10
        timeout_seconds   = 5
        failure_threshold = 6
      }

      dynamic "env" {
        for_each = merge(local.base_env, local.gitleaks_env, {
          FORGD_ROLE = "collect"
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.role_secrets["collector"]
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.access]

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]

    precondition {
      condition     = length(local.otel_tokens_without_org) == 0
      error_message = "otel_token_secret_ids.${join(", otel_token_secret_ids.", local.otel_tokens_without_org)} has no non-empty org_ids entry under the same FORGD_ORG_ID_<NAME>. The collector cross-checks a batch's organization.id against that id, and with none the check cannot run, so any organization's batch is accepted on the token. Add the org's id to org_ids."
    }

    precondition {
      condition     = length(local.otel_fleet_problems) == 0
      error_message = "${join("; ", local.otel_fleet_problems)}. The collector accepts a fleet token only for orgs it holds ids for, so every org in a fleet needs its org_ids entry."
    }
  }
}

# --- the dashboard -------------------------------------------------------
#
# The READER account, and NO hash salt. The dashboard reads every finding
# hash, so giving it the salt would put the key beside the data it protects.
#
# IAP signs a person in and hands the dashboard a signed
# `x-goog-iap-jwt-assertion`, which the app verifies itself against IAP's
# keys and this service's audience (dashboard/auth.py, platform iap).
resource "google_cloud_run_v2_service" "dashboard" {
  project             = var.project_id
  deletion_protection = var.deletion_protection
  name                = local.names["dashboard"]
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  iap_enabled         = true
  labels              = var.labels

  template {
    service_account = google_service_account.role["dashboard"].email

    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      name  = "dashboard"
      image = var.image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
      }

      startup_probe {
        http_get {
          path = local.ready_path
        }
        period_seconds    = 5
        timeout_seconds   = 4
        failure_threshold = 12
      }

      # With dashboard_admins_enabled, a failing readiness probe stops new
      # traffic to the instance without shutting it down; traffic returns
      # when it passes again.
      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          http_get {
            path = local.ready_path
          }
          period_seconds    = 10
          timeout_seconds   = 4
          failure_threshold = 3
        }
      }

      # oidc_jwt with platform iap overrides whatever policy.yaml says about
      # the mode and platform. The app refuses to start without an audience
      # of the right shape.
      dynamic "env" {
        for_each = merge(local.base_env, {
          FORGD_ROLE                = "dashboard"
          FORGD_DASHBOARD_AUTH_MODE = "oidc_jwt"
          FORGD_DASHBOARD_PLATFORM  = "iap"
          FORGD_DASHBOARD_AUDIENCE  = local.dashboard_iap_audience
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.role_secrets["dashboard"]
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]

    # The dashboard signs in through IAP here, and the app refuses
    # dashboard.admins with platform iap because IAP tokens carry no groups.
    precondition {
      condition     = !var.dashboard_admins_enabled
      error_message = "dashboard_admins_enabled: this module's dashboard signs in through IAP, whose tokens carry no groups, and the dashboard refuses dashboard.admins with platform iap. Runtime overrides from the dashboard are not available on this module."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || var.overrides_writer_lockout
      error_message = "dashboard_admins_enabled needs overrides_writer_lockout = true: store-gcs's overrides_writer_lockout output, which is true only with control_enabled. Without it the writer identities can write the runtime overrides object and audit prefix, and so forge an override."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || var.dashboard_form_key_secret_id != ""
      error_message = "dashboard_admins_enabled needs dashboard_form_key_secret_id, the secret holding FORGD_DASHBOARD_FORM_KEY. The dashboard refuses to start with admins configured and no form key."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || var.dashboard_signing_key_secret_id != ""
      error_message = "dashboard_admins_enabled needs dashboard_signing_key_secret_id, the secret holding FORGD_OVERRIDES_SIGNING_KEY. The dashboard signs every runtime-override record with it and refuses to start without it."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || length(var.overrides_verify_keys) > 0
      error_message = "dashboard_admins_enabled needs overrides_verify_keys, the public keys listed in FORGD_OVERRIDES_VERIFY_KEY. Every service verifies the runtime-override records with them; without one a service reads no runtime overrides and its /readyz answers 503."
    }
  }
}

# --- the findings connector ----------------------------------------------
#
# A read-only MCP server over the findings store, added to a Claude
# organization as a custom connector. See docs/CONNECTOR.md. Off unless
# connector_enabled.
#
# Claude calls it from Anthropic's cloud and it verifies the bearer token
# from the customer's identity provider itself, so it allows
# unauthenticated invocation and has IAP off: a sign-in or an IAM invoker
# check in front answers Claude before the connector's own 401 can point it
# at the identity provider. It runs as an account of its own, which
# store-gcs binds as a reader through reader_members, and gets no hash salt
# and no secret.
locals {
  connector_name = "${var.name_prefix}-connector"
  # Cloud Run's deterministic service URL: https://<service>-<project number>.<region>.run.app.
  connector_host     = "${local.connector_name}-${data.google_project.this.number}.${var.region}.run.app"
  connector_resource = var.connector_resource == "" ? "https://${local.connector_host}/mcp" : var.connector_resource
  # A malformed connector_resource is refused by the https, lowercase and
  # /mcp checks, so the host check reports only a well-formed URL on the
  # wrong host.
  connector_resource_malformed = !(startswith(var.connector_resource, "https://") && endswith(var.connector_resource, "/mcp") && var.connector_resource == lower(var.connector_resource))

  connector_env = merge(
    {
      FORGD_ROLE                = "connector"
      FORGD_CONNECTOR_ENABLED   = "true"
      FORGD_CONNECTOR_RESOURCE  = local.connector_resource
      FORGD_CONNECTOR_AUTH_MODE = "oidc_jwt"
    },
    # Lists as JSON, because an environment variable cannot carry a list.
    length(var.connector_scopes) == 0 ? {} : { FORGD_CONNECTOR_SCOPES = jsonencode(var.connector_scopes) },
    var.connector_required_scope == "" ? {} : { FORGD_CONNECTOR_REQUIRED_SCOPE = var.connector_required_scope },
    length(var.connector_allowed_origins) == 0 ? {} : { FORGD_CONNECTOR_ALLOWED_ORIGINS = jsonencode(var.connector_allowed_origins) },
    var.connector_issuer == "" ? {} : { FORGD_CONNECTOR_ISSUER = var.connector_issuer },
    var.connector_jwks_url == "" ? {} : { FORGD_CONNECTOR_JWKS_URL = var.connector_jwks_url },
    length(var.connector_audience) == 0 ? {} : { FORGD_CONNECTOR_AUDIENCE = jsonencode(var.connector_audience) },
    var.connector_groups_claim == "" ? {} : { FORGD_CONNECTOR_GROUPS_CLAIM = var.connector_groups_claim },
    length(var.connector_issuers) == 0 ? {} : { FORGD_CONNECTOR_ISSUERS = jsonencode(var.connector_issuers) },
  )
}

resource "google_service_account" "connector" {
  count = var.connector_enabled ? 1 : 0

  project      = var.project_id
  account_id   = local.connector_name
  display_name = "forgd-verdict connector"
}

resource "google_cloud_run_v2_service" "connector" {
  count = var.connector_enabled ? 1 : 0

  project             = var.project_id
  deletion_protection = var.deletion_protection
  name                = local.connector_name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  iap_enabled         = false
  labels              = var.labels

  template {
    service_account = google_service_account.connector[0].email

    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      name  = "connector"
      image = var.image

      ports {
        container_port = 8090
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      startup_probe {
        http_get {
          path = local.ready_path
        }
        period_seconds    = 5
        timeout_seconds   = 4
        failure_threshold = 12
      }

      # With dashboard_admins_enabled, a failing readiness probe stops new
      # traffic to the instance without shutting it down; traffic returns
      # when it passes again.
      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          http_get {
            path = local.ready_path
          }
          period_seconds    = 10
          timeout_seconds   = 4
          failure_threshold = 3
        }
      }

      # NO FORGD_HASH_SALT and no secret, as for the dashboard.
      dynamic "env" {
        for_each = merge(local.base_env, local.connector_env)
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]

    precondition {
      condition     = length(var.connector_issuers) > 0 || var.connector_issuer != ""
      error_message = "connector_enabled but connector_issuer is empty. The connector accepts only tokens from your identity provider and refuses to start without issuer, jwks_url and audience."
    }
    precondition {
      condition     = length(var.connector_issuers) > 0 || var.connector_jwks_url != ""
      error_message = "connector_enabled but connector_jwks_url is empty. The connector accepts only tokens from your identity provider and refuses to start without issuer, jwks_url and audience."
    }
    precondition {
      condition     = length(var.connector_issuers) > 0 || length(var.connector_audience) > 0
      error_message = "connector_enabled but connector_audience is empty. The connector accepts only tokens from your identity provider and refuses to start without issuer, jwks_url and audience."
    }
    precondition {
      condition     = length(var.connector_issuers) == 0 || (var.connector_issuer == "" && var.connector_jwks_url == "" && length(var.connector_audience) == 0)
      error_message = "Set either connector_issuers or connector_issuer, connector_jwks_url and connector_audience, not both. The connector refuses a partial single issuer beside a list."
    }
    precondition {
      condition     = alltrue([for i in var.connector_issuers : i.issuer != "" && i.jwks_url != "" && length(i.audience) > 0])
      error_message = "A connector_issuers entry has an empty issuer, jwks_url or audience; the connector refuses to start without them, because an unset audience would accept tokens minted for another application."
    }
    precondition {
      condition     = var.connector_required_scope != "" || !contains(["", "$"], substr(try(trimspace(tostring(yamldecode(var.policy_yaml).connector.required_scope)), ""), 0, 1))
      error_message = "connector_required_scope is empty. Without it any token whose audience matches is accepted, including an ID token or a dashboard token from the same app registration. Set it to the scope your identity provider issues for the connector, for example findings.read. A $VAR placeholder in the policy does not count: this module sets no such variable on the connector."
    }
    precondition {
      condition     = var.connector_resource == "" || startswith(var.connector_resource, "https://")
      error_message = "connector_resource must be an https URL."
    }
    precondition {
      condition     = var.connector_resource == lower(var.connector_resource)
      error_message = "connector_resource must be lowercase: Claude sends the canonical form, lowercase host included, and the app refuses anything else."
    }
    precondition {
      condition     = var.connector_resource == "" || endswith(var.connector_resource, "/mcp")
      error_message = "connector_resource must end in /mcp, the path the connector serves."
    }
    precondition {
      condition     = local.connector_resource_malformed || var.connector_resource == "" || var.connector_resource == "https://${local.connector_host}/mcp"
      error_message = "connector_resource does not match https://<name_prefix>-connector-<project number>.<region>.run.app/mcp, where Cloud Run serves the connector. Claude checks the metadata's resource against the URL it was given, so the two must match; leave connector_resource empty to derive it."
    }
  }
}

# Anyone may invoke, because the caller authenticates to the app.
resource "google_cloud_run_v2_service_iam_member" "connector_public_invoke" {
  count = var.connector_enabled ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.connector[0].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# --- adapter 2's receiving end: intake -----------------------------------
#
# Laptops POST spooled findings here with their fleet's bearer token, and
# a developer's hook waits on /scan, so it gets the daemon and the salt.
resource "google_cloud_run_v2_service" "intake" {
  count = var.enable_intake ? 1 : 0

  project             = var.project_id
  deletion_protection = var.deletion_protection
  name                = local.names["intake"]
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  iap_enabled         = false
  labels              = var.labels

  template {
    service_account = google_service_account.role["intake"].email

    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      name  = "intake"
      image = var.image

      ports {
        container_port = 8200
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "2Gi"
        }
        cpu_idle          = false
        startup_cpu_boost = true
      }

      startup_probe {
        http_get {
          path = local.ready_path
        }
        period_seconds    = 5
        timeout_seconds   = 4
        failure_threshold = 24
      }

      # With dashboard_admins_enabled, a failing readiness probe stops new
      # traffic to the instance without shutting it down; traffic returns
      # when it passes again.
      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          http_get {
            path = local.ready_path
          }
          period_seconds    = 10
          timeout_seconds   = 4
          failure_threshold = 3
        }
      }

      liveness_probe {
        http_get {
          path = "/livez"
        }
        period_seconds    = 10
        timeout_seconds   = 5
        failure_threshold = 6
      }

      dynamic "env" {
        for_each = merge(local.base_env, local.gitleaks_env, {
          FORGD_ROLE = "intake"
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.role_secrets["intake"]
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.access]

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]
  }
}

# --- who may call what ---------------------------------------------------

locals {
  service_names = merge({
    verdict   = google_cloud_run_v2_service.verdict.name
    collector = google_cloud_run_v2_service.collector.name
    dashboard = google_cloud_run_v2_service.dashboard.name
  }, var.enable_intake ? { intake = google_cloud_run_v2_service.intake[0].name } : {})
}

# Verdict, collector and intake: anyone may invoke, because the caller
# authenticates to the app. NEVER the dashboard.
resource "google_cloud_run_v2_service_iam_member" "public_invoke" {
  for_each = toset(local.public_services)

  project  = var.project_id
  location = var.region
  name     = local.service_names[each.key]
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# IAP calls the dashboard as its service agent, which exists once
# iap.googleapis.com is enabled in the project.
resource "google_cloud_run_v2_service_iam_member" "dashboard_iap_invoke" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.dashboard.name
  role     = "roles/run.invoker"
  member   = local.iap_service_agent
}

# The people allowed through IAP to the dashboard, on this service only.
resource "google_iap_web_cloud_run_service_iam_member" "dashboard_access" {
  for_each = toset(var.dashboard_iap_members)

  project                = var.project_id
  location               = var.region
  cloud_run_service_name = google_cloud_run_v2_service.dashboard.name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = each.value
}

# --- adapter 3: the ingest job -------------------------------------------
resource "google_cloud_run_v2_job" "ingest" {
  project             = var.project_id
  deletion_protection = var.deletion_protection
  name                = local.names["ingest"]
  location            = var.region
  labels              = var.labels

  template {
    task_count  = 1
    parallelism = 1

    template {
      service_account = google_service_account.role["ingest"].email
      # One pass walks every session updated since the last run plus every
      # claude.ai chat, and T2 multiplies the per-frame cost.
      timeout     = "3600s"
      max_retries = 1

      # No volume: the ingest cursor lives in the findings store.
      containers {
        name = "ingest"
        # The -ingest variant. A job on the base image runs, finds nothing
        # at T2 because the tier is `auto` and the dependency is absent, and
        # reports it as a clean scan.
        image = var.ingest_image

        # 2 vCPU / 4 Gi: the only adapter that runs Presidio, and
        # en_core_web_lg is ~1 GB resident on top of a 1.4 GB image.
        resources {
          limits = {
            cpu    = "2"
            memory = "4Gi"
          }
        }

        dynamic "env" {
          for_each = merge(local.base_env, {
            FORGD_ROLE        = "ingest"
            FORGD_INGEST_ARGS = "--family local"
          })
          content {
            name  = env.key
            value = env.value
          }
        }
        dynamic "env" {
          for_each = local.role_secrets["ingest"]
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = env.value
                version = "latest"
              }
            }
          }
        }
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.access]

  lifecycle {
    ignore_changes = [template[0].template[0].containers[0].image, client, client_version]
  }
}

# --- the ingest schedule -------------------------------------------------
#
# Cloud Scheduler calls the job's :run method as an account of its own,
# which may run this job and nothing else. It is not a job identity and
# holds no store access or secret.
resource "google_service_account" "scheduler" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-scheduler"
  display_name = "forgd-verdict ingest scheduler"
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_runs_ingest" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.ingest.name
  role     = "roles/run.invoker"
  member   = google_service_account.scheduler.member
}

resource "google_cloud_scheduler_job" "ingest" {
  project   = var.project_id
  region    = var.region
  name      = local.names["ingest"]
  schedule  = var.ingest_schedule
  time_zone = var.ingest_schedule_timezone

  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/${google_cloud_run_v2_job.ingest.name}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler.email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }

  depends_on = [google_cloud_run_v2_job_iam_member.scheduler_runs_ingest]
}
