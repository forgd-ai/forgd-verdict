# The six roles as Container Apps, from one image.
#
# `FORGD_ROLE` selects the role, so the services cannot drift to different
# versions of the scan core:
#
#   server     adapter 1, the verdict server. Anthropic calls IN.
#   collect    adapter 4, the OTLP collector. Anthropic pushes IN.
#   intake     adapter 2's receiving end, optional. Laptops call IN.
#   dashboard  read-only over the findings store. Holds no credential.
#   connector  the findings connector for Claude, optional. Claude calls IN.
#   ingest     adapter 3, a cron job. Holds the Compliance Access Key.
#
# THREE OF THESE MUST NEVER SIT BEHIND A PLATFORM AUTH PROVIDER. Anthropic
# authenticates to the verdict server with a webhook signature and to the
# collector with an OTLP header, and a laptop to the intake with a bearer
# token, so an auth redirect turns every governed prompt, export or shipped
# batch into a delivery failure rather than a deny. Nothing here
# enables one, and scripts/verify_deployment.sh asserts it on every roll.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # azurerm has no resource for Container Apps auth -- checked the 4.x
    # schema, there is none -- so the dashboard's Entra front end is the one
    # thing here that needs the raw ARM API.
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.0"
    }
  }
}

locals {
  # Upper case, hyphens to underscores, as the Helm chart and app-ecs name
  # them: an environment variable name cannot hold a hyphen.
  org_env = { for name, id in var.org_ids : "FORGD_ORG_ID_${upper(replace(name, "-", "_"))}" => id }

  # name -> its env name suffix, over the token names only, so the tokens
  # themselves stay sensitive. The secret name is the same suffix in lower
  # case with hyphens.
  otel_token_names = { for name in distinct(concat(nonsensitive(keys(var.otel_tokens)), keys(var.otel_token_secret_ids))) : name => upper(replace(name, "-", "_")) }
  org_id_by_env    = { for name, id in var.org_ids : upper(replace(name, "-", "_")) => id }
  # Token names with no non-empty org id under the same env name. A token
  # still at the placeholder authenticates nothing, so it is not listed.
  otel_tokens_without_org = [
    for name, suffix in local.otel_token_names : name
    if lookup(local.org_id_by_env, suffix, "") == "" && !contains(keys(local.otel_fleet_by_env), suffix) && (contains(keys(var.otel_token_secret_ids), name) || !nonsensitive(lookup(var.otel_tokens, name, "") == "placeholder-not-yet-issued"))
  ]
  # Per-org secrets, keyed by org_ids name: name -> env name suffix, over
  # the names only, so the values stay sensitive. A secret is named from the
  # suffix in lower case with hyphens.
  # Each map's names come from the plain map and its *_secret_ids map.
  webhook_org_names         = { for name in distinct(concat(nonsensitive(keys(var.webhook_secrets)), keys(var.webhook_secret_ids))) : name => upper(replace(name, "-", "_")) }
  webhook_org_previous      = { for name, suffix in local.webhook_org_names : name => suffix if(contains(keys(var.webhook_secret_ids), name) ? var.webhook_secret_ids[name].previous != "" : nonsensitive(var.webhook_secrets[name].previous != "")) }
  compliance_org_names      = { for name in distinct(concat(nonsensitive(keys(var.compliance_api_keys)), keys(var.compliance_key_secret_ids))) : name => upper(replace(name, "-", "_")) }
  intake_fleet_org_names    = { for name in distinct(concat(nonsensitive(keys(var.intake_fleet_tokens)), keys(var.intake_fleet_token_secret_ids))) : name => upper(replace(name, "-", "_")) }
  intake_fleet_org_previous = { for name, suffix in local.intake_fleet_org_names : name => suffix if(contains(keys(var.intake_fleet_token_secret_ids), name) ? var.intake_fleet_token_secret_ids[name].previous != "" : nonsensitive(var.intake_fleet_tokens[name].previous != "")) }
  intake_token_names        = { for name in distinct(concat(nonsensitive(keys(var.intake_tokens)), keys(var.intake_token_secret_ids))) : name => upper(replace(name, "-", "_")) }

  # Whether each optional single secret is set, by value or by id.
  has_webhook_previous      = var.webhook_secret_previous_id != "" || nonsensitive(var.webhook_secret_previous != "")
  has_metrics_token         = var.metrics_token_secret_id != "" || nonsensitive(var.metrics_token != "")
  has_intake_fleet          = var.intake_fleet_token_secret_id != "" || nonsensitive(var.intake_fleet_token != "")
  has_intake_fleet_previous = var.intake_fleet_token_previous_secret_id != "" || nonsensitive(var.intake_fleet_token_previous != "")

  # A slot given both a value and an id, or a name in both a plain map and
  # its id map. A placeholder default is not a value. Each problem is one
  # sentence of the refusal, and names variables, never values.
  secret_id_problems = concat(
    [for v, slot in {
      webhook_secret              = ["webhook_secret_id", nonsensitive(contains(["", "placeholder-not-yet-issued"], var.webhook_secret)), var.webhook_secret_id]
      webhook_secret_previous     = ["webhook_secret_previous_id", nonsensitive(var.webhook_secret_previous == ""), var.webhook_secret_previous_id]
      hash_salt                   = ["hash_salt_secret_id", nonsensitive(var.hash_salt == ""), var.hash_salt_secret_id]
      metrics_token               = ["metrics_token_secret_id", nonsensitive(var.metrics_token == ""), var.metrics_token_secret_id]
      compliance_api_key          = ["compliance_key_secret_id", nonsensitive(contains(["", "placeholder-not-yet-issued"], var.compliance_api_key)), var.compliance_key_secret_id]
      intake_fleet_token          = ["intake_fleet_token_secret_id", nonsensitive(var.intake_fleet_token == ""), var.intake_fleet_token_secret_id]
      intake_fleet_token_previous = ["intake_fleet_token_previous_secret_id", nonsensitive(var.intake_fleet_token_previous == ""), var.intake_fleet_token_previous_secret_id]
    } : "set ${v} or ${slot[0]}, not both" if !slot[1] && slot[2] != ""],
    flatten([for plain, both in {
      webhook_secrets     = ["webhook_secret_ids", setintersection(nonsensitive(keys(var.webhook_secrets)), keys(var.webhook_secret_ids))]
      compliance_api_keys = ["compliance_key_secret_ids", setintersection(nonsensitive(keys(var.compliance_api_keys)), keys(var.compliance_key_secret_ids))]
      intake_fleet_tokens = ["intake_fleet_token_secret_ids", setintersection(nonsensitive(keys(var.intake_fleet_tokens)), keys(var.intake_fleet_token_secret_ids))]
      intake_tokens       = ["intake_token_secret_ids", setintersection(nonsensitive(keys(var.intake_tokens)), keys(var.intake_token_secret_ids))]
      otel_tokens         = ["otel_token_secret_ids", setintersection(nonsensitive(keys(var.otel_tokens)), keys(var.otel_token_secret_ids))]
    } : [for name in both[1] : "${plain}.${name} and ${both[0]}.${name} are both set; give each name in one of them"]]),
    length(local.otel_token_names) == 0 ? ["otel_tokens or otel_token_secret_ids needs at least one entry, or the collector accepts nothing"] : [],
    var.hash_salt_secret_id == "" && nonsensitive(length(var.hash_salt) < 16) ? ["Set TF_VAR_hash_salt to at least 16 characters: openssl rand -base64 32, or name it in Key Vault with hash_salt_secret_id"] : [],
  )
  # Every variable each map could set, its single slots included, so a
  # repeat is a collision whether or not a previous value is set now.
  org_secret_vars = {
    webhook_secrets = concat(["WEBHOOK_SECRET", "WEBHOOK_SECRET_PREVIOUS"], flatten([
    for name, suffix in local.webhook_org_names : ["WEBHOOK_SECRET_${suffix}", "WEBHOOK_SECRET_${suffix}_PREVIOUS"]]))
    compliance_api_keys = concat(["ANTHROPIC_COMPLIANCE_ACCESS_KEY"], [
    for name, suffix in local.compliance_org_names : "ANTHROPIC_COMPLIANCE_ACCESS_KEY_${suffix}"])
    intake_fleet_tokens = concat(["FORGD_INTAKE_FLEET_TOKEN", "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS"], flatten([
    for name, suffix in local.intake_fleet_org_names : ["FORGD_INTAKE_FLEET_TOKEN_${suffix}", "FORGD_INTAKE_FLEET_TOKEN_${suffix}_PREVIOUS"]]))
  }
  org_secret_names = {
    webhook_secrets     = keys(local.webhook_org_names)
    compliance_api_keys = keys(local.compliance_org_names)
    intake_fleet_tokens = keys(local.intake_fleet_org_names)
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
    [for name, _ in var.otel_fleets : "otel_fleets.${name} has no token in otel_tokens" if !contains(values(local.otel_token_names), upper(replace(name, "-", "_")))],
  )

  # policy.yaml travels compressed. Plain it is ~18 KB, which is above the
  # single-variable limit on some targets; gzipped it is ~10 KB and fits
  # everywhere. The entrypoint decodes it and refuses to start if it does
  # not, because falling back to the baked default would silently run rules
  # nobody chose.
  policy_gz = base64gzip(var.policy_yaml)

  # The identity each writer role runs as.
  writer_identity = { verdict = var.identity_id, collector = var.identity_id, intake = var.identity_id, ingest = var.identity_id }
  writer_order    = concat(["verdict", "collector"], var.enable_intake ? ["intake"] : [], ["ingest"])
  # FORGD_OVERRIDES_WRITER_ROLES: one writer role per distinct store
  # identity, the first in writer_order that runs as it. Ingest is last, so
  # it is listed only when no long-running role shares its identity. The
  # dashboard and the connector only read.
  overrides_writer_roles = [
    for i, role in local.writer_order : role
    if !contains([for earlier in slice(local.writer_order, 0, i) : local.writer_identity[earlier]],
    local.writer_identity[role])
  ]

  # Every role honours runtime overrides only while this is "true", and
  # adopts only records that verify against a FORGD_OVERRIDES_VERIFY_KEY.
  overrides_env = var.dashboard_admins_enabled ? {
    FORGD_OVERRIDES_ENABLED      = "true"
    FORGD_OVERRIDES_WRITER_ROLES = join(",", local.overrides_writer_roles)
    FORGD_OVERRIDES_VERIFY_KEY   = join(",", var.overrides_verify_keys)
  } : {}

  # The path each readiness probe requests. /healthz answers 200 however
  # the runtime overrides read; /readyz answers 503 until they are confirmed.
  ready_path = var.dashboard_admins_enabled ? "/readyz" : "/healthz"

  base_env = merge({
    FORGD_VERDICT_STORE     = var.store_url
    AZURE_CLIENT_ID         = var.identity_client_id
    FORGD_VERDICT_LOG_LEVEL = "INFO"
    FORGD_POLICY_INLINE_GZ  = local.policy_gz
  }, local.org_env, local.overrides_env)
}

# AcrPull for both identities, or nothing can start.
#
# The apps pull with `registry_identity`, and an identity created by
# Terraform has no rights on a registry Terraform did not create. The first
# apply failed exactly here: "unable to pull image using Managed identity
# .../<app identity> for registry ...". The hand-built deployment
# had this grant, and reproducing the resources without reproducing the
# grant is the kind of gap a plan cannot show -- every resource was valid
# and the revision still could not provision.
#
# The DASHBOARD identity needs it too. It only reads the findings container
# (Storage Blob Data Reader, or store-azure's custom reader role while
# control_enabled is true), deliberately, but it still has to pull
# the image it runs.
resource "azurerm_role_assignment" "writer_pulls_images" {
  scope                = var.registry_id
  role_definition_name = "AcrPull"
  principal_id         = var.identity_principal_id
}

resource "azurerm_role_assignment" "reader_pulls_images" {
  scope                = var.registry_id
  role_definition_name = "AcrPull"
  principal_id         = var.reader_identity_principal_id
}

resource "azurerm_container_app_environment" "this" {
  name                = var.environment_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  # Azure creates this whether or not it is declared, so leaving it out
  # produced a permanent diff: every plan wanted to null it. A plan that
  # always shows changes is a plan nobody reads, which defeats the gate on
  # the apply.
  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }
}

# --- adapter 1: the verdict server ---------------------------------------
resource "azurerm_container_app" "verdict" {
  name                         = var.verdict_app_name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [local.writer_identity["verdict"]]
  }

  registry {
    server   = var.registry_server
    identity = var.identity_id
  }

  secret {
    name                = "webhook-secret"
    value               = var.webhook_secret_id == "" ? var.webhook_secret : null
    key_vault_secret_id = var.webhook_secret_id == "" ? null : var.webhook_secret_id
    identity            = var.webhook_secret_id == "" ? null : var.identity_id
  }
  dynamic "secret" {
    for_each = toset(local.has_webhook_previous ? ["previous"] : [])
    content {
      name                = "webhook-secret-previous"
      value               = var.webhook_secret_previous_id == "" ? var.webhook_secret_previous : null
      key_vault_secret_id = var.webhook_secret_previous_id == "" ? null : var.webhook_secret_previous_id
      identity            = var.webhook_secret_previous_id == "" ? null : var.identity_id
    }
  }
  dynamic "secret" {
    for_each = local.webhook_org_names
    content {
      name                = "webhook-secret-${lower(replace(secret.value, "_", "-"))}"
      value               = contains(keys(var.webhook_secret_ids), secret.key) ? null : try(var.webhook_secrets[secret.key].current, null)
      key_vault_secret_id = try(var.webhook_secret_ids[secret.key].current, null)
      identity            = contains(keys(var.webhook_secret_ids), secret.key) ? var.identity_id : null
    }
  }
  dynamic "secret" {
    for_each = local.webhook_org_previous
    content {
      name                = "webhook-secret-${lower(replace(secret.value, "_", "-"))}-previous"
      value               = contains(keys(var.webhook_secret_ids), secret.key) ? null : try(var.webhook_secrets[secret.key].previous, null)
      key_vault_secret_id = try(var.webhook_secret_ids[secret.key].previous, null)
      identity            = contains(keys(var.webhook_secret_ids), secret.key) ? var.identity_id : null
    }
  }
  secret {
    name                = "hash-salt"
    value               = var.hash_salt_secret_id == "" ? var.hash_salt : null
    key_vault_secret_id = var.hash_salt_secret_id == "" ? null : var.hash_salt_secret_id
    identity            = var.hash_salt_secret_id == "" ? null : var.identity_id
  }
  dynamic "secret" {
    for_each = toset(local.has_metrics_token ? ["metrics"] : [])
    content {
      name                = "metrics-token"
      value               = var.metrics_token_secret_id == "" ? var.metrics_token : null
      key_vault_secret_id = var.metrics_token_secret_id == "" ? null : var.metrics_token_secret_id
      identity            = var.metrics_token_secret_id == "" ? null : var.identity_id
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    # min 1: the org's verdict timeout covers
    # connection through response, so a cold start on the first governed
    # prompt after an idle period is a WEBHOOK FAILURE rather than a slow
    # allow, and repeated ones trip the circuit breaker.
    #
    # max 1 because the session cache and the webhook-id dedupe store are
    # per-process: spreading frames across replicas makes the latency
    # numbers meaningless. Raise it deliberately, not by default.
    min_replicas = 1
    max_replicas = 1

    # memory holds up to twice server.preauth_body_budget_bytes (256 MiB)
    # of unsigned request body; see docs/SERVER.md#memory.
    container {
      name   = "verdict"
      image  = var.image
      cpu    = 1.0
      memory = "2Gi"

      # /livez answers 503 only when gitleaksd stops answering; a restart
      # restarts the daemon with the app.
      liveness_probe {
        transport               = "HTTP"
        port                    = 8000
        path                    = "/livez"
        initial_delay           = 60
        interval_seconds        = 10
        timeout                 = 5
        failure_count_threshold = 6
      }

      # With dashboard_admins_enabled, holds the replica out of traffic while
      # /readyz answers 503.
      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          transport = "HTTP"
          port      = 8000
          path      = local.ready_path
        }
      }

      env {
        name  = "FORGD_ROLE"
        value = "server"
      }
      env {
        name  = "FORGD_VERDICT_MODE"
        value = var.verdict_mode
      }
      env {
        name  = "FORGD_GITLEAKS_SOCKET"
        value = "/run/forgd/gitleaksd.sock"
      }
      env {
        name        = "WEBHOOK_SECRET"
        secret_name = "webhook-secret"
      }
      dynamic "env" {
        for_each = toset(local.has_webhook_previous ? ["previous"] : [])
        content {
          name        = "WEBHOOK_SECRET_PREVIOUS"
          secret_name = "webhook-secret-previous"
        }
      }
      dynamic "env" {
        for_each = local.webhook_org_names
        content {
          name        = "WEBHOOK_SECRET_${env.value}"
          secret_name = "webhook-secret-${lower(replace(env.value, "_", "-"))}"
        }
      }
      dynamic "env" {
        for_each = local.webhook_org_previous
        content {
          name        = "WEBHOOK_SECRET_${env.value}_PREVIOUS"
          secret_name = "webhook-secret-${lower(replace(env.value, "_", "-"))}-previous"
        }
      }
      env {
        name        = "FORGD_HASH_SALT"
        secret_name = "hash-salt"
      }
      dynamic "env" {
        for_each = toset(local.has_metrics_token ? ["metrics"] : [])
        content {
          name        = "FORGD_METRICS_TOKEN"
          secret_name = "metrics-token"
        }
      }
      dynamic "env" {
        for_each = local.base_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  # CI rolls images; Terraform sets the first one and then keeps out of the
  # way. See DESIGN.md -- routing a release through `terraform apply` buys a
  # state lock and a plan to change one field.
  depends_on = [
    azurerm_role_assignment.writer_pulls_images,
    azurerm_role_assignment.reader_pulls_images,
  ]

  lifecycle {
    ignore_changes = [template[0].container[0].image]

    precondition {
      condition     = length(local.org_secret_problems) == 0
      error_message = "${join("; ", local.org_secret_problems)}."
    }
    precondition {
      condition     = length(local.secret_id_problems) == 0
      error_message = "${join("; ", local.secret_id_problems)}."
    }
  }
}

# --- adapter 4: the OTLP collector ---------------------------------------
resource "azurerm_container_app" "collector" {
  name                         = var.collector_app_name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [local.writer_identity["collector"]]
  }

  registry {
    server   = var.registry_server
    identity = var.identity_id
  }

  dynamic "secret" {
    for_each = local.otel_token_names
    content {
      name                = "otel-token-${lower(replace(secret.value, "_", "-"))}"
      value               = contains(keys(var.otel_token_secret_ids), secret.key) ? null : try(var.otel_tokens[secret.key], null)
      key_vault_secret_id = try(var.otel_token_secret_ids[secret.key], null)
      identity            = contains(keys(var.otel_token_secret_ids), secret.key) ? var.identity_id : null
    }
  }
  # /stats, which is how a silent surface is diagnosed. Without it the
  # endpoint does not exist and "nothing arrived" is indistinguishable from
  # "arrived and was rejected".
  dynamic "secret" {
    for_each = toset(local.has_metrics_token ? ["metrics"] : [])
    content {
      name                = "metrics-token"
      value               = var.metrics_token_secret_id == "" ? var.metrics_token : null
      key_vault_secret_id = var.metrics_token_secret_id == "" ? null : var.metrics_token_secret_id
      identity            = var.metrics_token_secret_id == "" ? null : var.identity_id
    }
  }
  secret {
    name                = "hash-salt"
    value               = var.hash_salt_secret_id == "" ? var.hash_salt : null
    key_vault_secret_id = var.hash_salt_secret_id == "" ? null : var.hash_salt_secret_id
    identity            = var.hash_salt_secret_id == "" ? null : var.identity_id
  }

  # External, because Anthropic pushes OTLP to it. No auth provider in
  # front: the exporter authenticates with an OTLP header, and a redirect
  # turns every export into a delivery failure.
  ingress {
    external_enabled = true
    target_port      = 8100
    transport        = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    # An exporter has a timeout and drops or retries a batch that does not
    # answer, so a cold start costs telemetry. max 1 because the store sink
    # queue is per-process, and backpressure -- the 503 that makes an
    # exporter hold its batch -- only means anything with one queue.
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "collector"
      image  = var.image
      cpu    = 1.0
      memory = "2Gi"

      # /livez answers 503 only when gitleaksd stops answering; a restart
      # restarts the daemon with the app.
      liveness_probe {
        transport               = "HTTP"
        port                    = 8100
        path                    = "/livez"
        initial_delay           = 60
        interval_seconds        = 10
        timeout                 = 5
        failure_count_threshold = 6
      }

      # With dashboard_admins_enabled, holds the replica out of traffic while
      # /readyz answers 503.
      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          transport = "HTTP"
          port      = 8100
          path      = local.ready_path
        }
      }

      env {
        name  = "FORGD_ROLE"
        value = "collect"
      }
      env {
        name  = "FORGD_GITLEAKS_SOCKET"
        value = "/run/forgd/gitleaksd.sock"
      }
      dynamic "env" {
        for_each = local.otel_token_names
        content {
          name        = "FORGD_OTEL_TOKEN_${env.value}"
          secret_name = "otel-token-${lower(replace(env.value, "_", "-"))}"
        }
      }
      dynamic "env" {
        for_each = toset(local.has_metrics_token ? ["metrics"] : [])
        content {
          name        = "FORGD_METRICS_TOKEN"
          secret_name = "metrics-token"
        }
      }
      env {
        name        = "FORGD_HASH_SALT"
        secret_name = "hash-salt"
      }
      dynamic "env" {
        for_each = local.base_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.writer_pulls_images,
    azurerm_role_assignment.reader_pulls_images,
  ]

  lifecycle {
    ignore_changes = [template[0].container[0].image]

    precondition {
      condition     = length(local.otel_tokens_without_org) == 0
      error_message = "otel_tokens.${join(", otel_tokens.", local.otel_tokens_without_org)} has no non-empty org_ids entry under the same FORGD_ORG_ID_<NAME>. The collector cross-checks a batch's organization.id against that id, and with none the check cannot run, so any organization's batch is accepted on the token. Add the org's id to org_ids."
    }

    precondition {
      condition     = length(local.otel_fleet_problems) == 0
      error_message = "${join("; ", local.otel_fleet_problems)}. The collector accepts a fleet token only for orgs it holds ids for, so every org in a fleet needs its org_ids entry."
    }
  }
}

# --- adapter 2's receiving end: the intake ---------------------------------
#
# Developer laptops POST spooled findings here with their fleet's bearer
# token, and ask /scan for a verdict, so a laptop holds no store
# credential. External and with no auth provider in front: a laptop
# authenticates with a bearer header, and a redirect to a sign-in page is
# a failure the hook cannot follow.
resource "azurerm_container_app" "intake" {
  count = var.enable_intake ? 1 : 0

  name                         = var.intake_app_name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [local.writer_identity["intake"]]
  }

  registry {
    server   = var.registry_server
    identity = var.identity_id
  }

  dynamic "secret" {
    for_each = toset(local.has_intake_fleet ? ["current"] : [])
    content {
      name                = "intake-fleet-token"
      value               = var.intake_fleet_token_secret_id == "" ? var.intake_fleet_token : null
      key_vault_secret_id = var.intake_fleet_token_secret_id == "" ? null : var.intake_fleet_token_secret_id
      identity            = var.intake_fleet_token_secret_id == "" ? null : var.identity_id
    }
  }
  dynamic "secret" {
    for_each = toset(local.has_intake_fleet_previous ? ["previous"] : [])
    content {
      name                = "intake-fleet-token-previous"
      value               = var.intake_fleet_token_previous_secret_id == "" ? var.intake_fleet_token_previous : null
      key_vault_secret_id = var.intake_fleet_token_previous_secret_id == "" ? null : var.intake_fleet_token_previous_secret_id
      identity            = var.intake_fleet_token_previous_secret_id == "" ? null : var.identity_id
    }
  }
  dynamic "secret" {
    for_each = local.intake_fleet_org_names
    content {
      name                = "intake-fleet-token-${lower(replace(secret.value, "_", "-"))}"
      value               = contains(keys(var.intake_fleet_token_secret_ids), secret.key) ? null : try(var.intake_fleet_tokens[secret.key].current, null)
      key_vault_secret_id = try(var.intake_fleet_token_secret_ids[secret.key].current, null)
      identity            = contains(keys(var.intake_fleet_token_secret_ids), secret.key) ? var.identity_id : null
    }
  }
  dynamic "secret" {
    for_each = local.intake_fleet_org_previous
    content {
      name                = "intake-fleet-token-${lower(replace(secret.value, "_", "-"))}-previous"
      value               = contains(keys(var.intake_fleet_token_secret_ids), secret.key) ? null : try(var.intake_fleet_tokens[secret.key].previous, null)
      key_vault_secret_id = try(var.intake_fleet_token_secret_ids[secret.key].previous, null)
      identity            = contains(keys(var.intake_fleet_token_secret_ids), secret.key) ? var.identity_id : null
    }
  }
  dynamic "secret" {
    for_each = local.intake_token_names
    content {
      name                = "intake-token-${lower(replace(secret.value, "_", "-"))}"
      value               = contains(keys(var.intake_token_secret_ids), secret.key) ? null : try(var.intake_tokens[secret.key], null)
      key_vault_secret_id = try(var.intake_token_secret_ids[secret.key], null)
      identity            = contains(keys(var.intake_token_secret_ids), secret.key) ? var.identity_id : null
    }
  }
  dynamic "secret" {
    for_each = toset(local.has_metrics_token ? ["metrics"] : [])
    content {
      name                = "metrics-token"
      value               = var.metrics_token_secret_id == "" ? var.metrics_token : null
      key_vault_secret_id = var.metrics_token_secret_id == "" ? null : var.metrics_token_secret_id
      identity            = var.metrics_token_secret_id == "" ? null : var.identity_id
    }
  }
  secret {
    name                = "hash-salt"
    value               = var.hash_salt_secret_id == "" ? var.hash_salt : null
    key_vault_secret_id = var.hash_salt_secret_id == "" ? null : var.hash_salt_secret_id
    identity            = var.hash_salt_secret_id == "" ? null : var.identity_id
  }

  ingress {
    external_enabled = true
    target_port      = 8200
    transport        = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    # A laptop's hook waits on /scan, and its shipping retries a refused
    # batch, so a cold start costs a prompt's wait. max 1, as the chart and
    # the other modules run it.
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "intake"
      image  = var.image
      cpu    = 1.0
      memory = "2Gi"

      liveness_probe {
        transport               = "HTTP"
        port                    = 8200
        path                    = "/livez"
        initial_delay           = 60
        interval_seconds        = 10
        timeout                 = 5
        failure_count_threshold = 6
      }

      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          transport = "HTTP"
          port      = 8200
          path      = local.ready_path
        }
      }

      env {
        name  = "FORGD_ROLE"
        value = "intake"
      }
      env {
        name  = "FORGD_GITLEAKS_SOCKET"
        value = "/run/forgd/gitleaksd.sock"
      }
      dynamic "env" {
        for_each = toset(local.has_intake_fleet ? ["current"] : [])
        content {
          name        = "FORGD_INTAKE_FLEET_TOKEN"
          secret_name = "intake-fleet-token"
        }
      }
      dynamic "env" {
        for_each = toset(local.has_intake_fleet_previous ? ["previous"] : [])
        content {
          name        = "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS"
          secret_name = "intake-fleet-token-previous"
        }
      }
      dynamic "env" {
        for_each = local.intake_fleet_org_names
        content {
          name        = "FORGD_INTAKE_FLEET_TOKEN_${env.value}"
          secret_name = "intake-fleet-token-${lower(replace(env.value, "_", "-"))}"
        }
      }
      dynamic "env" {
        for_each = local.intake_fleet_org_previous
        content {
          name        = "FORGD_INTAKE_FLEET_TOKEN_${env.value}_PREVIOUS"
          secret_name = "intake-fleet-token-${lower(replace(env.value, "_", "-"))}-previous"
        }
      }
      dynamic "env" {
        for_each = local.intake_token_names
        content {
          name        = "FORGD_INTAKE_TOKEN_${env.value}"
          secret_name = "intake-token-${lower(replace(env.value, "_", "-"))}"
        }
      }
      dynamic "env" {
        for_each = toset(local.has_metrics_token ? ["metrics"] : [])
        content {
          name        = "FORGD_METRICS_TOKEN"
          secret_name = "metrics-token"
        }
      }
      env {
        name        = "FORGD_HASH_SALT"
        secret_name = "hash-salt"
      }
      dynamic "env" {
        for_each = local.base_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.writer_pulls_images,
    azurerm_role_assignment.reader_pulls_images,
  ]

  lifecycle {
    ignore_changes = [template[0].container[0].image]

    precondition {
      condition     = local.has_intake_fleet || length(local.intake_fleet_org_names) > 0 || length(local.intake_token_names) > 0
      error_message = "enable_intake with no intake_fleet_token, intake_fleet_tokens or intake_tokens, nor a Key Vault id for one: the intake starts and refuses every laptop with 401, which looks exactly like a laptop with the wrong URL or a stale token."
    }
  }
}

# --- the dashboard -------------------------------------------------------
resource "azurerm_container_app" "dashboard" {
  name                         = var.dashboard_app_name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = var.tags

  # The READER identity, which only reads blobs, not the writer's: this is
  # the one internet-facing service a human signs into, and a compromise
  # that could rewrite findings would be rewriting the evidence.
  #
  # With dashboard_admins_enabled the control identity is attached as well
  # and AZURE_CLIENT_ID names it; the reader stays attached to pull the
  # image.
  identity {
    type         = "UserAssigned"
    identity_ids = var.dashboard_admins_enabled ? [var.reader_identity_id, var.control_identity_id] : [var.reader_identity_id]
  }

  registry {
    server   = var.registry_server
    identity = var.reader_identity_id
  }

  dynamic "secret" {
    for_each = toset(var.dashboard_auth_client_id == "" ? [] : ["entra"])
    content {
      name                = "entra-client-secret"
      value               = var.dashboard_auth_client_secret_secret_id == "" ? var.dashboard_auth_client_secret : null
      key_vault_secret_id = var.dashboard_auth_client_secret_secret_id == "" ? null : var.dashboard_auth_client_secret_secret_id
      identity            = var.dashboard_auth_client_secret_secret_id == "" ? null : var.reader_identity_id
    }
  }
  dynamic "secret" {
    for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
    content {
      name                = "dashboard-form-key"
      value               = var.dashboard_form_key_secret_id == "" ? var.dashboard_form_key : null
      key_vault_secret_id = var.dashboard_form_key_secret_id == "" ? null : var.dashboard_form_key_secret_id
      identity            = var.dashboard_form_key_secret_id == "" ? null : var.control_identity_id
    }
  }
  # A Key Vault reference, which Container Apps reads as the control identity.
  dynamic "secret" {
    for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
    content {
      name                = "overrides-signing-key"
      key_vault_secret_id = var.dashboard_signing_key_secret_id
      identity            = var.control_identity_id
    }
  }

  # NO hash-salt secret. The dashboard reads every finding hash, so giving
  # it the salt would put the key beside the data it protects -- one
  # compromise yielding both. It only needs the salt to resolve org LABELS,
  # which this deployment does not configure.
  ingress {
    external_enabled = true
    target_port      = 8080
    transport        = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "dashboard"
      image  = var.image
      cpu    = 0.5
      memory = "1Gi"

      # With dashboard_admins_enabled, holds the replica out of traffic while
      # /readyz answers 503.
      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          transport = "HTTP"
          port      = 8080
          path      = local.ready_path
        }
      }

      env {
        name  = "FORGD_ROLE"
        value = "dashboard"
      }
      # Overrides base_env: ManagedIdentityCredential would otherwise pick
      # the writer identity and the dashboard would hold write access it
      # was deliberately not granted.
      env {
        name  = "AZURE_CLIENT_ID"
        value = var.dashboard_admins_enabled ? var.control_client_id : var.reader_identity_client_id
      }
      dynamic "env" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          name        = "FORGD_DASHBOARD_FORM_KEY"
          secret_name = "dashboard-form-key"
        }
      }
      dynamic "env" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          name        = "FORGD_OVERRIDES_SIGNING_KEY"
          secret_name = "overrides-signing-key"
        }
      }
      dynamic "env" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          name  = "FORGD_OVERRIDES_WRITER_IDENTITIES"
          value = join(",", var.overrides_writer_identities)
        }
      }
      dynamic "env" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          name  = "FORGD_OVERRIDES_STORAGE_ACCOUNT_ID"
          value = var.overrides_storage_account_id
        }
      }
      # The proxy that strips inbound copies of the trusted header.
      #
      # `trusted_header` is identity forgery anywhere the container is
      # directly reachable, and the app refuses the mode without this.
      # The Helm chart requires the same attestation.
      #
      # EasyAuth is the answer here when `dashboard_auth_client_id` is
      # set: Container Apps strips inbound copies of the headers it
      # injects. With no client id there is no proxy, and an empty value
      # makes the dashboard refuse to start -- which is the right
      # outcome, not a regression.
      env {
        name  = "FORGD_DASHBOARD_STRIPPED_BY"
        value = var.dashboard_auth_client_id == "" ? "" : "Container Apps EasyAuth"
      }
      dynamic "env" {
        for_each = { for k, v in local.base_env : k => v if k != "AZURE_CLIENT_ID" }
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.writer_pulls_images,
    azurerm_role_assignment.reader_pulls_images,
  ]

  lifecycle {
    ignore_changes = [template[0].container[0].image]

    precondition {
      condition     = !var.dashboard_admins_enabled || var.overrides_writer_lockout
      error_message = "dashboard_admins_enabled needs overrides_writer_lockout = true: store-azure's overrides_writer_lockout output, which is true only with control_enabled. Without it the writer identities can write the runtime overrides object and audit prefix, and so forge an override."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || (length(var.overrides_writer_identities) > 0 && var.overrides_storage_account_id != "")
      error_message = "dashboard_admins_enabled needs overrides_writer_identities and overrides_storage_account_id: store-azure's overrides_writer_identities and storage_account_id outputs. The dashboard verifies each writer's lockout from its role assignments on the storage account, and adopts no runtime override while a writer is unverified."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || contains(var.overrides_writer_identities, var.identity_principal_id)
      error_message = "dashboard_admins_enabled needs overrides_writer_identities to include identity_principal_id, the writer identity every writer container runs as. The dashboard verifies only the identities listed, so an unlisted writer's lockout is never checked."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || (var.control_identity_id != "" && var.control_client_id != "")
      error_message = "dashboard_admins_enabled needs control_identity_id and control_client_id: store-azure's control identity, with control_enabled."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || !contains([var.reader_identity_id, var.identity_id], var.control_identity_id)
      error_message = "control_identity_id equals the reader's or the writer's identity. The reader must stay read-only for the other roles that hold it, and the writer can rewrite the findings; the dashboard's control identity must be its own."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || !contains([var.reader_identity_client_id, var.identity_client_id], var.control_client_id)
      error_message = "control_client_id equals the reader's or the writer's client id. The reader must stay read-only for the other roles that hold it, and the writer can rewrite the findings; the dashboard's control identity must be its own."
    }
    precondition {
      condition     = var.dashboard_auth_client_secret_secret_id == "" || nonsensitive(var.dashboard_auth_client_secret == "")
      error_message = "set dashboard_auth_client_secret or dashboard_auth_client_secret_secret_id, not both."
    }
    precondition {
      condition     = var.dashboard_form_key_secret_id == "" || nonsensitive(var.dashboard_form_key == "")
      error_message = "set dashboard_form_key or dashboard_form_key_secret_id, not both."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || var.dashboard_form_key_secret_id != "" || length(var.dashboard_form_key) >= 32
      error_message = "dashboard_admins_enabled needs dashboard_form_key, at least 32 characters (openssl rand -base64 32), or dashboard_form_key_secret_id. The dashboard refuses to start with admins configured and no form key."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || var.dashboard_signing_key_secret_id != ""
      error_message = "dashboard_admins_enabled needs dashboard_signing_key_secret_id, the Key Vault secret holding FORGD_OVERRIDES_SIGNING_KEY. The dashboard signs every runtime-override record with it and refuses to start without it."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || length(var.overrides_verify_keys) > 0
      error_message = "dashboard_admins_enabled needs overrides_verify_keys, the public keys set as FORGD_OVERRIDES_VERIFY_KEY. Every role verifies each runtime-override record against them and reads no runtime override without one."
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
# from the customer's identity provider itself, so it takes no auth
# provider: a sign-in in front answers Claude before the connector's own
# 401 can point it at the identity provider. Like the dashboard it runs on
# the READER identity and gets no hash salt and no secret.
locals {
  # External ingress on Container Apps serves <app name>.<environment default domain>.
  connector_default_host = "${var.connector_app_name}.${azurerm_container_app_environment.this.default_domain}"
  # The host connector_resource is matched against: the externally managed
  # one when given, else the default.
  connector_host     = var.connector_custom_host == "" ? local.connector_default_host : var.connector_custom_host
  connector_resource = var.connector_resource == "" ? "https://${local.connector_default_host}/mcp" : var.connector_resource
}

resource "azurerm_container_app" "connector" {
  count = var.connector_enabled ? 1 : 0

  name                         = var.connector_app_name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [var.reader_identity_id]
  }

  registry {
    server   = var.registry_server
    identity = var.reader_identity_id
  }

  ingress {
    external_enabled = true
    target_port      = 8090
    transport        = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }

    # Empty admits every source. Any entry makes the list an allowlist.
    dynamic "ip_security_restriction" {
      for_each = var.connector_source_ranges
      content {
        name             = "connector-source-${ip_security_restriction.key}"
        action           = "Allow"
        ip_address_range = ip_security_restriction.value
      }
    }
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "connector"
      image  = var.image
      cpu    = 0.5
      memory = "1Gi"

      readiness_probe {
        transport = "HTTP"
        port      = 8090
        path      = local.ready_path
      }

      env {
        name  = "FORGD_ROLE"
        value = "connector"
      }
      # Overrides base_env, as on the dashboard.
      env {
        name  = "AZURE_CLIENT_ID"
        value = var.reader_identity_client_id
      }
      env {
        name  = "FORGD_CONNECTOR_ENABLED"
        value = "true"
      }
      env {
        name  = "FORGD_CONNECTOR_RESOURCE"
        value = local.connector_resource
      }
      env {
        name  = "FORGD_CONNECTOR_AUTH_MODE"
        value = "oidc_jwt"
      }
      dynamic "env" {
        for_each = length(var.connector_scopes) == 0 ? [] : [jsonencode(var.connector_scopes)]
        content {
          name  = "FORGD_CONNECTOR_SCOPES"
          value = env.value
        }
      }
      dynamic "env" {
        for_each = var.connector_required_scope == "" ? [] : [var.connector_required_scope]
        content {
          name  = "FORGD_CONNECTOR_REQUIRED_SCOPE"
          value = env.value
        }
      }
      dynamic "env" {
        for_each = length(var.connector_allowed_origins) == 0 ? [] : [jsonencode(var.connector_allowed_origins)]
        content {
          name  = "FORGD_CONNECTOR_ALLOWED_ORIGINS"
          value = env.value
        }
      }
      dynamic "env" {
        for_each = var.connector_issuer == "" ? [] : [var.connector_issuer]
        content {
          name  = "FORGD_CONNECTOR_ISSUER"
          value = env.value
        }
      }
      dynamic "env" {
        for_each = var.connector_jwks_url == "" ? [] : [var.connector_jwks_url]
        content {
          name  = "FORGD_CONNECTOR_JWKS_URL"
          value = env.value
        }
      }
      # JSON, because an environment variable cannot carry a list.
      dynamic "env" {
        for_each = length(var.connector_audience) == 0 ? [] : [jsonencode(var.connector_audience)]
        content {
          name  = "FORGD_CONNECTOR_AUDIENCE"
          value = env.value
        }
      }
      dynamic "env" {
        for_each = var.connector_groups_claim == "" ? [] : [var.connector_groups_claim]
        content {
          name  = "FORGD_CONNECTOR_GROUPS_CLAIM"
          value = env.value
        }
      }
      dynamic "env" {
        for_each = length(var.connector_issuers) == 0 ? [] : [jsonencode(var.connector_issuers)]
        content {
          name  = "FORGD_CONNECTOR_ISSUERS"
          value = env.value
        }
      }
      # NO FORGD_HASH_SALT, as for the dashboard.
      dynamic "env" {
        for_each = { for k, v in local.base_env : k => v if k != "AZURE_CLIENT_ID" }
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.writer_pulls_images,
    azurerm_role_assignment.reader_pulls_images,
  ]

  lifecycle {
    ignore_changes = [template[0].container[0].image]

    # Every check but the last reads only values known at plan. The last
    # reads the environment's default domain unless connector_custom_host is
    # set; the domain is unknown until the environment exists, so on the
    # first apply that check runs at apply, before the app is created.
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
      condition     = var.connector_resource == "" ? var.connector_app_name == lower(var.connector_app_name) : var.connector_resource == lower(var.connector_resource)
      error_message = "connector_resource, or connector_app_name when it is derived, must be lowercase: Claude sends the canonical form, lowercase host included, and the app refuses anything else."
    }
    precondition {
      condition     = var.connector_resource == "" || endswith(var.connector_resource, "/mcp")
      error_message = "connector_resource must end in /mcp, the path the connector serves."
    }
    precondition {
      condition     = var.connector_custom_host == "" || var.connector_resource != ""
      error_message = "connector_custom_host is set but connector_resource is empty, which derives the default Container Apps host. Set connector_resource to https://<connector_custom_host>/mcp, the URL entered in Claude."
    }
    precondition {
      condition     = var.connector_resource == "" || trimprefix(var.connector_resource, "https://") == "${local.connector_host}/mcp"
      error_message = "connector_resource does not match the host the connector is served on: https://<connector_custom_host>/mcp when connector_custom_host is set, else https://<connector_app_name>.<environment default domain>/mcp. Claude checks the metadata's resource against the URL it was given, so the two must match; leave connector_resource empty to derive it."
    }
  }
}

# --- adapter 3: the ingest job -------------------------------------------
resource "azurerm_container_app_job" "ingest" {
  name                         = var.ingest_job_name
  resource_group_name          = var.resource_group_name
  location                     = var.location
  container_app_environment_id = azurerm_container_app_environment.this.id
  tags                         = var.tags

  # One pass walks every session updated since the last run plus every
  # claude.ai chat, and T2 multiplies the per-frame cost.
  workload_profile_name      = "Consumption"
  replica_timeout_in_seconds = 3600
  replica_retry_limit        = 1

  schedule_trigger_config {
    cron_expression          = var.ingest_cron
    parallelism              = 1
    replica_completion_count = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [local.writer_identity["ingest"]]
  }

  registry {
    server   = var.registry_server
    identity = var.identity_id
  }

  secret {
    name                = "compliance-key"
    value               = var.compliance_key_secret_id == "" ? var.compliance_api_key : null
    key_vault_secret_id = var.compliance_key_secret_id == "" ? null : var.compliance_key_secret_id
    identity            = var.compliance_key_secret_id == "" ? null : var.identity_id
  }
  dynamic "secret" {
    for_each = local.compliance_org_names
    content {
      name                = "compliance-key-${lower(replace(secret.value, "_", "-"))}"
      value               = contains(keys(var.compliance_key_secret_ids), secret.key) ? null : try(var.compliance_api_keys[secret.key], null)
      key_vault_secret_id = try(var.compliance_key_secret_ids[secret.key], null)
      identity            = contains(keys(var.compliance_key_secret_ids), secret.key) ? var.identity_id : null
    }
  }
  secret {
    name                = "hash-salt"
    value               = var.hash_salt_secret_id == "" ? var.hash_salt : null
    key_vault_secret_id = var.hash_salt_secret_id == "" ? null : var.hash_salt_secret_id
    identity            = var.hash_salt_secret_id == "" ? null : var.identity_id
  }

  # No volume: the ingest cursor lives in the
  # findings store, which is already durable, already reachable with
  # the identity this job holds, and works on every deployment target. An
  # EmptyDir would have been the obvious mistake -- it persists within a
  # replica, and a scheduled job gets a new replica every run.
  template {
    container {
      name = "ingest"
      # The -ingest variant. A job on the base image runs, finds nothing at
      # T2 because the tier is `auto` and the dependency is absent, and
      # reports it as a clean scan.
      image = var.ingest_image
      # 2 vCPU / 4 Gi, not the 1/2 the online services get: this is the only
      # adapter that runs Presidio, and en_core_web_lg is ~1 GB resident on
      # top of a 1.4 GB image.
      cpu    = 2.0
      memory = "4Gi"

      env {
        name  = "FORGD_ROLE"
        value = "ingest"
      }
      env {
        name  = "FORGD_INGEST_ARGS"
        value = "--family local"
      }
      env {
        name        = "ANTHROPIC_COMPLIANCE_ACCESS_KEY"
        secret_name = "compliance-key"
      }
      dynamic "env" {
        for_each = local.compliance_org_names
        content {
          name        = "ANTHROPIC_COMPLIANCE_ACCESS_KEY_${env.value}"
          secret_name = "compliance-key-${lower(replace(env.value, "_", "-"))}"
        }
      }
      env {
        name        = "FORGD_HASH_SALT"
        secret_name = "hash-salt"
      }
      dynamic "env" {
        for_each = local.base_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.writer_pulls_images,
    azurerm_role_assignment.reader_pulls_images,
  ]

  lifecycle {
    ignore_changes = [template[0].container[0].image]
  }
}


# --- the dashboard's Entra front end -------------------------------------
#
# The dashboard is the only service here that SHOULD sit behind a platform
# auth provider. The verdict server and the collector must never: Anthropic
# authenticates to them with a signature and an OTLP header, and a redirect
# would turn every governed prompt or export into a delivery failure. The
# dashboard is the opposite case -- a human signs in, and `auth.mode:
# trusted_header` expects a proxy to have put an identity in the header.
#
# Without this the module produces a dashboard nobody can log into: the app
# refuses every request with its own 401, correctly and uselessly.
#
# Optional, because a deployment fronting it some other way -- an ALB, an
# oauth2-proxy, its own oidc_jwt mode -- should not get a half-configured
# Entra provider. Leave the client id empty and none is created.
resource "azapi_resource" "dashboard_auth" {
  count = var.dashboard_auth_client_id == "" ? 0 : 1

  type      = "Microsoft.App/containerApps/authConfigs@2024-03-01"
  name      = "current"
  parent_id = azurerm_container_app.dashboard.id

  body = {
    properties = {
      platform = {
        enabled = true
      }
      globalValidation = {
        unauthenticatedClientAction = "RedirectToLoginPage"
        redirectToProvider          = "azureactivedirectory"
        # /healthz MUST be excluded.
        #
        # The deploy gate probes it before asserting anything else. Behind
        # an auth provider without this, the probe is redirected and
        # verify_deployment.sh fails `dashboard.health` on a deployment that
        # is perfectly healthy -- so the checks that matter never run.
        #
        # It reveals nothing: /healthz returns a status, an uptime and a
        # build, and holds no findings.
        excludedPaths = ["/healthz"]
      }
      identityProviders = {
        azureActiveDirectory = {
          registration = {
            clientId                = var.dashboard_auth_client_id
            clientSecretSettingName = "entra-client-secret"
            openIdIssuer            = "https://login.microsoftonline.com/${var.dashboard_auth_tenant_id}/v2.0"
          }
        }
      }
    }
  }
}
