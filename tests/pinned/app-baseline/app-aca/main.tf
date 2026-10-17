# The four roles as Container Apps, from one image.
#
# `FORGD_ROLE` selects the role, so the services cannot drift to different
# versions of the scan core:
#
#   server     adapter 1, the verdict server. Anthropic calls IN.
#   collect    adapter 4, the OTLP collector. Anthropic pushes IN.
#   dashboard  read-only over the findings store. Holds no credential.
#   ingest     adapter 3, a cron job. Holds the Compliance Access Key.
#
# TWO OF THESE MUST NEVER SIT BEHIND A PLATFORM AUTH PROVIDER. Anthropic
# authenticates to the verdict server with a webhook signature and to the
# collector with an OTLP header, so an auth redirect turns every governed
# prompt or export into a delivery failure rather than a deny. Nothing here
# enables one, and scripts/verify_deployment.sh asserts it on every roll.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
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
  org_env = { for name, id in var.org_ids : "FORGD_ORG_ID_${upper(name)}" => id }

  # policy.yaml travels compressed. Plain it is ~18 KB, which is above the
  # single-variable limit on some targets; gzipped it is ~10 KB and fits
  # everywhere. The entrypoint decodes it and refuses to start if it does
  # not, because falling back to the baked default would silently run rules
  # nobody chose.
  policy_gz = base64gzip(var.policy_yaml)

  base_env = merge({
    FORGD_VERDICT_STORE     = var.store_url
    AZURE_CLIENT_ID         = var.identity_client_id
    FORGD_VERDICT_LOG_LEVEL = "INFO"
    FORGD_POLICY_INLINE_GZ  = local.policy_gz
  }, local.org_env)
}

# AcrPull for both identities, or nothing can start.
#
# The apps pull with `registry_identity`, and an identity created by
# Terraform has no rights on a registry Terraform did not create. The first
# apply failed exactly here: "unable to pull image using Managed identity
# .../mi-forgd-verdict-app-tf for registry ...". The hand-built deployment
# had this grant, and reproducing the resources without reproducing the
# grant is the kind of gap a plan cannot show -- every resource was valid
# and the revision still could not provision.
#
# The DASHBOARD identity needs it too. It is Storage Blob Data READER on the
# findings container, deliberately, but it still has to pull the image it
# runs.
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
    identity_ids = [var.identity_id]
  }

  registry {
    server   = var.registry_server
    identity = var.identity_id
  }

  secret {
    name  = "webhook-secret"
    value = var.webhook_secret
  }
  secret {
    name  = "hash-salt"
    value = var.hash_salt
  }
  dynamic "secret" {
    for_each = toset(var.metrics_token == "" ? [] : ["metrics"])
    content {
      name  = "metrics-token"
      value = var.metrics_token
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
    # min 1 is NOT a cost preference. The org's verdict timeout covers
    # connection through response, so a cold start on the first governed
    # prompt after an idle period is a WEBHOOK FAILURE rather than a slow
    # allow, and repeated ones trip the circuit breaker.
    #
    # max 1 because the session cache and the webhook-id dedupe store are
    # per-process: spreading frames across replicas makes the latency
    # numbers meaningless. Raise it deliberately, not by default.
    min_replicas = 1
    max_replicas = 1

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
      env {
        name        = "FORGD_HASH_SALT"
        secret_name = "hash-salt"
      }
      dynamic "env" {
        for_each = toset(var.metrics_token == "" ? [] : ["metrics"])
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
    identity_ids = [var.identity_id]
  }

  registry {
    server   = var.registry_server
    identity = var.identity_id
  }

  secret {
    name  = "otel-token"
    value = var.otel_token
  }
  # /stats, which is how a silent surface is diagnosed. Without it the
  # endpoint does not exist and "nothing arrived" is indistinguishable from
  # "arrived and was rejected".
  dynamic "secret" {
    for_each = toset(var.metrics_token == "" ? [] : ["metrics"])
    content {
      name  = "metrics-token"
      value = var.metrics_token
    }
  }
  secret {
    name  = "hash-salt"
    value = var.hash_salt
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

      env {
        name  = "FORGD_ROLE"
        value = "collect"
      }
      env {
        name  = "FORGD_GITLEAKS_SOCKET"
        value = "/run/forgd/gitleaksd.sock"
      }
      env {
        name        = "FORGD_OTEL_TOKEN_PRIMARY"
        secret_name = "otel-token"
      }
      dynamic "env" {
        for_each = toset(var.metrics_token == "" ? [] : ["metrics"])
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

  # The READER identity. Storage Blob Data Reader, not Contributor: this is
  # the one internet-facing service a human signs into, and a compromise
  # that could rewrite findings would be rewriting the evidence.
  identity {
    type         = "UserAssigned"
    identity_ids = [var.reader_identity_id]
  }

  registry {
    server   = var.registry_server
    identity = var.reader_identity_id
  }

  dynamic "secret" {
    for_each = toset(var.dashboard_auth_client_id == "" ? [] : ["entra"])
    content {
      name  = "entra-client-secret"
      value = var.dashboard_auth_client_secret
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

      env {
        name  = "FORGD_ROLE"
        value = "dashboard"
      }
      # Overrides base_env: ManagedIdentityCredential would otherwise pick
      # the writer identity and the dashboard would hold write access it
      # was deliberately not granted.
      env {
        name  = "AZURE_CLIENT_ID"
        value = var.reader_identity_client_id
      }
      # The proxy that strips inbound copies of the trusted header.
      #
      # `trusted_header` is identity forgery anywhere the container is
      # directly reachable, and the app refuses the mode without this.
      # The Helm chart has always demanded it; this module documented the
      # interaction and enforced nothing, so the guard held on one of the
      # two deployment paths.
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
        path      = "/healthz"
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
    identity_ids = [var.identity_id]
  }

  registry {
    server   = var.registry_server
    identity = var.identity_id
  }

  secret {
    name  = "compliance-key"
    value = var.compliance_api_key
  }
  secret {
    name  = "hash-salt"
    value = var.hash_salt
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
        # /healthz MUST be excluded, and this is not a nicety.
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
