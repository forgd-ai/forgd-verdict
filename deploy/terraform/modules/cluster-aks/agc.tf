# Application Gateway for Containers, with ingress = "agc"
# (docs/design/agc.md).
#
# Bring-your-own deployment: this module creates the AGC, its frontend and
# its subnet association, and the chart's Gateway names them. The ALB
# Controller, installed by Helm before the chart, reads its configuration
# from the cluster and writes it to AGC as the identity below.

resource "azurerm_application_load_balancer" "this" {
  count               = local.agc ? 1 : 0
  name                = "${var.cluster_name}-agc"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_application_load_balancer_frontend" "this" {
  count                        = local.agc ? 1 : 0
  name                         = "${var.cluster_name}-frontend"
  application_load_balancer_id = azurerm_application_load_balancer.this[0].id
  tags                         = var.tags
}

resource "azurerm_application_load_balancer_subnet_association" "this" {
  count                        = local.agc ? 1 : 0
  name                         = "${var.cluster_name}-agc-subnet"
  application_load_balancer_id = azurerm_application_load_balancer.this[0].id
  subnet_id                    = var.agc_subnet_id
  tags                         = var.tags
}

# --- the ALB Controller's identity -----------------------------------------

resource "azurerm_user_assigned_identity" "alb_controller" {
  count               = local.agc ? 1 : 0
  name                = coalesce(var.alb_controller_identity_name, "${var.cluster_name}-alb-controller")
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# The controller's Helm chart names its service account alb-controller-sa.
resource "azurerm_federated_identity_credential" "alb_controller" {
  count                     = local.agc ? 1 : 0
  name                      = "${var.cluster_name}-alb-controller"
  user_assigned_identity_id = azurerm_user_assigned_identity.alb_controller[0].id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.alb_controller_namespace}:alb-controller-sa"
}

# The three grants Microsoft documents for a bring-your-own deployment.
# Owner and Contributor do not carry the configuration manager's data
# actions.
resource "azurerm_role_assignment" "alb_controller_configures_agc" {
  count                            = local.agc ? 1 : 0
  scope                            = regex("^(.*/resourceGroups/[^/]+)/", azurerm_application_load_balancer.this[0].id)[0]
  role_definition_name             = "AppGw for Containers Configuration Manager"
  principal_id                     = azurerm_user_assigned_identity.alb_controller[0].principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "alb_controller_joins_subnet" {
  count                            = local.agc ? 1 : 0
  scope                            = var.agc_subnet_id
  role_definition_name             = "Network Contributor"
  principal_id                     = azurerm_user_assigned_identity.alb_controller[0].principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "alb_controller_reads_nodes" {
  count                            = local.agc && var.grant_alb_controller_node_reader ? 1 : 0
  scope                            = azurerm_kubernetes_cluster.this.node_resource_group_id
  role_definition_name             = "Reader"
  principal_id                     = azurerm_user_assigned_identity.alb_controller[0].principal_id
  skip_service_principal_aad_check = true
}

# --- WAF policies ----------------------------------------------------------
#
# Four, attached per HTTPRoute by the chart's WebApplicationFirewallPolicy
# objects:
#
#   protected  the dashboard: DRS 2.1 and Bot Manager 1.1 on, bodies
#              inspected, Prevention
#   connector  the connector: its source-range rule
#   hook       /hook: its source-range rule and the optional rate limit
#   api        /v1, /intake, /scan and diagnostics: the optional rate limit
#
# On connector, hook and api, endpoint_waf_managed_rules decides whether
# DRS 2.1 runs:
#
#   off         the last custom rule allows every request, and a request a
#               custom rule allows is not evaluated by the managed rules, so
#               DRS never sees the prompt text, tool output and telemetry
#               these routes carry. Body inspection is off.
#   Detection   no allow rule; DRS evaluates headers, URI and body (up to
#               2000 KB) and logs what it would block. The policy mode is
#               policy-wide, so the custom rules only log as well.
#   Prevention  as Detection, and a DRS match is answered 403.
#
# request_body_enforcement is off, so a body over the inspection limit is
# not refused for its size. DRS 2.1 scores content types it does not parse
# (OTLP protobuf, hook-ship's NDJSON) under rule 920420, and a body that
# fails to parse (gzip, possibly JSON cut at the limit) under 200002; the
# soak shows which fire, and endpoint_waf_rule_overrides turns them to Log
# or off per policy. The firewall log's matched data is scrubbed for the
# request parts in local.endpoint_log_scrubbed.
#
# /hook has a route and a policy of its own so that its source ranges
# apply to whatever the Gateway routes there, with no path match in the
# WAF to disagree with the route's.
#
# The allow and rate-limit rules match every request by its URI beginning
# with "/": Application Gateway refuses RemoteAddr with the Any operator,
# which is for variables that take a selector, and IPMatch covers IPv4 only.
#
# The provider requires a managed rule set on every policy, so with
# endpoint_waf_managed_rules = "off" all three still carry DRS 2.1.
#
# With managed rules on, the hook policy excludes the keys and values of
# every argument DRS parses from the body, so on /hook it inspects headers
# and URI only. The body is prompt text, tool input and tool output, and
# 943120 matches its session_id key on every request that has no Referer.

locals {
  managed_rule_set_drs   = { type = "Microsoft_DefaultRuleSet", version = "2.1" }
  endpoint_managed_rules = var.endpoint_waf_managed_rules != "off"
  endpoint_waf_mode      = local.endpoint_managed_rules ? var.endpoint_waf_managed_rules : "Prevention"
  # Request parts masked in the firewall log, whose matched-data field
  # would otherwise carry prompt text, telemetry and scanned content.
  endpoint_log_scrubbed = ["RequestArgNames", "RequestPostArgNames", "RequestJSONArgNames", "RequestHeaderNames", "RequestCookieNames"]
  hook_argument_exclusions = local.endpoint_managed_rules ? [
    { match_variable = "RequestArgKeys", selector = "*", selector_match_operator = "EqualsAny" },
    { match_variable = "RequestArgValues", selector = "*", selector_match_operator = "EqualsAny" },
  ] : []
}

resource "azurerm_web_application_firewall_policy" "protected" {
  count               = local.agc ? 1 : 0
  name                = "${var.cluster_name}-waf-protected"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  policy_settings {
    enabled            = true
    mode               = "Prevention"
    request_body_check = true
  }

  managed_rules {
    managed_rule_set {
      type    = local.managed_rule_set_drs.type
      version = local.managed_rule_set_drs.version
    }
    managed_rule_set {
      type    = "Microsoft_BotManagerRuleSet"
      version = "1.1"
    }

    dynamic "exclusion" {
      for_each = toset(var.protected_waf_excluded_cookies)
      content {
        match_variable          = "RequestCookieNames"
        selector                = exclusion.value
        selector_match_operator = "StartsWith"
      }
    }
    dynamic "exclusion" {
      for_each = toset(var.protected_waf_excluded_args)
      content {
        match_variable          = "RequestArgNames"
        selector                = exclusion.value
        selector_match_operator = "Equals"
      }
    }
  }
}

resource "azurerm_web_application_firewall_policy" "connector" {
  count               = local.agc ? 1 : 0
  name                = "${var.cluster_name}-waf-connector"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  policy_settings {
    enabled                          = true
    mode                             = local.endpoint_waf_mode
    request_body_check               = local.endpoint_managed_rules
    request_body_enforcement         = false
    request_body_inspect_limit_in_kb = local.endpoint_managed_rules ? 2000 : 128

    dynamic "log_scrubbing" {
      for_each = toset(local.endpoint_managed_rules ? ["scrub"] : [])
      content {
        enabled = true
        dynamic "rule" {
          for_each = local.endpoint_log_scrubbed
          content {
            enabled                 = true
            match_variable          = rule.value
            selector_match_operator = "EqualsAny"
          }
        }
      }
    }
  }

  dynamic "custom_rules" {
    for_each = toset(length(var.connector_source_ranges) > 0 ? ["ranges"] : [])
    content {
      name      = "ConnectorSourceRanges"
      priority  = 10
      rule_type = "MatchRule"
      action    = "Block"

      match_conditions {
        match_variables {
          variable_name = "RemoteAddr"
        }
        operator           = "IPMatch"
        negation_condition = true
        match_values       = var.connector_source_ranges
      }
    }
  }

  dynamic "custom_rules" {
    for_each = toset(local.endpoint_managed_rules ? [] : ["allow"])
    content {
      name      = "AllowRest"
      priority  = 100
      rule_type = "MatchRule"
      action    = "Allow"

      match_conditions {
        match_variables {
          variable_name = "RequestUri"
        }
        operator     = "BeginsWith"
        match_values = ["/"]
      }
    }
  }

  managed_rules {
    managed_rule_set {
      type    = local.managed_rule_set_drs.type
      version = local.managed_rule_set_drs.version

      dynamic "rule_group_override" {
        for_each = { for o in lookup(var.endpoint_waf_rule_overrides, "connector", []) : o.rule_group_name => o... }
        content {
          rule_group_name = rule_group_override.key
          dynamic "rule" {
            for_each = rule_group_override.value
            content {
              id      = rule.value.rule_id
              enabled = rule.value.action != "Disabled"
              action  = rule.value.action == "Disabled" ? null : rule.value.action
            }
          }
        }
      }
    }

    dynamic "exclusion" {
      for_each = lookup(var.endpoint_waf_exclusions, "connector", [])
      content {
        match_variable          = exclusion.value.match_variable
        selector                = exclusion.value.selector
        selector_match_operator = exclusion.value.selector_match_operator
      }
    }
  }
}

resource "azurerm_web_application_firewall_policy" "hook" {
  count               = local.agc ? 1 : 0
  name                = "${var.cluster_name}-waf-hook"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  policy_settings {
    enabled                          = true
    mode                             = local.endpoint_waf_mode
    request_body_check               = local.endpoint_managed_rules
    request_body_enforcement         = false
    request_body_inspect_limit_in_kb = local.endpoint_managed_rules ? 2000 : 128

    dynamic "log_scrubbing" {
      for_each = toset(local.endpoint_managed_rules ? ["scrub"] : [])
      content {
        enabled = true
        dynamic "rule" {
          for_each = local.endpoint_log_scrubbed
          content {
            enabled                 = true
            match_variable          = rule.value
            selector_match_operator = "EqualsAny"
          }
        }
      }
    }
  }

  dynamic "custom_rules" {
    for_each = toset(length(var.hook_source_ranges) > 0 ? ["ranges"] : [])
    content {
      name      = "HookSourceRanges"
      priority  = 10
      rule_type = "MatchRule"
      action    = "Block"

      match_conditions {
        match_variables {
          variable_name = "RemoteAddr"
        }
        operator           = "IPMatch"
        negation_condition = true
        match_values       = var.hook_source_ranges
      }
    }
  }

  dynamic "custom_rules" {
    for_each = toset(var.api_rate_limit_per_minute == null ? [] : ["limit"])
    content {
      name                 = "RateLimit"
      priority             = 20
      rule_type            = "RateLimitRule"
      action               = "Block"
      rate_limit_duration  = "OneMin"
      rate_limit_threshold = var.api_rate_limit_per_minute
      group_rate_limit_by  = "ClientAddr"

      match_conditions {
        match_variables {
          variable_name = "RequestUri"
        }
        operator     = "BeginsWith"
        match_values = ["/"]
      }
    }
  }

  dynamic "custom_rules" {
    for_each = toset(local.endpoint_managed_rules ? [] : ["allow"])
    content {
      name      = "AllowRest"
      priority  = 100
      rule_type = "MatchRule"
      action    = "Allow"

      match_conditions {
        match_variables {
          variable_name = "RequestUri"
        }
        operator     = "BeginsWith"
        match_values = ["/"]
      }
    }
  }

  managed_rules {
    managed_rule_set {
      type    = local.managed_rule_set_drs.type
      version = local.managed_rule_set_drs.version

      dynamic "rule_group_override" {
        for_each = { for o in lookup(var.endpoint_waf_rule_overrides, "hook", []) : o.rule_group_name => o... }
        content {
          rule_group_name = rule_group_override.key
          dynamic "rule" {
            for_each = rule_group_override.value
            content {
              id      = rule.value.rule_id
              enabled = rule.value.action != "Disabled"
              action  = rule.value.action == "Disabled" ? null : rule.value.action
            }
          }
        }
      }
    }

    dynamic "exclusion" {
      for_each = distinct(concat(local.hook_argument_exclusions, lookup(var.endpoint_waf_exclusions, "hook", [])))
      content {
        match_variable          = exclusion.value.match_variable
        selector                = exclusion.value.selector
        selector_match_operator = exclusion.value.selector_match_operator
      }
    }
  }

  lifecycle {
    precondition {
      condition = var.endpoint_waf_managed_rules != "Detection" || (
        length(var.hook_source_ranges) == 0 && length(var.connector_source_ranges) == 0 &&
      var.api_rate_limit_per_minute == null)
      error_message = "endpoint_waf_managed_rules = \"Detection\" puts the hook, api and connector policies in Detection mode, where the source-range and rate-limit rules only log. Leave hook_source_ranges, connector_source_ranges and api_rate_limit_per_minute unset until the policies are in Prevention."
    }
  }
}

resource "azurerm_web_application_firewall_policy" "api" {
  count               = local.agc ? 1 : 0
  name                = "${var.cluster_name}-waf-api"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  policy_settings {
    enabled                          = true
    mode                             = local.endpoint_waf_mode
    request_body_check               = local.endpoint_managed_rules
    request_body_enforcement         = false
    request_body_inspect_limit_in_kb = local.endpoint_managed_rules ? 2000 : 128

    dynamic "log_scrubbing" {
      for_each = toset(local.endpoint_managed_rules ? ["scrub"] : [])
      content {
        enabled = true
        dynamic "rule" {
          for_each = local.endpoint_log_scrubbed
          content {
            enabled                 = true
            match_variable          = rule.value
            selector_match_operator = "EqualsAny"
          }
        }
      }
    }
  }

  dynamic "custom_rules" {
    for_each = toset(var.api_rate_limit_per_minute == null ? [] : ["limit"])
    content {
      name                 = "RateLimit"
      priority             = 20
      rule_type            = "RateLimitRule"
      action               = "Block"
      rate_limit_duration  = "OneMin"
      rate_limit_threshold = var.api_rate_limit_per_minute
      group_rate_limit_by  = "ClientAddr"

      match_conditions {
        match_variables {
          variable_name = "RequestUri"
        }
        operator     = "BeginsWith"
        match_values = ["/"]
      }
    }
  }

  dynamic "custom_rules" {
    for_each = toset(local.endpoint_managed_rules ? [] : ["allow"])
    content {
      name      = "AllowRest"
      priority  = 100
      rule_type = "MatchRule"
      action    = "Allow"

      match_conditions {
        match_variables {
          variable_name = "RequestUri"
        }
        operator     = "BeginsWith"
        match_values = ["/"]
      }
    }
  }

  managed_rules {
    managed_rule_set {
      type    = local.managed_rule_set_drs.type
      version = local.managed_rule_set_drs.version

      dynamic "rule_group_override" {
        for_each = { for o in lookup(var.endpoint_waf_rule_overrides, "api", []) : o.rule_group_name => o... }
        content {
          rule_group_name = rule_group_override.key
          dynamic "rule" {
            for_each = rule_group_override.value
            content {
              id      = rule.value.rule_id
              enabled = rule.value.action != "Disabled"
              action  = rule.value.action == "Disabled" ? null : rule.value.action
            }
          }
        }
      }
    }

    dynamic "exclusion" {
      for_each = lookup(var.endpoint_waf_exclusions, "api", [])
      content {
        match_variable          = exclusion.value.match_variable
        selector                = exclusion.value.selector
        selector_match_operator = exclusion.value.selector_match_operator
      }
    }
  }
}

# A security policy is what lets the controller reference a WAF policy from
# a WebApplicationFirewallPolicy object; one per WAF policy.
resource "azurerm_application_load_balancer_security_policy" "waf" {
  for_each = local.agc ? {
    protected = azurerm_web_application_firewall_policy.protected[0].id
    connector = azurerm_web_application_firewall_policy.connector[0].id
    hook      = azurerm_web_application_firewall_policy.hook[0].id
    api       = azurerm_web_application_firewall_policy.api[0].id
  } : {}
  name                               = "${var.cluster_name}-${each.key}"
  application_load_balancer_id       = azurerm_application_load_balancer.this[0].id
  location                           = var.location
  web_application_firewall_policy_id = each.value
  tags                               = var.tags
}

# The AGC's access and firewall logs. The firewall log is where Detection
# mode's matches appear.
resource "azurerm_monitor_diagnostic_setting" "agc" {
  count                      = local.agc && var.agc_log_analytics_workspace_id != null ? 1 : 0
  name                       = "${var.cluster_name}-agc-logs"
  target_resource_id         = azurerm_application_load_balancer.this[0].id
  log_analytics_workspace_id = var.agc_log_analytics_workspace_id

  enabled_log {
    category_group = "allLogs"
  }
}
