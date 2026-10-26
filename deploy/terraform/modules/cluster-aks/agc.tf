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
# Four, all in Prevention mode, attached per HTTPRoute by the chart's
# WebApplicationFirewallPolicy objects:
#
#   protected  the dashboard: DRS 2.1 and Bot Manager 1.1 on, bodies inspected
#   connector  the connector: its source-range rule, then allow
#   hook       /hook: its source-range rule and the optional rate limit,
#              then allow
#   api        /v1, /intake, /scan and diagnostics: the optional rate limit,
#              then allow
#
# /hook has a route and a policy of its own so that its source ranges
# apply to whatever the Gateway routes there, with no path match in the
# WAF to disagree with the route's.
#
# The provider requires a managed rule set on every policy. On connector,
# hook and api the last custom rule allows every request, and a request a
# custom rule allows is not evaluated by the managed rules, so DRS never
# sees the prompt text, tool output and telemetry those routes carry. A 403
# there is a webhook failure, or for the connector a broken OAuth discovery,
# since its own 401 is how Claude finds the identity provider. Body
# inspection is off on both as well.

locals {
  managed_rule_set_drs = { type = "Microsoft_DefaultRuleSet", version = "2.1" }
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
  }
}

resource "azurerm_web_application_firewall_policy" "connector" {
  count               = local.agc ? 1 : 0
  name                = "${var.cluster_name}-waf-connector"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  policy_settings {
    enabled                  = true
    mode                     = "Prevention"
    request_body_check       = false
    request_body_enforcement = false
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

  custom_rules {
    name      = "AllowRest"
    priority  = 100
    rule_type = "MatchRule"
    action    = "Allow"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator = "Any"
    }
  }

  managed_rules {
    managed_rule_set {
      type    = local.managed_rule_set_drs.type
      version = local.managed_rule_set_drs.version
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
    enabled                  = true
    mode                     = "Prevention"
    request_body_check       = false
    request_body_enforcement = false
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
          variable_name = "RemoteAddr"
        }
        operator = "Any"
      }
    }
  }

  custom_rules {
    name      = "AllowRest"
    priority  = 100
    rule_type = "MatchRule"
    action    = "Allow"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator = "Any"
    }
  }

  managed_rules {
    managed_rule_set {
      type    = local.managed_rule_set_drs.type
      version = local.managed_rule_set_drs.version
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
    enabled                  = true
    mode                     = "Prevention"
    request_body_check       = false
    request_body_enforcement = false
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
          variable_name = "RemoteAddr"
        }
        operator = "Any"
      }
    }
  }

  custom_rules {
    name      = "AllowRest"
    priority  = 100
    rule_type = "MatchRule"
    action    = "Allow"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator = "Any"
    }
  }

  managed_rules {
    managed_rule_set {
      type    = local.managed_rule_set_drs.type
      version = local.managed_rule_set_drs.version
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
