# Adapter 5's Azure Monitor destination.
#
# OPTIONAL, and composed only by a deployment that wants it. Nothing else
# in the stack references it, and `helm uninstall` cannot reach it.
#
# What the sink needs is one URI and one role assignment. Everything here
# exists to produce those two things:
#
#   workspace -> table (azapi) -> endpoint -> rule -> two role assignments
#
# The sink holds no credential. It authenticates as the deployment's
# managed identity -- the same one that writes findings -- which needs
# Monitoring Metrics Publisher on BOTH the rule and the endpoint. They are
# separate scopes and a grant on one does not cover the other.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # For the custom table. See the resource below for why azurerm cannot
    # do it. Same provider app-aca already uses for the one thing azurerm
    # has no schema for.
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.0"
    }
  }
}

resource "azurerm_log_analytics_workspace" "verdict" {
  name                = var.workspace_name
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "PerGB2018"

  # Findings already live in the blob store, which is the system of record
  # and is not on a retention clock. This copy exists to be queried
  # alongside the customer's other telemetry, so it is kept short: Log
  # Analytics bills per GB ingested AND per GB retained past the free
  # period, and a long default here would be a bill a fork inherits
  # without choosing it.
  retention_in_days = var.retention_days

  # A cap, because adapter 5 forwards every event rather than every
  # finding. -1 is no cap and is the provider default.
  daily_quota_gb = var.daily_quota_gb

  tags = var.tags
}

# The shape `AzureMonitorSink._rows()` posts. Column names and types must
# match it exactly -- a column the table does not declare is DROPPED by the
# ingestion pipeline, silently and per record, which looks like the sink
# working.
#
# azapi, because `azurerm_log_analytics_workspace_table` UPDATES a table
# that already exists -- it sets retention and plan on built-in tables --
# and cannot create a custom one. Pointed at a `_CL` name that does not
# exist yet it fails the apply with:
#
#   ResourceNotFound: The specified table: 'ForgdVerdict_CL' was not found.
#
# which reads like a missing dependency rather than a resource that does
# not do what it sounds like.
resource "azapi_resource" "table" {
  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = "${var.table_name}_CL"
  parent_id = azurerm_log_analytics_workspace.verdict.id

  body = {
    properties = {
      # Both, and they must agree or the API rejects the pair. Total
      # retention is archive-inclusive and cannot be shorter than the
      # interactive period.
      retentionInDays      = var.retention_days
      totalRetentionInDays = var.retention_days
      schema = {
        name = "${var.table_name}_CL"
        columns = [
          # Azure Monitor requires this one and fills it from the record.
          { name = "TimeGenerated", type = "datetime" },
          { name = "Kind", type = "string" },
          { name = "EventName", type = "string" },
          { name = "Surface", type = "string" },
          { name = "Organization", type = "string" },
          # Dynamic, not flattened. A flattened attribute bag makes every
          # new attribute name a schema change, and the rule drops columns
          # it was not told about.
          { name = "Attributes", type = "dynamic" },
          { name = "Resource", type = "dynamic" },
          # Detector -> count. No offsets and no values, so a query can
          # alert on "this was censored and why" without being told what.
          { name = "Redactions", type = "dynamic" },
          { name = "RedactionTotal", type = "int" },
        ]
      }
    }
  }
}

# An explicit endpoint, not the rule's own.
#
# A DCR created with `kind: Direct` generates its own `logsIngestion`
# endpoint and needs no DCE -- but the azurerm provider pinned here only
# accepts Linux, Windows, AgentDirectToStore and WorkspaceTransforms, so
# that shape is not reachable from Terraform at this version. The DCE is
# the supported path and produces the same ingestion URI.
resource "azurerm_monitor_data_collection_endpoint" "verdict" {
  name                          = var.endpoint_name
  resource_group_name           = var.resource_group_name
  location                      = var.location
  public_network_access_enabled = true
  tags                          = var.tags
}

resource "azurerm_monitor_data_collection_rule" "verdict" {
  name                        = var.rule_name
  resource_group_name         = var.resource_group_name
  location                    = var.location
  data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.verdict.id

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.verdict.id
      name                  = "verdict"
    }
  }

  data_flow {
    streams      = ["Custom-${var.table_name}_CL"]
    destinations = ["verdict"]
    # Straight through. A transform here would be a second place that
    # decides what a finding record looks like, and the first one is the
    # sink's `_rows()`.
    output_stream = "Custom-${var.table_name}_CL"
    transform_kql = "source"
  }

  stream_declaration {
    stream_name = "Custom-${var.table_name}_CL"

    # Azure Monitor requires this column and fills it from the record.
    column {
      name = "TimeGenerated"
      type = "datetime"
    }
    column {
      name = "Kind"
      type = "string"
    }
    column {
      name = "EventName"
      type = "string"
    }
    column {
      name = "Surface"
      type = "string"
    }
    column {
      name = "Organization"
      type = "string"
    }
    # Dynamic, not flattened. A flattened attribute bag makes every new
    # attribute name a schema change, and the rule drops columns it was
    # not told about.
    column {
      name = "Attributes"
      type = "dynamic"
    }
    column {
      name = "Resource"
      type = "dynamic"
    }
    # Detector -> count. No offsets and no values, so a query can alert on
    # "this event was censored and why" without being told what.
    column {
      name = "Redactions"
      type = "dynamic"
    }
    column {
      name = "RedactionTotal"
      type = "int"
    }
  }

  tags = var.tags

  depends_on = [azapi_resource.table]
}

# The only grant. "Monitoring Metrics Publisher" is what the Logs Ingestion
# API checks, despite the name saying metrics -- there is no separate logs
# publisher role, and the obvious-sounding "Log Analytics Contributor" does
# NOT grant ingestion against a rule.
#
# Scoped to the rule, not the workspace or the group: this identity already
# writes findings, and a broader grant here would widen what a compromised
# pod reaches for no benefit.
resource "azurerm_role_assignment" "publisher" {
  scope                = azurerm_monitor_data_collection_rule.verdict.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = var.writer_principal_id
}

# The endpoint is a separate scope and the grant on the rule does not cover
# it. Without this the POST is refused with a 403 that names neither.
resource "azurerm_role_assignment" "publisher_endpoint" {
  scope                = azurerm_monitor_data_collection_endpoint.verdict.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = var.writer_principal_id
}
