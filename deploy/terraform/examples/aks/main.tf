# The AKS example: the same store module, an AKS cluster, and the federation
# between them. The chart is installed separately -- see ../../helm/README.md.
#
# THE STATE FILE IS PER STACK, NOT SHARED. The backend key comes from the
# stack name so a second stack cannot reach this one's findings by sharing
# a state file.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
  # EMPTY on purpose. Committed values would point every fork at one
  # deployment's state account, so the workflow passes them at init.
  #
  #   terraform init \
  #     -backend-config="resource_group_name=..." \
  #     -backend-config="storage_account_name=..." \
  #     -backend-config="container_name=tfstate" \
  #     -backend-config="key=<stack>.tfstate" \
  #     -backend-config="use_azuread_auth=true"
  backend "azurerm" {}
}

provider "azurerm" {
  features {
    # Nothing here manages data-plane properties of the findings account,
    # and with shared keys off a data-plane call would need a data role the
    # infra identity does not hold.
    storage {
      data_plane_available = var.shared_access_key_enabled
    }
  }
  storage_use_azuread = !var.shared_access_key_enabled
  subscription_id     = var.subscription_id
}

# The region comes from the resource group, not from a variable.
#
# A `location` variable with its own default can disagree with the group:
# the store is then built in one region inside a group in another, and the
# cluster's VM size may not be offered to the subscription in the default
# region at all.
#
# A region that disagrees with the group is not only a failed apply. Findings
# are written on the verdict path, which has a 5,000 ms timeout end to end,
# and a cross-region write spends part of that budget for nothing.
#
# Deriving it means the question has one answer and the portal shows it.
data "azurerm_resource_group" "target" {
  name = var.resource_group_name
}

locals {
  location = data.azurerm_resource_group.target.location

  # THESE TWO STRINGS ARE A CONTRACT WITH THE CHART.
  #
  # Each is half of a federated subject -- system:serviceaccount:<ns>:<name>
  # -- and it is matched exactly. A name that does not match produces pods
  # that authenticate as nothing, and the only place that says so is the
  # pod's own log: the dashboard renders, empty, and the collector accepts
  # exports and fails to store them.
  #
  # So they are set here and passed to `helm install` from the outputs
  # below, rather than left to the chart's default naming on one side and
  # guessed on the other. tests/test_helm_chart.py asserts the chart renders
  # these same names.
  writer_service_account = "forgd-verdict-writer"
  reader_service_account = "forgd-verdict-reader"
}

module "store" {
  source = "../../modules/store-azure"

  resource_group_name  = var.resource_group_name
  location             = local.location
  storage_account_name = var.storage_account_name
  identity_name        = "mi-forgd-verdict-aks"
  reader_identity_name = "mi-forgd-dashboard-aks"
  tags                 = var.tags

  shared_access_key_enabled       = var.shared_access_key_enabled
  container_delete_retention_days = var.container_delete_retention_days
}

# Adapter 5's Azure Monitor destination. OFF unless `enable_azure_monitor`
# is set: it creates a Log Analytics workspace, which bills per GB ingested
# and retained, and a fork should choose that rather than inherit it.
#
# Nothing else references it, so turning it off destroys only these three
# resources and leaves the findings store alone.
module "monitor" {
  source = "../../modules/monitor-azure"
  count  = var.enable_azure_monitor ? 1 : 0

  resource_group_name = var.resource_group_name
  location            = local.location
  writer_principal_id = module.store.identity_principal_id
  retention_days      = var.monitor_retention_days
  daily_quota_gb      = var.monitor_daily_quota_gb
  tags                = var.tags
}

module "cluster" {
  source = "../../modules/cluster-aks"

  resource_group_name = var.resource_group_name
  location            = local.location
  cluster_name        = var.cluster_name
  sku_tier            = var.sku_tier
  registry_id         = var.registry_id
  namespace           = var.namespace
  tags                = var.tags

  writer_identity_id = module.store.identity_id
  reader_identity_id = module.store.reader_identity_id

  writer_service_account = local.writer_service_account
  reader_service_account = local.reader_service_account

  private_cluster_enabled              = var.private_cluster_enabled
  api_server_authorized_ip_ranges      = var.api_server_authorized_ip_ranges
  allow_unrestricted_public_api_server = var.allow_unrestricted_public_api_server
  local_account_disabled               = var.local_account_disabled
  entra_admin_group_object_ids         = var.entra_admin_group_object_ids
}
