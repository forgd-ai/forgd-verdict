# Who may reach the cluster. With local_account_disabled (the default) every
# caller signs in with Entra ID and is authorized by an Azure role on the
# cluster, which is what the roles below are.
#
# The deploy workflow's identity gets what a roll needs and no more: a
# kubeconfig, write access to the chart's namespace, and the right to import
# the release's images into the registry. It holds nothing cluster-wide.

variable "cd_identity_name" {
  type        = string
  description = "The user-assigned identity .github/workflows/deploy.yml signs in as, through a federated credential naming the `deploy` environment."
}

variable "cd_identity_resource_group_name" {
  type        = string
  description = "The resource group holding the deploy workflow's identity."
}

variable "cluster_admin_principal_ids" {
  type        = list(string)
  default     = []
  description = "Entra object ids given Azure Kubernetes Service RBAC Cluster Admin on the cluster: the people who run kubectl and helm by hand."
}

locals {
  # The module does not output the cluster's id; built from its name so the
  # grants still wait for the cluster.
  cluster_id = "/subscriptions/${var.subscription_id}/resourceGroups/${var.resource_group_name}/providers/Microsoft.ContainerService/managedClusters/${module.cluster.cluster_name}"
}

data "azurerm_user_assigned_identity" "cd" {
  name                = var.cd_identity_name
  resource_group_name = var.cd_identity_resource_group_name
}

resource "azurerm_role_assignment" "cd_cluster_user" {
  scope                = local.cluster_id
  role_definition_name = "Azure Kubernetes Service Cluster User Role"
  principal_id         = data.azurerm_user_assigned_identity.cd.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "cd_namespace_writer" {
  scope                = "${local.cluster_id}/namespaces/${var.namespace}"
  role_definition_name = "Azure Kubernetes Service RBAC Writer"
  principal_id         = data.azurerm_user_assigned_identity.cd.principal_id
  principal_type       = "ServicePrincipal"
}

# `az acr import` needs importImage, which AcrPush does not include. Without
# registry_id the workflow pulls from ghcr.io and nothing is imported.
resource "azurerm_role_definition" "registry_importer" {
  count       = var.registry_id == "" ? 0 : 1
  name        = "forgd-verdict registry importer"
  scope       = var.registry_id
  description = "Import images into this registry from another registry."
  permissions {
    actions = [
      "Microsoft.ContainerRegistry/registries/read",
      "Microsoft.ContainerRegistry/registries/importImage/action",
    ]
  }
  assignable_scopes = [var.registry_id]
}

resource "azurerm_role_assignment" "cd_registry_importer" {
  count              = var.registry_id == "" ? 0 : 1
  scope              = var.registry_id
  role_definition_id = azurerm_role_definition.registry_importer[0].role_definition_resource_id
  principal_id       = data.azurerm_user_assigned_identity.cd.principal_id
  principal_type     = "ServicePrincipal"
}

# deploy.yml reads each imported image's digest back to compare it with
# GHCR's, which is a data-plane read the importer role does not cover.
resource "azurerm_role_assignment" "cd_registry_reader" {
  count                = var.registry_id == "" ? 0 : 1
  scope                = var.registry_id
  role_definition_name = "AcrPull"
  principal_id         = data.azurerm_user_assigned_identity.cd.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "cluster_admin" {
  for_each             = toset(var.cluster_admin_principal_ids)
  scope                = local.cluster_id
  role_definition_name = "Azure Kubernetes Service RBAC Cluster Admin"
  principal_id         = each.value
}
