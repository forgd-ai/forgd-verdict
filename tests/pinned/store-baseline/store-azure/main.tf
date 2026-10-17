# The findings store, and the identity allowed to write to it.
#
# Every deployment path needs this module -- Container Apps, ECS, Cloud Run,
# and a Kubernetes cluster that only wants `helm install`. A cluster still
# needs somewhere to put findings and an identity permitted to write there.
# Factoring it out is what stops each target reimplementing bucket-plus-IAM.
#
# PRIVACY: what lands here is findings -- detector, locator, and a one-way
# digest -- never prompt content. The container is private and stays private;
# `allow_nested_items_to_be_public` is false and there is no anonymous access.
# A findings export is still sensitive: it is hashed, and those hashes are
# salted precisely because a bare digest of a low-entropy value is reversible.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
  }
}

resource "azurerm_storage_account" "findings" {
  name                            = var.storage_account_name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = var.replication
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = var.shared_access_key_enabled
  # Findings are read by the dashboard over the public endpoint today. A
  # deployment that can reach the storage account privately should set this
  # false and add a private endpoint; it is left open rather than assumed
  # because closing it without one locks the dashboard out silently.
  public_network_access = var.public_network_access ? "Enabled" : "Disabled"

  blob_properties {
    # The store is append-only by design and never rewrites an object, so
    # versioning buys nothing against our own writes. It buys a recovery
    # path against an operator deleting a partition by hand.
    versioning_enabled = true
    delete_retention_policy {
      days = var.soft_delete_days
    }
  }

  tags = var.tags
}

resource "azurerm_storage_container" "findings" {
  name                  = var.container_name
  storage_account_id    = azurerm_storage_account.findings.id
  container_access_type = "private"
}

# The identity the WRITERS run as: the verdict server, the collector and the
# ingest job. Not the dashboard -- see `reader` below.
resource "azurerm_user_assigned_identity" "app" {
  name                = var.identity_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# Contributor on the DATA plane, scoped to this one container. Not
# "Storage Account Contributor", which is control-plane and would let a
# compromised app rotate keys or open public access.
resource "azurerm_role_assignment" "app_writes_findings" {
  scope                = azurerm_storage_container.findings.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

# The dashboard's identity, and it only READS.
#
# `blob.py` and CREDENTIALS.md both specify separate identities, and giving
# the dashboard the writer identity would contradict them: the dashboard is
# the one internet-facing service a human signs into, so a compromise there
# would be able to alter or delete findings -- rewriting the evidence, in a
# tool whose output is evidence.
resource "azurerm_user_assigned_identity" "reader" {
  name                = var.reader_identity_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_role_assignment" "dashboard_reads_findings" {
  scope                = azurerm_storage_container.findings.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.reader.principal_id
}
