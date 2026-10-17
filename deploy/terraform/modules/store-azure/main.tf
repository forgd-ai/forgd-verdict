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
# A findings export is still sensitive: it is hashed, and the deployment salts
# those hashes precisely because a bare digest of a low-entropy value is reversible.

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
  public_network_access_enabled = var.public_network_access

  blob_properties {
    # The store is append-only by design and never rewrites an object, so
    # versioning buys nothing against our own writes. It buys a recovery
    # path against an operator deleting a partition by hand.
    versioning_enabled = true
    delete_retention_policy {
      days = var.soft_delete_days
    }
    # Keeps a deleted container, and every blob in it, restorable for this
    # many days. Omitted when container_delete_retention_days is 0 or null.
    dynamic "container_delete_retention_policy" {
      for_each = coalesce(var.container_delete_retention_days, 0) > 0 ? [var.container_delete_retention_days] : []
      content {
        days = container_delete_retention_policy.value
      }
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

# The writer's role on the DATA plane, scoped to this one container. Not
# "Storage Account Contributor", which is control-plane and would let a
# compromised app rotate keys or open public access.
#
# While control_enabled is false: Storage Blob Data Contributor. While it is
# true: the custom role `writer`, blob read, write and add and no
# control-plane action, so no container delete or recreate, with a
# condition that keeps every blob mutation off the runtime overrides object
# and its audit records, which only the control identity writes.
#
# Turning control_enabled on or off changes the role, which replaces the
# assignment. create_before_destroy creates the new one before the old one
# goes, so the writer is never without a role; the two hold different roles,
# so Azure accepts both at once. A change to `condition` alone forces a
# replacement with the same scope, principal and role, which Azure refuses
# (RoleAssignmentExists) while the old assignment exists, so such an apply
# fails and leaves it in place.
resource "azurerm_role_assignment" "app_writes_findings" {
  scope                = azurerm_storage_container.findings.id
  role_definition_name = var.control_enabled ? null : "Storage Blob Data Contributor"
  role_definition_id   = one(azurerm_role_definition.writer[*].role_definition_resource_id)
  principal_id         = azurerm_user_assigned_identity.app.principal_id
  condition_version    = var.control_enabled ? "2.0" : null
  condition            = var.control_enabled ? local.writer_write_condition : null

  lifecycle {
    create_before_destroy = true
  }
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

# Storage Blob Data Reader while control_enabled is false; the custom role
# `reader`, blob read only, while it is true. The role change replaces the
# assignment as the writer's does. create_before_destroy is safe here
# because this assignment sets no condition, description or name, so every
# replacement changes its scope, principal or role.
resource "azurerm_role_assignment" "dashboard_reads_findings" {
  scope                = azurerm_storage_container.findings.id
  role_definition_name = var.control_enabled ? null : "Storage Blob Data Reader"
  role_definition_id   = one(azurerm_role_definition.reader[*].role_definition_resource_id)
  principal_id         = azurerm_user_assigned_identity.reader.principal_id

  lifecycle {
    create_before_destroy = true
  }
}

# The dashboard's identity while admins are enabled (docs/OVERRIDES.md): a
# role holding blob read and the two blob write data actions, whose
# assignment is conditioned on the runtime overrides object and the audit
# prefix.
locals {
  # The store-azure URL carries no key prefix, so every store key starts at
  # the container. A blob path excludes the container name and any leading
  # slash.
  control_overrides_path = "state/runtime-overrides.json"
  control_audit_prefix   = "audit/runtime-overrides/"
  blob_read_action       = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
  control_write_actions = [
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
  ]

  # Every data action that changes or removes a blob and can be conditioned
  # on its path.
  writer_mutating_actions = [
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action",
  ]

  # A read passes the first clause; a mutation passes only off both paths.
  writer_write_condition = <<-EOT
    (
     (
      ${join("\n  AND\n  ", [for a in local.writer_mutating_actions : "!(ActionMatches{'${a}'})"])}
     )
     OR
     (
      @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringNotEquals '${local.control_overrides_path}'
      AND
      @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringNotStartsWith '${local.control_audit_prefix}'
     )
    )
  EOT

  # Each action passes its own clause: `write`, which also replaces, only on
  # the overrides object; `add/action`, which only creates, on the object and
  # under the audit prefix. A request for any other action passes both.
  control_write_condition = <<-EOT
    (
     (
      !(ActionMatches{'${local.control_write_actions[0]}'})
     )
     OR
     (
      @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringEquals '${local.control_overrides_path}'
     )
    )
    AND
    (
     (
      !(ActionMatches{'${local.control_write_actions[1]}'})
     )
     OR
     (
      @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringEquals '${local.control_overrides_path}'
      OR
      @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringStartsWith '${local.control_audit_prefix}'
     )
    )
  EOT
}

resource "azurerm_user_assigned_identity" "control" {
  count               = var.control_enabled ? 1 : 0
  name                = var.control_identity_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

data "azurerm_resource_group" "findings" {
  count = var.control_enabled ? 1 : 0
  name  = var.resource_group_name
}

# The custom roles, while control_enabled. Custom roles are defined and
# assignable at a resource group, not at a container, so each assignment is
# what scopes its role to the findings container. None holds a control-plane action, a blob delete or a move:
# the store reads, lists and puts blobs, and nothing else.
resource "azurerm_role_definition" "writer" {
  count             = var.control_enabled ? 1 : 0
  name              = coalesce(var.writer_role_name, "forgd-verdict findings writer (${var.storage_account_name})")
  scope             = data.azurerm_resource_group.findings[0].id
  description       = "Blob read, write and add only: no container action, no delete, no move."
  assignable_scopes = [data.azurerm_resource_group.findings[0].id]

  permissions {
    actions      = []
    data_actions = concat([local.blob_read_action], local.control_write_actions)
  }
}

resource "azurerm_role_definition" "reader" {
  count             = var.control_enabled ? 1 : 0
  name              = coalesce(var.reader_role_name, "forgd-verdict findings reader (${var.storage_account_name})")
  scope             = data.azurerm_resource_group.findings[0].id
  description       = "Blob read only: no container action."
  assignable_scopes = [data.azurerm_resource_group.findings[0].id]

  permissions {
    actions      = []
    data_actions = [local.blob_read_action]
  }
}

resource "azurerm_role_definition" "control_writes" {
  count             = var.control_enabled ? 1 : 0
  name              = coalesce(var.control_role_name, "forgd-verdict runtime overrides writer (${var.storage_account_name})")
  scope             = data.azurerm_resource_group.findings[0].id
  description       = "Blob read, write and add only: no container action, no delete, no move. Assigned with a condition limiting write to the runtime overrides object, and add to it and its audit records."
  assignable_scopes = [data.azurerm_resource_group.findings[0].id]

  permissions {
    actions      = []
    data_actions = concat([local.blob_read_action], local.control_write_actions)
  }
}

resource "azurerm_role_assignment" "control_writes_overrides" {
  count              = var.control_enabled ? 1 : 0
  scope              = azurerm_storage_container.findings.id
  role_definition_id = azurerm_role_definition.control_writes[0].role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.control[0].principal_id
  condition_version  = "2.0"
  condition          = local.control_write_condition
  description        = "The runtime overrides object and its audit records."

  lifecycle {
    precondition {
      condition     = !contains([var.identity_name, var.reader_identity_name], var.control_identity_name)
      error_message = "control_identity_name must differ from identity_name and reader_identity_name. The reader identity is shared with the connector, and the writer's can rewrite the findings."
    }
  }
}

# The control identity reads the role assignments and role definitions that
# apply to the storage account, to verify the writers' lockout.
resource "azurerm_role_definition" "control_reads_assignments" {
  count             = var.control_enabled ? 1 : 0
  name              = coalesce(var.control_evidence_role_name, "forgd-verdict writer lockout reader (${var.storage_account_name})")
  scope             = data.azurerm_resource_group.findings[0].id
  description       = "Role assignment and role definition read only. Assigned on the findings storage account."
  assignable_scopes = [data.azurerm_resource_group.findings[0].id]

  permissions {
    actions = [
      "Microsoft.Authorization/roleAssignments/read",
      "Microsoft.Authorization/roleDefinitions/read",
    ]
    data_actions = []
  }
}

resource "azurerm_role_assignment" "control_reads_assignments" {
  count              = var.control_enabled ? 1 : 0
  scope              = azurerm_storage_account.findings.id
  role_definition_id = azurerm_role_definition.control_reads_assignments[0].role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.control[0].principal_id
  description        = "The writers' role assignments on this storage account, for the lockout verification."
}

# A CanNotDelete lock on the storage account while control_enabled. A lock
# covers control-plane operations only: it refuses deleting the account
# through Resource Manager, and deleting a role assignment scoped under it,
# and does not stop a blob write or delete on the data plane. It depends on
# every role assignment so that Terraform creates it after them and removes
# it before them.
resource "azurerm_management_lock" "findings" {
  count      = var.control_enabled && var.storage_account_delete_lock ? 1 : 0
  name       = "forgd-verdict-findings-cannot-delete"
  scope      = azurerm_storage_account.findings.id
  lock_level = "CanNotDelete"
  notes      = "forgd-verdict findings store. Remove this lock before destroying the store, or before an apply that removes or replaces one of its role assignments."

  depends_on = [
    azurerm_role_assignment.app_writes_findings,
    azurerm_role_assignment.dashboard_reads_findings,
    azurerm_role_assignment.control_writes_overrides,
    azurerm_role_assignment.control_reads_assignments,
  ]
}
