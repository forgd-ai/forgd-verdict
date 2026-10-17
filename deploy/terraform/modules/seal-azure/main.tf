# The key that seals matched values (privacy.sealing, docs/PRIVACY.md).
#
# An RSA key in a Key Vault of its own, for decryption only. Every
# forgd-verdict service seals with the key's public half, which is an
# output and goes into the policy; none of them is granted anything here.
# The module grants Decrypt to `decrypt_principal_ids`, the people who act
# on findings, and nothing else.
#
# The vault uses access policies rather than Azure RBAC because a policy
# names key operations one by one: the identity that runs Terraform needs
# to create and read the key, and every built-in RBAC role that can create
# a key can also decrypt with it.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
  }
}

data "azurerm_client_config" "current" {}

locals {
  deployer = coalesce(var.deployer_object_id, data.azurerm_client_config.current.object_id)
  # Key operations the deployer holds: enough to create, read, update and
  # delete the key, and no use of it.
  deployer_key_permissions = ["Create", "Delete", "Get", "GetRotationPolicy", "Recover", "Update"]
  # What an operator in decrypt_principal_ids holds.
  decrypt_key_permissions = ["Decrypt", "Get"]
}

resource "azurerm_key_vault" "seal" {
  name                       = var.key_vault_name
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = var.sku_name
  rbac_authorization_enabled = false
  # A deleted key stays recoverable for soft_delete_retention_days and
  # cannot be purged before then. Losing the key loses every value sealed
  # to it.
  purge_protection_enabled   = true
  soft_delete_retention_days = var.soft_delete_retention_days
  tags                       = var.tags

  lifecycle {
    precondition {
      condition     = length(setintersection(var.decrypt_principal_ids, var.service_principal_ids)) == 0
      error_message = "A principal in service_principal_ids is also in decrypt_principal_ids. No forgd-verdict service may decrypt sealed values: each needs only the public key."
    }
    precondition {
      condition     = !contains(var.service_principal_ids, local.deployer)
      error_message = "The deployer is a forgd-verdict service identity. Run Terraform as another identity: the deployer can manage the key, and a service must not."
    }
  }
}

resource "azurerm_key_vault_access_policy" "deployer" {
  key_vault_id    = azurerm_key_vault.seal.id
  tenant_id       = data.azurerm_client_config.current.tenant_id
  object_id       = local.deployer
  key_permissions = local.deployer_key_permissions
}

resource "azurerm_key_vault_access_policy" "decrypt" {
  for_each        = toset(var.decrypt_principal_ids)
  key_vault_id    = azurerm_key_vault.seal.id
  tenant_id       = data.azurerm_client_config.current.tenant_id
  object_id       = each.value
  key_permissions = local.decrypt_key_permissions
}

resource "azurerm_key_vault_key" "seal" {
  name         = var.key_name
  key_vault_id = azurerm_key_vault.seal.id
  key_type     = "RSA"
  key_size     = var.key_size
  # Sealing encrypts with the public half outside the vault, so decrypt is
  # the only operation the key permits.
  key_opts = ["decrypt"]
  tags     = var.tags

  depends_on = [azurerm_key_vault_access_policy.deployer]
}
