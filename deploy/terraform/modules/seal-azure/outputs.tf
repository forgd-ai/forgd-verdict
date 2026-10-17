output "sealing_key" {
  description = "privacy.sealing.key: the KMS, the key by version, and its public half."
  value = {
    kms        = "azure"
    id         = azurerm_key_vault_key.seal.id
    public_key = azurerm_key_vault_key.seal.public_key_pem
  }
}

output "key_vault_id" {
  value = azurerm_key_vault.seal.id
}
