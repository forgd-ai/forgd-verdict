output "store_url" {
  value       = "https://${azurerm_storage_account.findings.name}.blob.core.windows.net/${azurerm_storage_container.findings.name}"
  description = "FORGD_VERDICT_STORE. `open_store` dispatches on this prefix."
}

output "identity_id" {
  value = azurerm_user_assigned_identity.app.id
}

output "identity_client_id" {
  value       = azurerm_user_assigned_identity.app.client_id
  description = "AZURE_CLIENT_ID, so ManagedIdentityCredential picks this identity rather than guessing."
}

output "identity_principal_id" {
  value = azurerm_user_assigned_identity.app.principal_id
}

output "reader_identity_id" {
  value       = azurerm_user_assigned_identity.reader.id
  description = "For the dashboard. Storage Blob Data READER, never Contributor."
}

output "reader_identity_client_id" {
  value = azurerm_user_assigned_identity.reader.client_id
}

output "reader_identity_principal_id" {
  value = azurerm_user_assigned_identity.reader.principal_id
}
