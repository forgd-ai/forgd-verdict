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
  description = "For the dashboard. Storage Blob Data Reader, or with control_enabled the custom reader role; never the writer's."
}

output "reader_identity_client_id" {
  value = azurerm_user_assigned_identity.reader.client_id
}

output "reader_identity_principal_id" {
  value = azurerm_user_assigned_identity.reader.principal_id
}

output "control_identity_id" {
  value       = var.control_enabled ? azurerm_user_assigned_identity.control[0].id : null
  description = "For the dashboard with admins enabled: app-aca's control_identity_id, cluster-aks's control_identity_id. Null unless control_enabled."
}

output "control_identity_client_id" {
  value       = var.control_enabled ? azurerm_user_assigned_identity.control[0].client_id : null
  description = "AZURE_CLIENT_ID for the dashboard with admins enabled: app-aca's control_client_id, the chart's serviceAccounts.control.clientId. Null unless control_enabled."
}

output "control_identity_principal_id" {
  value       = var.control_enabled ? azurerm_user_assigned_identity.control[0].principal_id : null
  description = "Null unless control_enabled."
}

output "overrides_writer_lockout" {
  value       = var.control_enabled
  description = "True only with control_enabled, when this module takes the writers' writes to the runtime overrides object and audit prefix away. app-aca's overrides_writer_lockout; it refuses dashboard_admins_enabled without it."
}

output "overrides_writer_identities" {
  value       = var.control_enabled ? [azurerm_user_assigned_identity.app.principal_id] : []
  description = "The writer principal ids whose lockout the dashboard verifies from their role assignments: app-aca's overrides_writer_identities, or the chart's dashboard.admins.writerIdentities. Empty unless control_enabled."
}

output "storage_account_id" {
  value       = azurerm_storage_account.findings.id
  description = "The storage account's resource id: app-aca's overrides_storage_account_id, or the chart's dashboard.admins.storageAccountId. The lockout verification lists role assignments at this scope."
}
