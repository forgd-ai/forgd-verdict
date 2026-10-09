output "verdict_url" {
  value       = "https://${azurerm_container_app.verdict.ingress[0].fqdn}"
  description = "The Inference hooks endpoint is this + /hook."
}

output "collector_url" {
  value       = "https://${azurerm_container_app.collector.ingress[0].fqdn}"
  description = "The OTLP endpoint. Anthropic appends /v1/logs and /v1/traces."
}

output "dashboard_url" {
  value = "https://${azurerm_container_app.dashboard.ingress[0].fqdn}"
}

output "verify_command" {
  description = "Applying proves the resources exist, not that they refuse an unsigned request."
  value = join(" ", [
    "scripts/verify_deployment.sh",
    "https://${azurerm_container_app.verdict.ingress[0].fqdn}",
    "https://${azurerm_container_app.collector.ingress[0].fqdn}",
    "https://${azurerm_container_app.dashboard.ingress[0].fqdn}",
  ])
}

output "connector_url" {
  value       = var.connector_enabled ? local.connector_resource : null
  description = "The findings connector's MCP URL, the one entered in Claude and set as FORGD_CONNECTOR_URL for scripts/deploy_azure.sh: connector_resource, or the derived default. Null when connector_enabled is false."
}

output "connector_app_name" {
  value       = var.connector_enabled ? azurerm_container_app.connector[0].name : null
  description = "Set as AZURE_CONNECTOR_APP for scripts/deploy_azure.sh. Null when connector_enabled is false."
}
