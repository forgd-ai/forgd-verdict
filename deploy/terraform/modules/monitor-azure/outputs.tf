output "ingestion_endpoint" {
  description = <<-TXT
    The whole URI for `sinks[].endpoint`. The host on its own is not
    enough -- the sink refuses it at startup, because that is what the
    portal shows and it 404s at send time otherwise.
  TXT
  value = format(
    "%s/dataCollectionRules/%s/streams/Custom-%s_CL",
    azurerm_monitor_data_collection_endpoint.verdict.logs_ingestion_endpoint,
    azurerm_monitor_data_collection_rule.verdict.immutable_id,
    var.table_name,
  )
}

output "workspace_id" {
  value = azurerm_log_analytics_workspace.verdict.id
}

output "rule_id" {
  value = azurerm_monitor_data_collection_rule.verdict.id
}
