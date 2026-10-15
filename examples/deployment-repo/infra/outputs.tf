output "store_url" {
  value = module.store.store_url
}

output "writer_client_id" {
  value       = module.store.identity_client_id
  description = "serviceAccounts.writer.clientId."
}

output "reader_client_id" {
  value       = module.store.reader_identity_client_id
  description = "serviceAccounts.reader.clientId. The dashboard's, and not the writer's."
}

output "kubeconfig_command" {
  value = module.cluster.kubeconfig_command
}

output "ingress_class_name" {
  value = module.cluster.ingress_class_name
}


output "service_account_names" {
  value = {
    writer = local.writer_service_account
    reader = local.reader_service_account
  }
  description = "Half of each federated subject. Must equal what the chart renders."
}

output "azure_monitor_sink_endpoint" {
  description = "Paste into `sinks[].endpoint`. Empty when enable_azure_monitor is false."
  value       = try(module.monitor[0].ingestion_endpoint, "")
}
