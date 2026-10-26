output "vnet_id" {
  value = azurerm_virtual_network.this.id
}

output "node_subnet_id" {
  description = "cluster-aks's vnet_subnet_id."
  value       = azurerm_subnet.nodes.id
}

output "agc_subnet_id" {
  description = "cluster-aks's agc_subnet_id."
  value       = azurerm_subnet.agc.id
}

output "agc_subnet_cidr" {
  description = "The chart's networkPolicy.agc.subnetCidr: the range AGC reaches pods from."
  value       = var.agc_subnet_prefix
}
