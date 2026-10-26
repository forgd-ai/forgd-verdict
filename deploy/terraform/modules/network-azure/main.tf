# The network an AKS cluster needs to run Application Gateway for
# Containers (docs/design/agc.md).
#
# A VNet with two subnets: one for the nodes, passed to cluster-aks as
# vnet_subnet_id, and a /24 delegated to
# Microsoft.ServiceNetworking/trafficControllers for AGC. With Azure CNI
# Overlay, AGC's subnet must be exactly a /24 in the nodes' VNet; a peered
# VNet does not work. Pods take their addresses from the overlay's
# pod_cidr, not from this VNet, so the node subnet is sized for nodes only.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
  }
}

resource "azurerm_virtual_network" "this" {
  name                = var.vnet_name
  resource_group_name = var.resource_group_name
  location            = var.location
  address_space       = var.address_space
  tags                = var.tags
}

resource "azurerm_subnet" "nodes" {
  name                 = var.node_subnet_name
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.node_subnet_prefix]
}

resource "azurerm_subnet" "agc" {
  name                 = var.agc_subnet_name
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.agc_subnet_prefix]

  delegation {
    name = "agc"
    service_delegation {
      name    = "Microsoft.ServiceNetworking/trafficControllers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}
