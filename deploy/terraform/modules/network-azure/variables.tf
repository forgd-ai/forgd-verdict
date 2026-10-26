variable "resource_group_name" { type = string }
variable "location" { type = string }

variable "vnet_name" {
  type    = string
  default = "vnet-forgd-verdict"
}

variable "address_space" {
  type        = list(string)
  default     = ["10.240.0.0/16"]
  description = "The VNet's address space. It must not overlap cluster-aks's service_cidr (AKS's default is 10.0.0.0/16) or its overlay pod_cidr (10.244.0.0/16), or AKS refuses the cluster."
  validation {
    condition     = length(var.address_space) > 0 && alltrue([for c in var.address_space : can(cidrhost(c, 0))])
    error_message = "address_space must be one or more CIDR blocks."
  }
}

variable "node_subnet_name" {
  type    = string
  default = "snet-nodes"
}

variable "node_subnet_prefix" {
  type        = string
  default     = "10.240.0.0/22"
  description = "The node subnet, inside address_space. Overlay pods do not use it, so a /22 holds about 1,000 nodes."
  validation {
    condition     = can(cidrhost(var.node_subnet_prefix, 0))
    error_message = "node_subnet_prefix must be a CIDR block."
  }
}

variable "agc_subnet_name" {
  type    = string
  default = "snet-agc"
}

variable "agc_subnet_prefix" {
  type        = string
  default     = "10.240.8.0/24"
  description = "Application Gateway for Containers' subnet, inside address_space. Exactly a /24: AGC with Azure CNI Overlay takes nothing else."
  validation {
    condition     = can(cidrhost(var.agc_subnet_prefix, 0)) && endswith(var.agc_subnet_prefix, "/24")
    error_message = "agc_subnet_prefix must be a /24. With Azure CNI Overlay, AGC's subnet is exactly a /24, and Azure refuses the association otherwise, after a plan that looks fine."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
