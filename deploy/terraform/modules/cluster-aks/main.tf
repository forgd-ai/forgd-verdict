# An AKS cluster for the Helm chart, and the federation that lets its pods
# authenticate as the store's identities.
#
# This module deliberately does NOT deploy the chart. `terraform apply` for
# infrastructure and `helm upgrade` for the release are different cadences:
# routing a release through an apply buys a state lock and a plan to change
# one image tag, which is the same reason the Container Apps module keeps
# `ignore_changes` on its images.
#
# It also does not create the store. Findings outlive clusters -- see
# ../store-azure, which every deployment path uses unchanged.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
  }
}

locals {
  # cidrhost masks the address it is given to the prefix, so the two agree
  # exactly when dns_service_ip is inside service_cidr.
  dns_in_service_cidr = try(
    cidrhost("${var.dns_service_ip}/${split("/", var.service_cidr)[1]}", 0) == cidrhost(var.service_cidr, 0)
    && var.dns_service_ip != cidrhost(var.service_cidr, 0),
    false,
  )

  # "none" is app_routing_enabled = false with ingress unset: an ingress
  # controller the deployment supplies itself.
  ingress = var.ingress != null ? var.ingress : (var.app_routing_enabled == false ? "none" : "app_routing")
  agc     = local.ingress == "agc"

  # Whether the nodes join vnet_subnet_id, which decides the control
  # plane's identity. A subnet created in the same apply has an id that is
  # not known at plan, and a count that read it would fail the plan with
  # "Invalid count argument". ingress = "agc" always has a subnet, so it
  # answers without reading the id.
  own_vnet = local.agc ? true : var.vnet_subnet_id != null

  # "1.35" or "1.35.7" -> [1, 35]; kubernetes_version's validation admits
  # only that shape.
  kubernetes_minor = var.kubernetes_version == null ? null : [for n in slice(split(".", var.kubernetes_version), 0, 2) : tonumber(n)]
}

# With vnet_subnet_id, the control plane runs as this identity, which needs
# Network Contributor on the subnet to join the nodes and the API server's
# private endpoint to it. AKS checks the permission when it creates the
# cluster, so the assignment comes first. A system-assigned identity cannot
# be granted anything before the cluster exists.
resource "azurerm_user_assigned_identity" "control_plane" {
  count               = local.own_vnet ? 1 : 0
  name                = "${var.cluster_name}-control-plane"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_role_assignment" "control_plane_subnet" {
  count                = local.own_vnet ? 1 : 0
  scope                = var.vnet_subnet_id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_user_assigned_identity.control_plane[0].principal_id
  # The identity is new, so the assignment can race the directory's view of it.
  skip_service_principal_aad_check = true
}

resource "azurerm_kubernetes_cluster" "this" {
  name                = var.cluster_name
  resource_group_name = var.resource_group_name
  location            = var.location
  dns_prefix          = var.cluster_name
  sku_tier            = var.sku_tier
  kubernetes_version  = var.kubernetes_version
  node_resource_group = var.node_resource_group
  tags                = var.tags

  # Both are required and neither is the default.
  #
  # Without the OIDC issuer there is no token for Entra to trust, and
  # without the workload identity webhook the projected token is never
  # mounted. A pod then falls back to whatever credential the node offers --
  # which on AKS is the kubelet identity, and that has AcrPull and nothing
  # on the store. The failure surfaces as a dashboard with no findings
  # rather than as an authentication error.
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  depends_on = [azurerm_role_assignment.control_plane_subnet]

  private_cluster_enabled = var.private_cluster_enabled
  local_account_disabled  = var.local_account_disabled

  dynamic "api_server_access_profile" {
    for_each = toset(length(var.api_server_authorized_ip_ranges) > 0 ? ["ranges"] : [])
    content {
      authorized_ip_ranges = var.api_server_authorized_ip_ranges
    }
  }

  # AKS refuses to disable local accounts without Entra integration.
  dynamic "azure_active_directory_role_based_access_control" {
    for_each = toset(var.local_account_disabled ? ["entra"] : [])
    content {
      azure_rbac_enabled     = true
      admin_group_object_ids = var.entra_admin_group_object_ids
    }
  }

  # The control plane's own identity. Separate from the kubelet's, and
  # separate again from the two the workloads federate to. Changing its type
  # replaces the cluster.
  identity {
    type         = local.own_vnet ? "UserAssigned" : "SystemAssigned"
    identity_ids = local.own_vnet ? [azurerm_user_assigned_identity.control_plane[0].id] : null
  }

  # Manual: the default node pool below and no node auto-provisioning,
  # which is what 4.x clusters ran with. azurerm 5 requires the block.
  # default_node_pools is azurerm 5's default, written out: AKS reads it only
  # with mode = "Auto", and left unset the provider sends its own default.
  node_provisioning_profile {
    mode               = "Manual"
    default_node_pools = "Auto"
  }

  default_node_pool {
    name    = "system"
    vm_size = var.node_vm_size
    # Sized against what the chart actually requests, because the failure
    # mode is a Pending pod rather than an error:
    #
    #   verdict    1.00 vCPU / 2 Gi
    #   collector  1.00 vCPU / 2 Gi
    #   dashboard  0.25 vCPU / 0.5 Gi
    #   ingest     1.00 vCPU / 3 Gi   (every six hours, alongside the rest)
    #             ------------------
    #              3.25 vCPU / 7.5 Gi, plus the system add-ons and whatever
    #                                  the ingress controller asks for.
    #
    # Two 4-vCPU nodes give ~7 allocatable, so the six-hourly ingest pass
    # has somewhere to land without evicting a service Anthropic is calling.
    #
    # It is also 8 vCPU of QUOTA, and an upgrade transiently wants a ninth
    # through to twelfth via max_surge. A subscription at the default limit
    # of 10 regional vCPU cannot hold this alongside anything else -- see
    # node_vm_size for how that error reads. Check `az vm list-usage`
    # before changing either number.
    node_count           = var.node_count
    vnet_subnet_id       = var.vnet_subnet_id
    auto_scaling_enabled = false
    os_disk_size_gb      = 64
    upgrade_settings {
      max_surge = "1"
    }
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "cilium"
    # Cilium needs overlay mode AND the Cilium data plane together; the
    # combination is validated at apply, not at plan. `network_data_plane`,
    # not the `ebpf_data_plane` of azurerm 3.x -- the old name is accepted by
    # neither, so a copied 3.x example fails at init.
    network_plugin_mode = "overlay"
    network_data_plane  = "cilium"
    load_balancer_sku   = "standard"
    # Null leaves AKS's defaults: pods 10.244.0.0/16, services 10.0.0.0/16.
    # Neither may overlap the VNet vnet_subnet_id is in, or anything it
    # routes to.
    pod_cidr       = var.pod_cidr
    service_cidr   = var.service_cidr
    dns_service_ip = var.dns_service_ip
  }

  # The managed nginx add-on, rather than an ingress-nginx Helm release
  # managed by Terraform. Terraform holding a Helm release means the cluster
  # must be reachable from wherever `plan` runs, and a plan that cannot
  # reach the API server fails instead of reporting drift.
  #
  # It is nginx underneath, so the chart's nginx.ingress.kubernetes.io/*
  # annotations apply. The ingress class is webapprouting.kubernetes.azure.com --
  # pass the `ingress_class_name` output to the chart rather than assuming
  # "nginx".
  # toset([...]) rather than [1]: Terraform 1.9 rejects a bare numeric list
  # here and 1.5 accepts it, so a local validate on an older binary does not
  # catch it. app-aca uses the same pattern for the same reason.
  dynamic "web_app_routing" {
    for_each = toset(local.ingress == "app_routing" ? ["enabled"] : [])
    content {
      # Empty: TLS is expected to terminate with cert-manager against a
      # hostname managed outside this module. A zone id here would make the
      # add-on own DNS records too.
      dns_zone_ids = []
    }
  }

  lifecycle {
    precondition {
      condition     = var.private_cluster_enabled || length(var.api_server_authorized_ip_ranges) > 0 || var.allow_unrestricted_public_api_server
      error_message = "The API server is public and api_server_authorized_ip_ranges is empty, so it admits every address. Set private_cluster_enabled, list the ranges that need the API, or set allow_unrestricted_public_api_server to accept that."
    }
    precondition {
      condition     = (var.service_cidr == null) == (var.dns_service_ip == null)
      error_message = "service_cidr and dns_service_ip are set together: dns_service_ip is an address inside service_cidr."
    }
    precondition {
      condition     = var.service_cidr == null || var.dns_service_ip == null || local.dns_in_service_cidr
      error_message = "dns_service_ip must be an address inside service_cidr other than its first."
    }
    precondition {
      condition     = var.ingress == null || var.app_routing_enabled == null
      error_message = "Set ingress, not app_routing_enabled as well: app_routing_enabled is the older form of the same choice, and the two can disagree."
    }
    precondition {
      condition     = !local.agc || (var.vnet_subnet_id != null && var.agc_subnet_id != null)
      error_message = "ingress = \"agc\" needs vnet_subnet_id and agc_subnet_id: Application Gateway for Containers needs its own /24 in the nodes' VNet, and a VNet AKS manages cannot take one. network-azure makes both."
    }
    precondition {
      condition     = local.agc || var.agc_subnet_id == null
      error_message = "agc_subnet_id is only for ingress = \"agc\"."
    }
    precondition {
      condition     = !local.agc || lower(coalesce(var.agc_subnet_id, "x")) != lower(coalesce(var.vnet_subnet_id, "y"))
      error_message = "agc_subnet_id is the nodes' subnet. AGC needs a /24 of its own, delegated to Microsoft.ServiceNetworking/trafficControllers, holding nothing else."
    }
    precondition {
      condition     = !local.agc || var.kubernetes_version == null || try(local.kubernetes_minor[0] > 1 || (local.kubernetes_minor[0] == 1 && local.kubernetes_minor[1] >= 32), false)
      error_message = "ingress = \"agc\" needs kubernetes_version 1.32 or later, the oldest the ALB Controller supports, or null for AKS's default."
    }
    precondition {
      condition     = !var.private_cluster_enabled || length(var.api_server_authorized_ip_ranges) == 0
      error_message = "api_server_authorized_ip_ranges applies only to a public API server; AKS does not take it on a private cluster. Set private_cluster_enabled = false to use the ranges, or remove them."
    }
    ignore_changes = [
      # AKS moves the patch version under an auto-upgrade channel, and a
      # permanent diff is a plan nobody reads -- which defeats the gate on
      # the apply.
      kubernetes_version,
    ]
  }
}

# AcrPull for the KUBELET identity, not the cluster identity.
#
# Without it the apply succeeds and the pods cannot start: an identity
# Terraform created has no rights on a registry Terraform did not create. On
# AKS the puller is the kubelet's identity, and naming the control plane's
# here would produce ImagePullBackOff with a plan that looked clean.
resource "azurerm_role_assignment" "kubelet_pulls_images" {
  count                = var.registry_id == "" ? 0 : 1
  scope                = var.registry_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.this.kubelet_identity[0].object_id
  # The identity is created with the cluster, so the assignment can race the
  # directory's view of it.
  skip_service_principal_aad_check = true
}

# --- workload identity federation ----------------------------------------
#
# Each credential says: a token from THIS cluster's issuer, for THIS
# namespace and service account, may act as this managed identity. The
# subject is an exact string -- a namespace or service account name that
# does not match produces a pod that authenticates as nothing, with the
# rejection visible only in the pod's own logs.
#
# So the names are inputs shared with the chart rather than defaults
# repeated in two places.
resource "azurerm_federated_identity_credential" "writer" {
  name                      = "${var.cluster_name}-writer"
  user_assigned_identity_id = var.writer_identity_id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.namespace}:${var.writer_service_account}"
}

# The dashboard's, and it is a SEPARATE credential on a separate identity.
# Federating the dashboard's service account to the writer identity would
# undo the read-only split without changing anything in the chart.
resource "azurerm_federated_identity_credential" "reader" {
  name                      = "${var.cluster_name}-reader"
  user_assigned_identity_id = var.reader_identity_id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.namespace}:${var.reader_service_account}"
}

# The findings connector's, on the READER identity like the dashboard's.
resource "azurerm_federated_identity_credential" "connector" {
  count                     = var.connector_enabled ? 1 : 0
  name                      = "${var.cluster_name}-connector"
  user_assigned_identity_id = var.reader_identity_id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.namespace}:${var.connector_service_account}"

  lifecycle {
    precondition {
      condition     = !contains([var.writer_service_account, var.reader_service_account], var.connector_service_account)
      error_message = "connector_service_account must be a service account of its own, not the writer's or the dashboard's."
    }
  }
}

# The dashboard's service account with admins enabled, on store-azure's
# control identity.
resource "azurerm_federated_identity_credential" "control" {
  count                     = var.control_enabled ? 1 : 0
  name                      = "${var.cluster_name}-control"
  user_assigned_identity_id = var.control_identity_id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.namespace}:${var.control_service_account}"

  lifecycle {
    precondition {
      condition     = var.control_identity_id != "" && !contains([var.writer_identity_id, var.reader_identity_id], var.control_identity_id)
      error_message = "control_enabled needs control_identity_id, store-azure's control_identity_id, and it must differ from writer_identity_id and reader_identity_id. The reader identity is shared with the connector, and the writer's can rewrite the findings."
    }
    precondition {
      condition     = !contains(concat([var.writer_service_account, var.reader_service_account], var.connector_enabled ? [var.connector_service_account] : []), var.control_service_account)
      error_message = "control_service_account must be a service account of its own, not the writer's, the reader's or the connector's."
    }
  }
}
