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

resource "azurerm_kubernetes_cluster" "this" {
  name                = var.cluster_name
  resource_group_name = var.resource_group_name
  location            = var.location
  dns_prefix          = var.cluster_name
  sku_tier            = var.sku_tier
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
  # separate again from the two the workloads federate to.
  identity {
    type = "SystemAssigned"
  }

  # Manual: the default node pool below and no node auto-provisioning,
  # which is what 4.x clusters ran with. azurerm 5 requires the block.
  node_provisioning_profile {
    mode = "Manual"
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
  }

  # The managed nginx add-on, rather than an ingress-nginx Helm release
  # managed by Terraform. Terraform holding a Helm release means the cluster
  # must be reachable from wherever `plan` runs, and a plan that cannot
  # reach the API server fails instead of reporting drift.
  #
  # It is nginx underneath, so the chart's nginx.ingress.kubernetes.io/*
  # annotations apply. The ingress class is webapprouting.kubernetes.io --
  # pass the `ingress_class_name` output to the chart rather than assuming
  # "nginx".
  # toset([...]) rather than [1]: Terraform 1.9 rejects a bare numeric list
  # here and 1.5 accepts it, so a local validate on an older binary does not
  # catch it. app-aca uses the same pattern for the same reason.
  dynamic "web_app_routing" {
    for_each = toset(var.app_routing_enabled ? ["enabled"] : [])
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
