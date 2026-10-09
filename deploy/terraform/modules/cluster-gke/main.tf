# A GKE Autopilot cluster for the Helm chart, and the Workload Identity
# bindings that let its pods act as the store's service accounts.
#
# This module does NOT deploy the chart, and installs nothing into the
# cluster: no helm or kubernetes provider.
#
# It also does not create the store or grant access to it. ../store-gcs
# does, and its writer and reader emails are inputs here. The only IAM this
# module grants is roles/iam.workloadIdentityUser on those two accounts, each
# to one Kubernetes service account, and, with a database encryption key,
# use of that key to GKE's service agent.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
  }
}

data "google_project" "this" {
  count      = local.kms ? 1 : 0
  project_id = var.project_id
}

locals {
  kms = var.database_encryption_key_name != null

  # Autopilot enables Workload Identity with the project's pool.
  workload_pool = "${var.project_id}.svc.id.goog"

  # The Kubernetes service account each store account is bound to, and the
  # project that owns the account, read from its email's domain.
  workload_identity = merge({
    writer = {
      email           = var.writer_email
      project         = regex("@([a-z0-9-]+)\\.iam\\.gserviceaccount\\.com$", var.writer_email)[0]
      service_account = var.writer_service_account
    }
    reader = {
      email           = var.reader_email
      project         = regex("@([a-z0-9-]+)\\.iam\\.gserviceaccount\\.com$", var.reader_email)[0]
      service_account = var.reader_service_account
    }
    }, var.connector_enabled ? {
    # The findings connector, on the reader account like the dashboard.
    connector = {
      email           = var.reader_email
      project         = regex("@([a-z0-9-]+)\\.iam\\.gserviceaccount\\.com$", var.reader_email)[0]
      service_account = var.connector_service_account
    }
    } : {}, var.control_enabled ? {
    # The dashboard with admins enabled, on store-gcs's control account.
    control = {
      email           = var.control_email
      project         = try(regex("@([a-z0-9-]+)\\.iam\\.gserviceaccount\\.com$", var.control_email)[0], "")
      service_account = var.control_service_account
    }
  } : {})
}

# --- control plane -------------------------------------------------------

# With a customer-managed key, GKE encrypts secrets as its own service agent,
# and without this the cluster fails to create.
resource "google_kms_crypto_key_iam_member" "gke_agent" {
  count         = local.kms ? 1 : 0
  crypto_key_id = var.database_encryption_key_name
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this[0].number}@container-engine-robot.iam.gserviceaccount.com"
}

resource "google_container_cluster" "this" {
  project  = var.project_id
  name     = var.cluster_name
  location = var.region

  enable_autopilot    = true
  deletion_protection = var.deletion_protection
  resource_labels     = var.labels

  network    = var.network
  subnetwork = var.subnetwork

  release_channel {
    channel = "REGULAR"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = !var.endpoint_public_access

    master_global_access_config {
      enabled = var.private_endpoint_global_access
    }
  }

  # private_access_cidrs are always rendered; public_access_cidrs only with
  # the public endpoint on.
  master_authorized_networks_config {
    gcp_public_cidrs_access_enabled = false

    dynamic "cidr_blocks" {
      for_each = toset(concat(var.private_access_cidrs, var.endpoint_public_access ? var.public_access_cidrs : []))
      content {
        cidr_block = cidr_blocks.value
      }
    }
  }

  # The DNS-based endpoint is a second way to the API. Every request to it
  # must carry an IAM credential with container.clusters.connect; with
  # dns_endpoint_allow_external_traffic off, only traffic from inside Google
  # Cloud reaches it.
  control_plane_endpoints_config {
    dns_endpoint_config {
      allow_external_traffic = var.dns_endpoint_allow_external_traffic
    }
  }

  dynamic "database_encryption" {
    for_each = local.kms ? [1] : []
    content {
      state    = "ENCRYPTED"
      key_name = var.database_encryption_key_name
    }
  }

  lifecycle {
    precondition {
      condition     = !var.endpoint_public_access || length(var.public_access_cidrs) > 0
      error_message = "endpoint_public_access is true but public_access_cidrs is empty. List the ranges that may reach the Kubernetes API, or turn public access off."
    }
    precondition {
      condition     = !local.kms || try(regex("/locations/([^/]+)/", var.database_encryption_key_name)[0], "") == var.region
      error_message = "database_encryption_key_name must be a key in var.region; GKE refuses a key in another location."
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.gke_agent]
}

# --- workload identity ---------------------------------------------------

# The member is keyed on namespace and service account name, both of which
# must match the release exactly. A mismatch gives a pod with no Google
# credentials, which surfaces as a dashboard with no findings.
#
# The pool exists once the project has a cluster with Workload Identity, and
# IAM refuses a member in a pool that does not exist yet, hence depends_on.
resource "google_service_account_iam_member" "workload_identity" {
  for_each = local.workload_identity

  service_account_id = "projects/${each.value.project}/serviceAccounts/${each.value.email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${local.workload_pool}[${var.namespace}/${each.value.service_account}]"

  lifecycle {
    precondition {
      condition     = var.reader_email != var.writer_email
      error_message = "reader_email equals writer_email. The dashboard must hold store-gcs's reader account, or the one service a human signs into can rewrite the findings."
    }
    precondition {
      condition     = var.reader_service_account != var.writer_service_account
      error_message = "reader_service_account equals writer_service_account. The dashboard's service account would be bound to both store accounts, and could rewrite the findings."
    }
    precondition {
      condition     = !var.connector_enabled || !contains([var.writer_service_account, var.reader_service_account], var.connector_service_account)
      error_message = "connector_service_account must be a service account of its own, not the writer's or the dashboard's."
    }
    precondition {
      condition     = !var.control_enabled || (var.control_email != "" && !contains([var.writer_email, var.reader_email], var.control_email))
      error_message = "control_enabled needs control_email, store-gcs's control_email, and it must differ from writer_email and reader_email. The reader account is shared with the connector, and the writer's can rewrite the findings."
    }
    precondition {
      condition     = !var.control_enabled || !contains(concat([var.writer_service_account, var.reader_service_account], var.connector_enabled ? [var.connector_service_account] : []), var.control_service_account)
      error_message = "control_service_account must be a service account of its own, not the writer's, the reader's or the connector's."
    }
  }

  depends_on = [google_container_cluster.this]
}
