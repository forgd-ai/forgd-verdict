# The CD identity for the GCP deploy job: one service account that GitHub
# Actions impersonates through Workload Identity Federation, from one
# environment of one repository.
#
# Each grant is made on the resource it covers. The account's writes are
# image layers to one Artifact Registry repository and new revisions of the
# Cloud Run services and the ingest job Terraform owns. It may act as the
# runtime service accounts those revisions run as, and no other account.
#
# On GKE it may fetch cluster credentials and nothing more through IAM.
# What helm may do in the cluster is namespaced RBAC this module does not
# create; the gke_rbac_manifest output is it, for kubectl apply.
#
# This module does not deploy anything. Apply it with an identity that can
# create pools, service accounts and IAM bindings; the account it creates
# cannot.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
  }
}

locals {
  # One member: every token from the repository, narrowed to the one
  # environment by the provider's attribute_condition.
  deployer_member = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository_id/${var.github_repository_id}"

  cloudrun_services = var.cloudrun == null ? {} : var.cloudrun.services
  runtime_accounts  = var.cloudrun == null ? toset([]) : toset(var.cloudrun.runtime_service_accounts)

  # Read by .github/workflows/deploy.yml, which a fork copies from
  # examples/github/deploy.yml, and passed to deploy_gcp.sh as environment
  # variables of the same names.
  repository_variables = concat(
    [
      "GCP_WORKLOAD_IDENTITY_PROVIDER", "GCP_SERVICE_ACCOUNT", "GCP_PROJECT_ID", "GCP_REGION",
      "GCP_ARTIFACT_REPOSITORY", "GCP_DEPLOY_TARGET",
      "FORGD_VERDICT_URL", "FORGD_COLLECTOR_URL", "FORGD_DASHBOARD_URL", "FORGD_CONNECTOR_URL", "FORGD_INTAKE_URL",
      "GCP_IMAGE_PLATFORM", "GCP_ALLOW_CROSS_BUILD",
    ],
    var.cloudrun == null ? [] : [
      "GCP_RUN_VERDICT_SERVICE", "GCP_RUN_COLLECTOR_SERVICE", "GCP_RUN_DASHBOARD_SERVICE", "GCP_RUN_INTAKE_SERVICE",
      "GCP_RUN_CONNECTOR_SERVICE", "GCP_RUN_INGEST_JOB",
    ],
    var.gke == null ? [] : ["GCP_GKE_CLUSTER", "GCP_GKE_LOCATION", "GCP_GKE_NAMESPACE", "GCP_GKE_RELEASE", "GCP_GKE_CHART"],
  )

  # ClusterRole edit, plus the chart's two GKE custom resources, which edit
  # does not necessarily aggregate. Every object is in the release namespace.
  gke_rbac_manifest = var.gke == null ? null : <<-EOT
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: ${var.name_prefix}-deploy-gke
      namespace: ${var.gke.namespace}
    rules:
      - apiGroups: ["cloud.google.com"]
        resources: ["backendconfigs"]
        verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
      - apiGroups: ["networking.gke.io"]
        resources: ["managedcertificates"]
        verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      name: ${var.name_prefix}-deploy-edit
      namespace: ${var.gke.namespace}
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: edit
    subjects:
      - apiGroup: rbac.authorization.k8s.io
        kind: User
        name: ${google_service_account.deploy.email}
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      name: ${var.name_prefix}-deploy-gke
      namespace: ${var.gke.namespace}
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: Role
      name: ${var.name_prefix}-deploy-gke
    subjects:
      - apiGroup: rbac.authorization.k8s.io
        kind: User
        name: ${google_service_account.deploy.email}
  EOT
}

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "GitHub Actions"
  description               = "Tokens from ${var.github_environment} in GitHub repository ${var.github_repository_id}."
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub Actions"

  attribute_mapping = {
    "google.subject"                = "assertion.sub"
    "attribute.repository_id"       = "assertion.repository_id"
    "attribute.repository_owner_id" = "assertion.repository_owner_id"
    "attribute.environment"         = "assertion.environment"
  }

  # A token failing this is refused by STS, before any IAM binding is read.
  attribute_condition = join(" && ", [
    "assertion.repository_id == ${jsonencode(var.github_repository_id)}",
    "assertion.repository_owner_id == ${jsonencode(var.github_owner_id)}",
    "assertion.environment == ${jsonencode(var.github_environment)}",
  ])

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "deploy" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-deploy"
  display_name = "forgd-verdict CD"

  lifecycle {
    precondition {
      condition     = var.cloudrun != null || var.gke != null
      error_message = "Set cloudrun, gke or both. With neither the account can push images and roll nothing."
    }
  }
}

resource "google_service_account_iam_member" "deploy_workload_identity" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.deployer_member
}

resource "google_artifact_registry_repository_iam_member" "deploy" {
  project    = var.project_id
  location   = var.artifact_registry.location
  repository = var.artifact_registry.repository_id
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.deploy.member
}

# --- cloudrun --------------------------------------------------------------

resource "google_cloud_run_v2_service_iam_member" "deploy" {
  for_each = local.cloudrun_services

  project  = var.project_id
  location = var.region
  name     = each.value
  role     = "roles/run.developer"
  member   = google_service_account.deploy.member
}

resource "google_cloud_run_v2_job_iam_member" "deploy" {
  count = var.cloudrun == null ? 0 : 1

  project  = var.project_id
  location = var.region
  name     = var.cloudrun.ingest_job
  role     = "roles/run.developer"
  member   = google_service_account.deploy.member
}

# A new revision runs as the service's account, and deploying one needs
# iam.serviceAccounts.actAs on it.
resource "google_service_account_iam_member" "deploy_act_as" {
  for_each = local.runtime_accounts

  service_account_id = "projects/${var.project_id}/serviceAccounts/${each.value}"
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.deploy.member
}

# --- gke -------------------------------------------------------------------

# For `gcloud container clusters get-credentials` and the DNS endpoint:
# container.clusters.get and container.clusters.connect. GKE has no
# cluster-level IAM, so this is on the project. The role carries no
# Kubernetes object permission; gke_rbac_manifest is the only one.
resource "google_project_iam_member" "deploy_gke" {
  count = var.gke == null ? 0 : 1

  project = var.project_id
  role    = "roles/container.clusterViewer"
  member  = google_service_account.deploy.member
}
