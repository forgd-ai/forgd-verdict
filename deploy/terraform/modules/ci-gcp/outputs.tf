output "workload_identity_provider" {
  description = "Set it as GCP_WORKLOAD_IDENTITY_PROVIDER on the github_environment environment (verdict-cd-gcp by default)."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "service_account_email" {
  description = "Set it as GCP_SERVICE_ACCOUNT on the github_environment environment (verdict-cd-gcp by default)."
  value       = google_service_account.deploy.email
}

output "gke_rbac_manifest" {
  description = "Null without gke. Apply it once with `kubectl apply -f -`, as someone who may create Roles and RoleBindings in the namespace: it lets the account edit the release namespace, including the chart's BackendConfig and ManagedCertificate, and nothing else in the cluster."
  value       = local.gke_rbac_manifest
}

output "repository_variables" {
  description = "The variables the GCP deploy job reads, to set on the github_environment environment (verdict-cd-gcp by default). GCP_DEPLOY_TARGET is cloudrun or gke. Leave GCP_IMAGE_PLATFORM, GCP_ALLOW_CROSS_BUILD, GCP_GKE_RELEASE and GCP_GKE_CHART unset for their defaults, GCP_RUN_INTAKE_SERVICE and FORGD_INTAKE_URL unset for a stack without intake, and GCP_RUN_CONNECTOR_SERVICE and FORGD_CONNECTOR_URL unset for one without the connector (on gke, FORGD_CONNECTOR_URL alone checks the chart's connector)."
  value       = local.repository_variables
}

output "artifact_repository" {
  description = "Set it as GCP_ARTIFACT_REPOSITORY on the github_environment environment (verdict-cd-gcp by default)."
  value       = "${var.artifact_registry.location}-docker.pkg.dev/${var.project_id}/${var.artifact_registry.repository_id}"
}
