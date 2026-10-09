output "verdict_url" {
  value       = google_cloud_run_v2_service.verdict.uri
  description = "The Inference hooks endpoint is this + /hook."
}

output "collector_url" {
  value       = google_cloud_run_v2_service.collector.uri
  description = "The OTLP endpoint. Anthropic appends /v1/logs and /v1/traces."
}

output "dashboard_url" {
  value = google_cloud_run_v2_service.dashboard.uri
}

output "intake_url" {
  value       = var.enable_intake ? google_cloud_run_v2_service.intake[0].uri : null
  description = "Null unless enable_intake."
}

output "dashboard_iap_audience" {
  value       = local.dashboard_iap_audience
  description = "IAP's audience for the dashboard. The module sets it as FORGD_DASHBOARD_AUDIENCE; it is output for a dashboard.auth.audience set elsewhere."
}

output "service_account_emails" {
  value       = merge({ for role, sa in google_service_account.role : role => sa.email }, var.connector_enabled ? { connector = google_service_account.connector[0].email } : {})
  description = "role -> the account the role runs as. Each reads only its own secrets. ci-gcp's cloudrun.runtime_service_accounts takes these values."
}

output "writer_members" {
  value       = { for r in local.writer_roles : r => google_service_account.role[r].member }
  description = "The verdict, collector, ingest and (with enable_intake) intake accounts by role, for store-gcs's writer_members."
}

output "reader_members" {
  value       = merge(var.dashboard_admins_enabled ? {} : { dashboard = google_service_account.role["dashboard"].member }, var.connector_enabled ? { connector = google_service_account.connector[0].member } : {})
  description = "The dashboard's (unless dashboard_admins_enabled) and (with connector_enabled) the connector's accounts by role, for store-gcs's reader_members."
}

output "control_members" {
  value       = var.dashboard_admins_enabled ? { dashboard = google_service_account.role["dashboard"].member } : {}
  description = "The dashboard's account when dashboard_admins_enabled, for store-gcs's control_members, which gives it the readers' binding as well. It leaves reader_members then, under the same key."
}

output "scheduler_service_account_email" {
  value       = google_service_account.scheduler.email
  description = "Cloud Scheduler runs the ingest job as this account. It may run that job and nothing else."
}

output "ingest_job_name" {
  value = google_cloud_run_v2_job.ingest.name
}

output "connector_url" {
  value       = var.connector_enabled ? local.connector_resource : null
  description = "The findings connector's MCP URL, the one entered in Claude and set as FORGD_CONNECTOR_URL. Null unless connector_enabled."
}

output "connector_service_name" {
  value       = var.connector_enabled ? google_cloud_run_v2_service.connector[0].name : null
  description = "Set as GCP_RUN_CONNECTOR_SERVICE, and as cloudrun.services.connector in ci-gcp. Null unless connector_enabled."
}
