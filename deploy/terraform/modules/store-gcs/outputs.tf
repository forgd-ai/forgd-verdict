output "store_url" {
  value       = var.key_prefix == "" ? "gs://${google_storage_bucket.findings.name}" : "gs://${google_storage_bucket.findings.name}/${var.key_prefix}"
  description = "FORGD_VERDICT_STORE. `open_store` dispatches on this prefix."
}

output "bucket_name" {
  value = google_storage_bucket.findings.name
}

output "writer_email" {
  value       = google_service_account.writer.email
  description = "For the verdict server, the collector and the ingest job."
}

output "reader_email" {
  value       = google_service_account.reader.email
  description = "For the dashboard. Get and list only, never create or delete."
}

output "control_email" {
  value       = var.control_enabled ? google_service_account.control[0].email : null
  description = "For the dashboard with admins enabled: the chart's serviceAccounts.control annotation, and cluster-gke's control_email. Null unless control_enabled."
}

output "control_member" {
  value       = var.control_enabled ? google_service_account.control[0].member : null
  description = "The control account as an IAM member. Null unless control_enabled."
}

output "overrides_writer_lockout" {
  value       = var.control_enabled
  description = "True only with control_enabled, when this module takes the writers' writes to the runtime overrides object and audit prefix away. app-cloudrun's overrides_writer_lockout; it refuses dashboard_admins_enabled without it."
}

output "overrides_writer_identities" {
  value       = var.control_enabled ? values(local.writer_members) : []
  description = "The writer IAM members, the module's writer account and each of writer_members, whose lockout the dashboard verifies from the bucket IAM policy: app-cloudrun's overrides_writer_identities, or the chart's dashboard.admins.writerIdentities. Empty unless control_enabled."
}
