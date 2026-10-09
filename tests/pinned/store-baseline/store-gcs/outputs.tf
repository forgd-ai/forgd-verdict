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
