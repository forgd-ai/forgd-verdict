output "store_url" {
  value       = var.key_prefix == "" ? "s3://${aws_s3_bucket.findings.bucket}" : "s3://${aws_s3_bucket.findings.bucket}/${var.key_prefix}"
  description = "FORGD_VERDICT_STORE. `open_store` dispatches on this prefix."
}

output "bucket_name" {
  value = aws_s3_bucket.findings.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.findings.arn
}

output "writer_role_arn" {
  value       = aws_iam_role.writer.arn
  description = "For the verdict server, the collector and the ingest job."
}

output "reader_role_arn" {
  value       = aws_iam_role.reader.arn
  description = "For the dashboard. GetObject and ListBucket only, never PutObject."
}
