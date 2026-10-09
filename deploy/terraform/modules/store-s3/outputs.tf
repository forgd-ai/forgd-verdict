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

output "writer_deny_policy_json" {
  value = var.control_enabled ? jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "WriterCannotWriteRuntimeOverrides"
      Effect   = "Deny"
      Action   = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"]
      Resource = [local.control_overrides_object, local.control_audit_objects]
      }, {
      Sid      = "WriterCannotRewriteBucketPolicy"
      Effect   = "Deny"
      Action   = ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy"]
      Resource = [aws_s3_bucket.findings.arn]
      }, {
      Sid    = "WriterCannotReconfigureBucket"
      Effect = "Deny"
      Action = [
        "s3:PutBucket*", "s3:DeleteBucket*", "s3:PutLifecycleConfiguration",
        "s3:PutReplicationConfiguration", "s3:PutEncryptionConfiguration",
        "s3:PutInventoryConfiguration", "s3:PutAnalyticsConfiguration",
        "s3:PutMetricsConfiguration", "s3:PutIntelligentTieringConfiguration",
        "s3:PutAccelerateConfiguration",
      ]
      Resource = [aws_s3_bucket.findings.arn]
      }, {
      Sid      = "WriterCannotDelete"
      Effect   = "Deny"
      Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
      Resource = ["${aws_s3_bucket.findings.arn}/*"]
    }]
  }) : null
  description = "While control_enabled, an identity policy for any writer role that is not writer_role_arn, such as one an ECS task or EKS service account brings. Attach it to that role. It denies writes to the runtime overrides object and the audit prefix, any change to the bucket's policy or configuration (lifecycle, versioning, replication, encryption and the rest), and deletes. The bucket policy's Deny names this module's writer role only. Null unless control_enabled."
}

output "reader_role_arn" {
  value       = aws_iam_role.reader.arn
  description = "For the dashboard. GetObject and ListBucket only, never PutObject."
}

output "control_role_arn" {
  value       = var.control_enabled ? aws_iam_role.control[0].arn : null
  description = "For the dashboard with admins enabled: app-ecs's control_role_arn, or cluster-eks's. The reader's reads plus the runtime overrides writes. Null unless control_enabled."
}

output "overrides_writer_lockout" {
  value       = var.control_enabled
  description = "True only with control_enabled, when this module takes the writers' writes to the runtime overrides object and audit prefix away. app-ecs's overrides_writer_lockout; it refuses dashboard_admins_enabled without it."
}

output "overrides_writer_identities" {
  value       = var.control_enabled ? [aws_iam_role.writer.arn] : []
  description = "The writer role ARNs whose lockout the dashboard verifies from the bucket policy: app-ecs's overrides_writer_identities, or the chart's dashboard.admins.writerIdentities. Only writer_role_arn is named in the bucket policy's Deny, so a writer role carrying writer_deny_policy_json instead does not verify. Empty unless control_enabled."
}
