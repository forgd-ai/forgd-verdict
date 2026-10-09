output "role_arn" {
  description = "Set it as AWS_DEPLOY_ROLE_ARN on the verdict-cd-aws environment."
  value       = aws_iam_role.deploy.arn
}

output "oidc_provider_arn" {
  value = local.oidc_provider_arn
}

output "repository_variables" {
  description = "The variables the AWS deploy job reads, to set on the verdict-cd-aws environment. Leave AWS_IMAGE_PLATFORM, AWS_ALLOW_CROSS_BUILD, AWS_INGEST_SCHEDULE_GROUP, AWS_EKS_CHART and AWS_EKS_REGION unset for their defaults, the AWS_ECS_INTAKE_* pair and FORGD_INTAKE_URL unset for a stack without intake, and the AWS_ECS_CONNECTOR_* pair and FORGD_CONNECTOR_URL unset for one without the connector (on eks, FORGD_CONNECTOR_URL alone checks the chart's connector)."
  value       = local.repository_variables
}
