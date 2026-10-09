output "alb_dns_name" {
  value       = aws_lb.this.dns_name
  description = "Point every service host at this, as a CNAME or a Route 53 alias with alb_zone_id."
}

output "alb_zone_id" {
  value = aws_lb.this.zone_id
}

output "alb_arn" {
  value       = aws_lb.this.arn
  description = "The dashboard verifies sign-in tokens against it. Replacing the ALB changes it, and the dashboard's task definition with it."
}

output "verdict_url" {
  value       = "https://${var.verdict_host}"
  description = "The Inference hooks endpoint is this + /hook."
}

output "collector_url" {
  value       = "https://${var.collector_host}"
  description = "The OTLP endpoint. Anthropic appends /v1/logs and /v1/traces."
}

output "dashboard_url" {
  value = "https://${var.dashboard_host}"
}

output "intake_url" {
  value = var.enable_intake ? "https://${var.intake_host}" : null
}

output "oidc_redirect_uri" {
  value       = "https://${var.dashboard_host}/oauth2/idpresponse"
  description = "Register this with the IdP client. The ALB's callback path is fixed."
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "service_names" {
  value = merge({
    verdict   = aws_ecs_service.verdict.name
    collector = aws_ecs_service.collector.name
    dashboard = aws_ecs_service.dashboard.name
    intake    = var.enable_intake ? aws_ecs_service.intake[0].name : null
  }, var.connector_enabled ? { connector = aws_ecs_service.connector[0].name } : {})
}

output "task_definition_families" {
  value = merge({
    verdict   = aws_ecs_task_definition.verdict.family
    collector = aws_ecs_task_definition.collector.family
    dashboard = aws_ecs_task_definition.dashboard.family
    intake    = var.enable_intake ? aws_ecs_task_definition.intake[0].family : null
    ingest    = aws_ecs_task_definition.ingest.family
  }, var.connector_enabled ? { connector = aws_ecs_task_definition.connector[0].family } : {})
  description = "What CI rolls. A release registers a revision from the latest in each family with the new image."
}

output "ingest_schedule_name" {
  value = aws_scheduler_schedule.ingest.name
}

output "verify_command" {
  description = "Applying proves the resources exist, not that they refuse an unsigned request. Run it once DNS for the hosts resolves to the ALB."
  value = join(" ", [
    "scripts/verify_deployment.sh",
    "https://${var.verdict_host}",
    "https://${var.collector_host}",
    "https://${var.dashboard_host}",
  ])
}

output "ci_release" {
  description = "What the CD role in ../ci-aws may act on: pass it as that module's `ecs` input."
  value = {
    service_arns = [for s in concat([aws_ecs_service.verdict, aws_ecs_service.collector, aws_ecs_service.dashboard], aws_ecs_service.intake, aws_ecs_service.connector) : s.id]
    task_definition_arns = [
      for f in compact([
        aws_ecs_task_definition.verdict.family,
        aws_ecs_task_definition.collector.family,
        aws_ecs_task_definition.dashboard.family,
        var.enable_intake ? aws_ecs_task_definition.intake[0].family : null,
        aws_ecs_task_definition.ingest.family,
        var.connector_enabled ? aws_ecs_task_definition.connector[0].family : null,
      ]) : "arn:${local.partition}:ecs:${local.region}:${local.account_id}:task-definition/${f}:*"
    ]
    task_role_arns    = distinct(concat([for r in aws_iam_role.execution : r.arn], [var.writer_role_arn, var.reader_role_arn]))
    schedule_arn      = aws_scheduler_schedule.ingest.arn
    schedule_role_arn = aws_iam_role.scheduler.arn
  }
}

output "connector_url" {
  value       = var.connector_enabled ? local.connector_resource : null
  description = "The findings connector's MCP URL, the one entered in Claude and set as FORGD_CONNECTOR_URL, with service_names.connector and task_definition_families.connector as AWS_ECS_CONNECTOR_SERVICE and AWS_ECS_CONNECTOR_FAMILY. Null unless connector_enabled."
}
