# Five roles as ECS Fargate services, and ingest as a scheduled task,
# from one image.
#
# `FORGD_ROLE` selects the role, so the services cannot drift to different
# versions of the scan core:
#
#   server     adapter 1, the verdict server. Anthropic calls IN.
#   collect    adapter 4, the OTLP collector. Anthropic pushes IN.
#   dashboard  read-only over the findings store. Holds no credential.
#   intake     adapter 2's receiving end, optional. Laptops POST IN.
#   connector  the findings connector for Claude, optional. Claude calls IN.
#   ingest     adapter 3, a scheduled task. Holds the Compliance Access Key.
#
# Each task is ONE container. deploy/entrypoint.sh starts gitleaksd inside it
# for the roles that scan on a path someone waits on, and binds the app only
# once the socket exists, so there is no sidecar to order or share a volume
# with.
#
# THREE OF THESE MUST NEVER SIT BEHIND A PLATFORM AUTH PROVIDER. Anthropic
# authenticates to the verdict server with a webhook signature and to the
# collector with an OTLP header, and a laptop authenticates to intake with a
# bearer token, so an auth redirect turns every governed prompt, export or
# spool upload into a delivery failure rather than a deny. The ALB's
# `authenticate-oidc` action is on the dashboard's rule and nowhere else, and
# scripts/verify_deployment.sh asserts it on every roll.
#
# Routing is by HOST, one hostname per service. Path-based routing cannot
# work: `/healthz` exists on both the verdict server and the dashboard.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition

  # The same name rule as the Helm chart: upper case, hyphens to
  # underscores, because an environment variable name cannot hold a hyphen
  # and policy.yaml refers to these as $FORGD_ORG_ID_<NAME>.
  org_env = { for name, id in var.org_ids : "FORGD_ORG_ID_${upper(replace(name, "-", "_"))}" => id }

  # policy.yaml travels compressed. Plain it is ~18 KB, which is above the
  # single-variable limit on some targets; gzipped it is ~10 KB and fits
  # everywhere. The entrypoint decodes it and refuses to start if it does
  # not, because falling back to the baked default would silently run rules
  # nobody chose.
  policy_gz = base64gzip(var.policy_yaml)

  # The task role each writer role runs as.
  writer_identity = merge(
    { verdict = var.writer_role_arn, collector = var.writer_role_arn, ingest = var.writer_role_arn },
    var.enable_intake ? { intake = var.writer_role_arn } : {},
  )
  writer_order = concat(["verdict", "collector"], var.enable_intake ? ["intake"] : [], ["ingest"])
  # FORGD_OVERRIDES_WRITER_ROLES: one writer role per distinct store
  # identity, the first in writer_order that runs as it. Ingest is last, so
  # it is listed only when no long-running role shares its identity. The
  # dashboard and the connector only read.
  overrides_writer_roles = [
    for i, role in local.writer_order : role
    if !contains([for earlier in slice(local.writer_order, 0, i) : local.writer_identity[earlier]],
    local.writer_identity[role])
  ]

  # Every role honours runtime overrides only while this is "true".
  overrides_env = var.dashboard_admins_enabled ? {
    FORGD_OVERRIDES_ENABLED      = "true"
    FORGD_OVERRIDES_WRITER_ROLES = join(",", local.overrides_writer_roles)
    FORGD_OVERRIDES_VERIFY_KEY   = join(",", var.overrides_verify_keys)
  } : {}

  # The writer identities the dashboard verifies the lockout of.
  dashboard_evidence_env = var.dashboard_admins_enabled ? {
    FORGD_OVERRIDES_WRITER_IDENTITIES = join(",", var.overrides_writer_identities)
  } : {}

  # The path the target group and each container check request for
  # readiness. /healthz answers 200 however the runtime overrides read;
  # /readyz answers 503 until they are confirmed.
  ready_path = var.dashboard_admins_enabled ? "/readyz" : "/healthz"

  base_env = merge({
    FORGD_VERDICT_STORE     = var.store_url
    FORGD_VERDICT_LOG_LEVEL = "INFO"
    FORGD_POLICY_INLINE_GZ  = local.policy_gz
    AWS_REGION              = local.region
  }, local.org_env, local.overrides_env)

  gitleaks_env = { FORGD_GITLEAKS_SOCKET = "/run/forgd/gitleaksd.sock" }

  # Every environment entry and every secret is built from a map, name =>
  # value or name => ARN, so the two can never be confused in the container
  # definition: a secret goes in `secrets` as `valueFrom`, and the value is
  # fetched by the ECS agent at task start. Neither Terraform nor its state
  # ever holds it.
  metrics_secret = var.metrics_token_secret_arn == "" ? {} : { FORGD_METRICS_TOKEN = var.metrics_token_secret_arn }
  salt_secret    = { FORGD_HASH_SALT = var.hash_salt_secret_arn }

  otel_secrets = { for name, arn in var.otel_token_secret_arns : "FORGD_OTEL_TOKEN_${upper(replace(name, "-", "_"))}" => arn }
  # Token names with no non-empty org id under the same env name.
  org_id_by_env = { for name, id in var.org_ids : upper(replace(name, "-", "_")) => id }
  otel_tokens_without_org = [
    for name in keys(var.otel_token_secret_arns) : name
    if lookup(local.org_id_by_env, upper(replace(name, "-", "_")), "") == "" && !contains(keys(local.otel_fleet_by_env), upper(replace(name, "-", "_")))
  ]
  # A fleet exporter token: one token for a set of orgs, each named by its
  # org_ids key. Each problem is one sentence of the refusal.
  otel_fleet_by_env = { for name, members in var.otel_fleets : upper(replace(name, "-", "_")) => members }
  otel_fleet_problems = concat(
    [for name, members in var.otel_fleets : "otel_fleets.${name} names no org" if length(members) == 0],
    [for name, _ in var.otel_fleets : "otel_fleets.${name} has the name of an org_ids entry, so FORGD_OTEL_TOKEN_${upper(replace(name, "-", "_"))} would be both" if contains(keys(local.org_id_by_env), upper(replace(name, "-", "_")))],
    [for name, members in var.otel_fleets : "otel_fleets.${name} lists an org id; list each org by its org_ids name" if anytrue([for o in members : can(regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$", o))])],
    flatten([for name, members in var.otel_fleets : [
      for o in members : "otel_fleets.${name} names ${o}, which has no non-empty org_ids entry"
      if !can(regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$", o)) && lookup(local.org_id_by_env, upper(replace(o, "-", "_")), "") == ""
    ]]),
    [for name, _ in var.otel_fleets : "otel_fleets.${name} has no token in otel_token_secret_arns" if !contains([for name in keys(var.otel_token_secret_arns) : upper(replace(name, "-", "_"))], upper(replace(name, "-", "_")))],
  )
  # Per-org secrets, keyed by org_ids name. Each name makes <PREFIX>_<NAME>
  # and, for the two with a previous slot, <PREFIX>_<NAME>_PREVIOUS.
  webhook_org_secrets = merge(concat([{}], [for name, s in var.webhook_secret_arns : merge(
    { "WEBHOOK_SECRET_${upper(replace(name, "-", "_"))}" = s.current },
    s.previous == "" ? {} : { "WEBHOOK_SECRET_${upper(replace(name, "-", "_"))}_PREVIOUS" = s.previous },
  )])...)
  compliance_org_secrets = { for name, arn in var.compliance_key_secret_arns : "ANTHROPIC_COMPLIANCE_ACCESS_KEY_${upper(replace(name, "-", "_"))}" => arn }
  intake_fleet_org_secrets = merge(concat([{}], [for name, s in var.intake_fleet_token_secret_arns : merge(
    { "FORGD_INTAKE_FLEET_TOKEN_${upper(replace(name, "-", "_"))}" = s.current },
    s.previous == "" ? {} : { "FORGD_INTAKE_FLEET_TOKEN_${upper(replace(name, "-", "_"))}_PREVIOUS" = s.previous },
  )])...)
  # Every variable each map could set, its single slots included, so a
  # repeat is a collision whether or not a previous value is set now.
  org_secret_vars = {
    webhook_secret_arns = concat(["WEBHOOK_SECRET", "WEBHOOK_SECRET_PREVIOUS"], flatten([
    for name in keys(var.webhook_secret_arns) : ["WEBHOOK_SECRET_${upper(replace(name, "-", "_"))}", "WEBHOOK_SECRET_${upper(replace(name, "-", "_"))}_PREVIOUS"]]))
    compliance_key_secret_arns = concat(["ANTHROPIC_COMPLIANCE_ACCESS_KEY"], [
    for name in keys(var.compliance_key_secret_arns) : "ANTHROPIC_COMPLIANCE_ACCESS_KEY_${upper(replace(name, "-", "_"))}"])
    intake_fleet_token_secret_arns = concat(["FORGD_INTAKE_FLEET_TOKEN", "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS"], flatten([
    for name in keys(var.intake_fleet_token_secret_arns) : ["FORGD_INTAKE_FLEET_TOKEN_${upper(replace(name, "-", "_"))}", "FORGD_INTAKE_FLEET_TOKEN_${upper(replace(name, "-", "_"))}_PREVIOUS"]]))
  }
  org_secret_names = {
    webhook_secret_arns            = keys(var.webhook_secret_arns)
    compliance_key_secret_arns     = keys(var.compliance_key_secret_arns)
    intake_fleet_token_secret_arns = keys(var.intake_fleet_token_secret_arns)
  }
  org_secret_problems = concat(
    flatten([for v, names in local.org_secret_names : [
      for name in names : "${v}.${name} has no org_ids entry; each key is an org's org_ids name"
      if !contains(keys(local.org_id_by_env), upper(replace(name, "-", "_")))
    ]]),
    flatten([for v, vars in local.org_secret_vars : [
      for x in distinct(vars) : "${v} collides on ${x}: give one of the orgs another org_ids name"
      if length([for y in vars : y if y == x]) > 1
    ]]),
  )
  intake_secrets = merge(
    { for name, arn in var.intake_token_secret_arns : "FORGD_INTAKE_TOKEN_${upper(replace(name, "-", "_"))}" => arn },
    var.intake_fleet_token_secret_arn == "" ? {} : { FORGD_INTAKE_FLEET_TOKEN = var.intake_fleet_token_secret_arn },
    var.intake_fleet_token_previous_secret_arn == "" ? {} : { FORGD_INTAKE_FLEET_TOKEN_PREVIOUS = var.intake_fleet_token_previous_secret_arn },
    local.intake_fleet_org_secrets,
  )

  verdict_secrets = merge(
    var.webhook_secret_arn == "" ? {} : { WEBHOOK_SECRET = var.webhook_secret_arn },
    local.webhook_org_secrets,
    var.webhook_secret_previous_arn == "" ? {} : { WEBHOOK_SECRET_PREVIOUS = var.webhook_secret_previous_arn },
    local.salt_secret,
    local.metrics_secret,
  )
  collector_secrets = merge(local.otel_secrets, local.salt_secret, local.metrics_secret)
  intake_all        = merge(local.intake_secrets, local.salt_secret, local.metrics_secret)
  ingest_secrets = merge(
    var.compliance_key_secret_arn == "" ? {} : { ANTHROPIC_COMPLIANCE_ACCESS_KEY = var.compliance_key_secret_arn },
    local.compliance_org_secrets,
    local.salt_secret,
  )
  dashboard_secrets = var.dashboard_admins_enabled ? {
    FORGD_DASHBOARD_FORM_KEY    = var.dashboard_form_key_secret_arn
    FORGD_OVERRIDES_SIGNING_KEY = var.dashboard_signing_key_secret_arn
  } : {}

  # role => the secrets its container definition names. The container
  # definitions and the execution-role policies both read this map, so the
  # two cannot disagree, and the dashboard's execution role cannot fetch the
  # webhook secret, the Compliance key or an OTel token.
  role_secrets = merge({
    verdict   = local.verdict_secrets
    collector = local.collector_secrets
    dashboard = local.dashboard_secrets
    ingest    = local.ingest_secrets
  }, var.enable_intake ? { intake = local.intake_all } : {}, var.connector_enabled ? { connector = {} } : {})

  roles = concat(var.enable_intake ? ["verdict", "collector", "dashboard", "intake", "ingest"] : ["verdict", "collector", "dashboard", "ingest"], var.connector_enabled ? ["connector"] : [])

  ports = merge({
    verdict   = 8000
    collector = 8100
    dashboard = 8080
    intake    = 8200
  }, var.connector_enabled ? { connector = 8090 } : {})
  hosts = merge({
    verdict   = var.verdict_host
    collector = var.collector_host
    dashboard = var.dashboard_host
    intake    = var.intake_host
  }, var.connector_enabled ? { connector = var.connector_host } : {})
  # ECS replaces a task whose essential container fails this. urlopen raises
  # on a non-2xx, so /livez's 503 exits non-zero.
  livez_check = { for r in ["verdict", "collector", "intake"] : r => {
    command     = ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${local.ports[r]}/livez', timeout=4)"]
    interval    = 10
    timeout     = 5
    retries     = 6
    startPeriod = 90
  } }
  # With dashboard_admins_enabled, every container's check: /livez on the
  # roles that run gitleaksd, then local.ready_path on every service. The
  # ALB target group's check on local.ready_path is what holds a task out
  # of traffic.
  container_check_paths = { for r in keys(local.ports) : r => contains(["verdict", "collector", "intake"], r) ? ["/livez", local.ready_path] : [local.ready_path] }
  container_check = { for r, paths in local.container_check_paths : r => {
    command = ["CMD", "python", "-c", join("; ", concat(["import urllib.request"], [
      for path in paths : "urllib.request.urlopen('http://127.0.0.1:${local.ports[r]}${path}', timeout=2)"
    ]))]
    interval    = 10
    timeout     = 5
    retries     = 6
    startPeriod = 90
  } }

  services = concat(var.enable_intake ? ["verdict", "collector", "dashboard", "intake"] : ["verdict", "collector", "dashboard"], var.connector_enabled ? ["connector"] : [])

  service_hosts = [for svc in local.services : lower(local.hosts[svc])]

  log_config = { for r in local.roles : r => {
    logDriver = "awslogs"
    options = {
      awslogs-group         = aws_cloudwatch_log_group.this[r].name
      awslogs-region        = local.region
      awslogs-stream-prefix = r
    }
  } }
}

# --- logs ----------------------------------------------------------------
resource "aws_cloudwatch_log_group" "this" {
  for_each = toset(local.roles)

  name              = "/ecs/${var.name_prefix}/${each.key}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# --- the execution roles ------------------------------------------------
#
# The ECS AGENT's roles, not the app's: each pulls the image, writes the log
# stream and fetches the secrets named in its task's container definition.
# The app runs as the TASK role, which is an input -- store-s3's writer or
# reader role -- so this module never decides what a service may do to
# findings.
#
# One per role rather than one shared. A shared role can read the union of
# every task's secrets, so the dashboard's task would run under an identity
# able to fetch the Compliance key; the container would not receive it, but
# the permission would be there for anything that obtained the role.
#
# Scoped by hand rather than with AmazonECSTaskExecutionRolePolicy, which
# grants log writes to every group in the account and no secrets at all.
resource "aws_iam_role" "execution" {
  for_each = toset(local.roles)

  name = "${var.name_prefix}-${each.key}-execution"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "execution" {
  for_each = toset(local.roles)

  name = "pull-log-read-secrets"
  role = aws_iam_role.execution[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        # GetAuthorizationToken has no resource-level permission. The layer
        # reads are left unscoped because the image source is an input:
        # this module does not know which repository it is.
        Sid      = "PullImage"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = "*"
      },
      {
        Sid      = "WriteLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.this[each.key].arn}:*"
      },
      ],
      # This role's secrets exactly, by full ARN -- see the validation on the
      # variables for why the ARN must carry its random suffix. None for the
      # dashboard, and so no statement at all rather than an empty one,
      # which IAM rejects.
      length(local.role_secrets[each.key]) == 0 ? [] : [{
        Sid      = "ReadSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = distinct(values(local.role_secrets[each.key]))
      }],
      length(local.role_secrets[each.key]) == 0 || length(var.secrets_kms_key_arns) == 0 ? [] : [{
        Sid      = "DecryptSecrets"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secrets_kms_key_arns
        Condition = { StringEquals = {
          "kms:ViaService" = "secretsmanager.${local.region}.amazonaws.com"
        } }
    }])
  })
}

# --- network -------------------------------------------------------------
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "forgd-verdict ALB: HTTPS in from the internet"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each = toset(var.alb_ingress_cidrs)

  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS"
}

# Only to be redirected. Nothing is served on 80.
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  for_each = toset(var.alb_ingress_cidrs)

  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = each.value
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "HTTP, redirected to HTTPS"
}

# Open, not just to the tasks: `authenticate-oidc` has the ALB itself call
# the IdP's token and userinfo endpoints, and with egress limited to the VPC
# every dashboard sign-in fails at the callback with a 500.
resource "aws_vpc_security_group_egress_rule" "alb" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Targets, and the IdP for authenticate-oidc"
}

# One group per service, each admitting its own port from the ALB and
# nothing else -- not other tasks, not the VPC.
resource "aws_security_group" "task" {
  for_each = toset(local.roles)

  name        = "${var.name_prefix}-${each.key}"
  description = "forgd-verdict ${each.key} task"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "task_from_alb" {
  for_each = toset(local.services)

  security_group_id            = aws_security_group.task[each.key].id
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = local.ports[each.key]
  to_port                      = local.ports[each.key]
  ip_protocol                  = "tcp"
  description                  = "From the ALB only"
}

# Open: tasks reach Anthropic's APIs, S3, Secrets Manager and ECR, and none
# of those has a fixed address range worth pinning here.
resource "aws_vpc_security_group_egress_rule" "task" {
  for_each = toset(local.roles)

  security_group_id = aws_security_group.task[each.key].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Anthropic APIs, S3, Secrets Manager, ECR"
}

# --- the load balancer ---------------------------------------------------
resource "aws_lb" "this" {
  name               = var.name_prefix
  load_balancer_type = "application"
  internal           = false
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]
  tags               = var.tags

  # The dashboard trusts `x-amzn-oidc-data` only after checking its
  # signature against this ALB's ARN, so a forged copy is refused either
  # way. Dropping malformed header names is still the ALB's job.
  drop_invalid_header_fields = true

  lifecycle {
    # The dashboard verifies the ALB's sign-in token by fetching the signing
    # key from public-keys.auth.elb.<region>.amazonaws.com, which serves the
    # commercial partition only; `_verify_alb` refuses any other ARN and the
    # dashboard would never start. Refused here, at plan, instead.
    precondition {
      condition     = local.partition == "aws"
      error_message = "The dashboard's ALB sign-in verification supports the commercial partition (aws) only; this account is in ${local.partition}."
    }
  }
}

resource "aws_lb_target_group" "this" {
  for_each = toset(local.services)

  name        = "${var.name_prefix}-${each.key}"
  port        = local.ports[each.key]
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  tags        = var.tags

  deregistration_delay = 30

  health_check {
    path                = local.ready_path
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  tags              = var.tags

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = var.certificate_arn
  tags              = var.tags

  # A host this module does not name gets a 404 rather than a default
  # service, so a stray DNS record cannot reach the dashboard unauthenticated
  # by way of some other rule.
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
}

# Verdict, collector and intake: a plain forward. NEVER authenticate-oidc --
# see the header. tests/test_app_ecs.py fails if one appears.
resource "aws_lb_listener_rule" "verdict" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  tags         = var.tags

  condition {
    host_header {
      values = [var.verdict_host]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["verdict"].arn
  }
}

resource "aws_lb_listener_rule" "collector" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20
  tags         = var.tags

  condition {
    host_header {
      values = [var.collector_host]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["collector"].arn
  }
}

resource "aws_lb_listener_rule" "intake" {
  count = var.enable_intake ? 1 : 0

  listener_arn = aws_lb_listener.https.arn
  priority     = 30
  tags         = var.tags

  condition {
    host_header {
      values = [var.intake_host]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["intake"].arn
  }

  lifecycle {
    precondition {
      condition     = var.intake_host != ""
      error_message = "enable_intake is true but intake_host is empty. Intake is routed by host like every other service."
    }
  }
}

# The findings connector: a plain forward, like verdict. NEVER
# authenticate-oidc: the connector verifies the bearer token from the
# customer's identity provider itself, and a sign-in in front answers Claude
# before the connector's own 401 can point it at the identity provider.
resource "aws_lb_listener_rule" "connector" {
  count = var.connector_enabled ? 1 : 0

  listener_arn = aws_lb_listener.https.arn
  priority     = 60
  tags         = var.tags

  condition {
    host_header {
      values = [var.connector_host]
    }
  }
  # Empty admits every source that alb_ingress_cidrs admits. A request from
  # anywhere else falls through to the listener's 404.
  dynamic "condition" {
    for_each = length(var.connector_source_ranges) == 0 ? [] : [var.connector_source_ranges]
    content {
      source_ip {
        values = condition.value
      }
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["connector"].arn
  }
}

# The dashboard's /healthz, unauthenticated, at a HIGHER priority than the
# sign-in rule below. The deploy gate probes it before asserting anything
# else; behind authenticate-oidc the probe is redirected and
# verify_deployment.sh fails `dashboard.health` on a healthy deployment, so
# the checks that matter never run. It reveals nothing: a status, an uptime
# and a build.
resource "aws_lb_listener_rule" "dashboard_healthz" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 40
  tags         = var.tags

  condition {
    host_header {
      values = [var.dashboard_host]
    }
  }
  condition {
    path_pattern {
      values = ["/healthz"]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["dashboard"].arn
  }
}

# The only rule that signs anyone in. The ALB runs the OIDC flow and hands
# the dashboard a signed `x-amzn-oidc-data`, which the app verifies itself
# (dashboard/auth.py `_verify_alb`) against this ALB's ARN and the IdP's
# issuer and client id. The client secret is the one secret this module
# holds as a value -- the action takes nothing else -- so it is in state.
resource "aws_lb_listener_rule" "dashboard" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 50
  tags         = var.tags

  condition {
    host_header {
      values = [var.dashboard_host]
    }
  }
  action {
    type = "authenticate-oidc"
    authenticate_oidc {
      issuer                     = var.oidc_issuer
      authorization_endpoint     = var.oidc_authorization_endpoint
      token_endpoint             = var.oidc_token_endpoint
      user_info_endpoint         = var.oidc_user_info_endpoint
      client_id                  = var.oidc_client_id
      client_secret              = var.oidc_client_secret
      scope                      = var.oidc_scope
      on_unauthenticated_request = "authenticate"
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["dashboard"].arn
  }

  lifecycle {
    # Rules are matched in priority order, and every rule above this one
    # forwards without sign-in. A dashboard host shared with any of them is
    # served by that rule instead, so this one never runs.
    precondition {
      condition     = length(distinct(local.service_hosts)) == length(local.service_hosts)
      error_message = "verdict_host, collector_host, dashboard_host, (with enable_intake) intake_host and (with connector_enabled) connector_host must all differ. The ALB routes on the host, and a shared host is taken by an earlier rule, which forwards without sign-in."
    }
  }
}

# --- the cluster ---------------------------------------------------------
resource "aws_ecs_cluster" "this" {
  name = var.name_prefix
  tags = var.tags
}

# --- task definitions ----------------------------------------------------
#
# Terraform registers the first revision of each. After that, CI owns which
# revision runs -- see the services' lifecycle blocks.

# --- adapter 1: the verdict server ---------------------------------------
# memory holds up to twice server.preauth_body_budget_bytes (256 MiB) of
# unsigned request body; see docs/SERVER.md#memory.
resource "aws_ecs_task_definition" "verdict" {
  family                   = "${var.name_prefix}-verdict"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.execution["verdict"].arn
  task_role_arn            = local.writer_identity["verdict"]
  tags                     = var.tags

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  container_definitions = jsonencode([{
    name         = "verdict"
    image        = var.image
    essential    = true
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    environment = [for k, v in merge(local.base_env, local.gitleaks_env, {
      FORGD_ROLE         = "server"
      FORGD_VERDICT_MODE = var.verdict_mode
    }) : { name = k, value = v }]
    secrets          = [for k, arn in local.role_secrets["verdict"] : { name = k, valueFrom = arn }]
    logConfiguration = local.log_config["verdict"]
    healthCheck      = var.dashboard_admins_enabled ? local.container_check["verdict"] : local.livez_check["verdict"]
  }])
}

# --- adapter 4: the OTLP collector ---------------------------------------
resource "aws_ecs_task_definition" "collector" {
  family                   = "${var.name_prefix}-collector"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.execution["collector"].arn
  task_role_arn            = local.writer_identity["collector"]
  tags                     = var.tags

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # /stats needs the metrics token, and it is how a silent surface is
  # diagnosed. Without it "nothing arrived" is indistinguishable from
  # "arrived and was rejected".
  container_definitions = jsonencode([{
    name         = "collector"
    image        = var.image
    essential    = true
    portMappings = [{ containerPort = 8100, protocol = "tcp" }]
    environment = [for k, v in merge(local.base_env, local.gitleaks_env, {
      FORGD_ROLE = "collect"
    }) : { name = k, value = v }]
    secrets          = [for k, arn in local.role_secrets["collector"] : { name = k, valueFrom = arn }]
    logConfiguration = local.log_config["collector"]
    healthCheck      = var.dashboard_admins_enabled ? local.container_check["collector"] : local.livez_check["collector"]
  }])

  lifecycle {
    precondition {
      condition     = length(local.otel_tokens_without_org) == 0
      error_message = "otel_token_secret_arns.${join(", otel_token_secret_arns.", local.otel_tokens_without_org)} has no non-empty org_ids entry under the same FORGD_ORG_ID_<NAME>. The collector cross-checks a batch's organization.id against that id, and with none the check cannot run, so any organization's batch is accepted on the token. Add the org's id to org_ids."
    }

    precondition {
      condition     = length(local.otel_fleet_problems) == 0
      error_message = "${join("; ", local.otel_fleet_problems)}. The collector accepts a fleet token only for orgs it holds ids for, so every org in a fleet needs its org_ids entry."
    }
  }
}

# --- the dashboard -------------------------------------------------------
#
# The READER role, and NO hash salt. The dashboard reads every finding hash,
# so giving it the salt would put the key beside the data it protects -- one
# compromise yielding both.
resource "aws_ecs_task_definition" "dashboard" {
  family                   = "${var.name_prefix}-dashboard"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution["dashboard"].arn
  # With dashboard_admins_enabled, store-s3's control role: the reader's
  # policy plus the runtime overrides writes.
  task_role_arn = var.dashboard_admins_enabled ? var.control_role_arn : var.reader_role_arn
  tags          = var.tags

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # oidc_jwt with platform alb_oidc overrides whatever policy.yaml says about
  # dashboard auth, so one policy can serve a Container Apps deployment on
  # trusted_header and this one. The app refuses to start if the ARN,
  # issuer or audience is missing.
  container_definitions = jsonencode([merge({
    name         = "dashboard"
    image        = var.image
    essential    = true
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]
    environment = [for k, v in merge(local.base_env, {
      FORGD_ROLE                = "dashboard"
      FORGD_DASHBOARD_AUTH_MODE = "oidc_jwt"
      FORGD_DASHBOARD_PLATFORM  = "alb_oidc"
      FORGD_DASHBOARD_ALB_ARN   = aws_lb.this.arn
      FORGD_DASHBOARD_ISSUER    = var.oidc_issuer
      # ALB tokens carry no `aud`. The client id in their `client` header
      # stands in for it.
      FORGD_DASHBOARD_AUDIENCE = var.oidc_client_id
    }, local.dashboard_evidence_env) : { name = k, value = v }]
    logConfiguration = local.log_config["dashboard"]
    }, length(local.role_secrets["dashboard"]) == 0 ? {} : {
    secrets = [for k, arn in local.role_secrets["dashboard"] : { name = k, valueFrom = arn }]
    }, var.dashboard_admins_enabled ? {
    healthCheck = local.container_check["dashboard"]
  } : {})])

  lifecycle {
    precondition {
      condition     = !var.dashboard_admins_enabled || var.overrides_writer_lockout
      error_message = "dashboard_admins_enabled needs overrides_writer_lockout = true: store-s3's overrides_writer_lockout output, which is true only with control_enabled. Without it the writer identities can write the runtime overrides object and audit prefix, and so forge an override."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || contains(var.overrides_writer_identities, var.writer_role_arn)
      error_message = "dashboard_admins_enabled needs overrides_writer_identities, store-s3's overrides_writer_identities output, including writer_role_arn. The dashboard verifies each writer's lockout from the bucket policy, and adopts no runtime override while a writer it runs is unverified."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || var.control_role_arn != ""
      error_message = "dashboard_admins_enabled needs control_role_arn: store-s3's control_role_arn, with control_enabled."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || !contains([var.reader_role_arn, var.writer_role_arn], var.control_role_arn)
      error_message = "control_role_arn equals reader_role_arn or writer_role_arn. The reader must stay read-only for the other services that hold it, and the writer can rewrite the findings; the dashboard's control role must be its own."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || var.dashboard_form_key_secret_arn != ""
      error_message = "dashboard_admins_enabled needs dashboard_form_key_secret_arn, the secret holding FORGD_DASHBOARD_FORM_KEY. The dashboard refuses to start with admins configured and no form key."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || var.dashboard_signing_key_secret_arn != ""
      error_message = "dashboard_admins_enabled needs dashboard_signing_key_secret_arn, the secret holding FORGD_OVERRIDES_SIGNING_KEY. The dashboard signs every runtime-override record with it and refuses to start without it."
    }
    precondition {
      condition     = !var.dashboard_admins_enabled || length(var.overrides_verify_keys) > 0
      error_message = "dashboard_admins_enabled needs overrides_verify_keys, the public keys every service verifies runtime-override records with, as FORGD_OVERRIDES_VERIFY_KEY. With none, every service that reads the runtime overrides reports verify_key_misconfigured and does not read them."
    }
  }
}

# --- adapter 2's receiving end: intake -----------------------------------
#
# Laptops POST spooled findings here with their fleet's bearer token, so
# they need no store credential. It also serves /scan, which a
# developer's hook waits on, so it gets the daemon and the deployment salt:
# records written on /scan are hashed HERE, and unsalted a bare sha256 of an
# SSN is about a billion guesses.
resource "aws_ecs_task_definition" "intake" {
  count = var.enable_intake ? 1 : 0

  family                   = "${var.name_prefix}-intake"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.execution["intake"].arn
  task_role_arn            = local.writer_identity["intake"]
  tags                     = var.tags

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  container_definitions = jsonencode([{
    name         = "intake"
    image        = var.image
    essential    = true
    portMappings = [{ containerPort = 8200, protocol = "tcp" }]
    environment = [for k, v in merge(local.base_env, local.gitleaks_env, {
      FORGD_ROLE = "intake"
    }) : { name = k, value = v }]
    secrets          = [for k, arn in local.role_secrets["intake"] : { name = k, valueFrom = arn }]
    logConfiguration = local.log_config["intake"]
    healthCheck      = var.dashboard_admins_enabled ? local.container_check["intake"] : local.livez_check["intake"]
  }])
}

# --- the findings connector ----------------------------------------------
#
# A read-only MCP server over the findings store, added to a Claude
# organization as a custom connector. See docs/CONNECTOR.md. Off unless
# connector_enabled. The READER role, like the dashboard, and no hash salt
# and no secret.
locals {
  connector_resource = var.connector_resource == "" ? "https://${var.connector_host}/mcp" : var.connector_resource
  # A malformed connector_resource is refused by the https, lowercase and
  # /mcp checks, so the host check reports only a well-formed URL on the
  # wrong host.
  connector_resource_malformed = !(startswith(var.connector_resource, "https://") && endswith(var.connector_resource, "/mcp") && var.connector_resource == lower(var.connector_resource))

  connector_env = merge(
    {
      FORGD_ROLE                = "connector"
      FORGD_CONNECTOR_ENABLED   = "true"
      FORGD_CONNECTOR_RESOURCE  = local.connector_resource
      FORGD_CONNECTOR_AUTH_MODE = "oidc_jwt"
    },
    # Lists as JSON, because an environment variable cannot carry a list.
    length(var.connector_scopes) == 0 ? {} : { FORGD_CONNECTOR_SCOPES = jsonencode(var.connector_scopes) },
    var.connector_required_scope == "" ? {} : { FORGD_CONNECTOR_REQUIRED_SCOPE = var.connector_required_scope },
    length(var.connector_allowed_origins) == 0 ? {} : { FORGD_CONNECTOR_ALLOWED_ORIGINS = jsonencode(var.connector_allowed_origins) },
    var.connector_issuer == "" ? {} : { FORGD_CONNECTOR_ISSUER = var.connector_issuer },
    var.connector_jwks_url == "" ? {} : { FORGD_CONNECTOR_JWKS_URL = var.connector_jwks_url },
    length(var.connector_audience) == 0 ? {} : { FORGD_CONNECTOR_AUDIENCE = jsonencode(var.connector_audience) },
    var.connector_groups_claim == "" ? {} : { FORGD_CONNECTOR_GROUPS_CLAIM = var.connector_groups_claim },
    length(var.connector_issuers) == 0 ? {} : { FORGD_CONNECTOR_ISSUERS = jsonencode(var.connector_issuers) },
  )
}

resource "aws_ecs_task_definition" "connector" {
  count = var.connector_enabled ? 1 : 0

  family                   = "${var.name_prefix}-connector"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution["connector"].arn
  task_role_arn            = var.reader_role_arn
  tags                     = var.tags

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  container_definitions = jsonencode([merge({
    name             = "connector"
    image            = var.image
    essential        = true
    portMappings     = [{ containerPort = 8090, protocol = "tcp" }]
    environment      = [for k, v in merge(local.base_env, local.connector_env) : { name = k, value = v }]
    logConfiguration = local.log_config["connector"]
    }, var.dashboard_admins_enabled ? {
    healthCheck = local.container_check["connector"]
  } : {})])

  lifecycle {
    precondition {
      condition     = var.connector_host != ""
      error_message = "connector_enabled is true but connector_host is empty. The connector is routed by host like every other service."
    }
    precondition {
      condition     = length(var.connector_issuers) > 0 || var.connector_issuer != ""
      error_message = "connector_enabled but connector_issuer is empty. The connector accepts only tokens from your identity provider and refuses to start without issuer, jwks_url and audience."
    }
    precondition {
      condition     = length(var.connector_issuers) > 0 || var.connector_jwks_url != ""
      error_message = "connector_enabled but connector_jwks_url is empty. The connector accepts only tokens from your identity provider and refuses to start without issuer, jwks_url and audience."
    }
    precondition {
      condition     = length(var.connector_issuers) > 0 || length(var.connector_audience) > 0
      error_message = "connector_enabled but connector_audience is empty. The connector accepts only tokens from your identity provider and refuses to start without issuer, jwks_url and audience."
    }
    precondition {
      condition     = length(var.connector_issuers) == 0 || (var.connector_issuer == "" && var.connector_jwks_url == "" && length(var.connector_audience) == 0)
      error_message = "Set either connector_issuers or connector_issuer, connector_jwks_url and connector_audience, not both. The connector refuses a partial single issuer beside a list."
    }
    precondition {
      condition     = alltrue([for i in var.connector_issuers : i.issuer != "" && i.jwks_url != "" && length(i.audience) > 0])
      error_message = "A connector_issuers entry has an empty issuer, jwks_url or audience; the connector refuses to start without them, because an unset audience would accept tokens minted for another application."
    }
    precondition {
      condition     = var.connector_required_scope != "" || !contains(["", "$"], substr(try(trimspace(tostring(yamldecode(var.policy_yaml).connector.required_scope)), ""), 0, 1))
      error_message = "connector_required_scope is empty. Without it any token whose audience matches is accepted, including an ID token or a dashboard token from the same app registration. Set it to the scope your identity provider issues for the connector, for example findings.read. A $VAR placeholder in the policy does not count: this module sets no such variable on the connector."
    }
    precondition {
      condition     = var.connector_resource == "" || startswith(var.connector_resource, "https://")
      error_message = "connector_resource must be an https URL."
    }
    precondition {
      condition     = var.connector_resource == lower(var.connector_resource)
      error_message = "connector_resource must be lowercase: Claude sends the canonical form, lowercase host included, and the app refuses anything else."
    }
    precondition {
      condition     = var.connector_resource == "" || endswith(var.connector_resource, "/mcp")
      error_message = "connector_resource must end in /mcp, the path the connector serves."
    }
    precondition {
      condition     = local.connector_resource_malformed || var.connector_resource == "" || var.connector_resource == "https://${var.connector_host}/mcp"
      error_message = "connector_resource does not match https://<connector_host>/mcp, where the ALB serves the connector. Claude checks the metadata's resource against the URL it was given, so the two must match; leave connector_resource empty to derive it."
    }
  }
}

# --- adapter 3: the ingest task ------------------------------------------
resource "aws_ecs_task_definition" "ingest" {
  family                   = "${var.name_prefix}-ingest"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  # 2 vCPU / 4 GB, not the 1/2 the online services get: this is the only
  # adapter that runs Presidio, and en_core_web_lg is ~1 GB resident on top
  # of a 1.4 GB image.
  cpu                = 2048
  memory             = 4096
  execution_role_arn = aws_iam_role.execution["ingest"].arn
  task_role_arn      = local.writer_identity["ingest"]
  tags               = var.tags

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # No volume: the ingest cursor lives in the findings store, and a
  # scheduled task gets a fresh filesystem every run.
  container_definitions = jsonencode([{
    name = "ingest"
    # The -ingest variant. A task on the base image runs, finds nothing at
    # T2 because the tier is `auto` and the dependency is absent, and
    # reports it as a clean scan.
    image     = var.ingest_image
    essential = true
    environment = [for k, v in merge(local.base_env, {
      FORGD_ROLE        = "ingest"
      FORGD_INGEST_ARGS = "--family local"
    }) : { name = k, value = v }]
    secrets          = [for k, arn in local.role_secrets["ingest"] : { name = k, valueFrom = arn }]
    logConfiguration = local.log_config["ingest"]
  }])
}

# --- services ------------------------------------------------------------
#
# CI rolls images; Terraform registers the first revision and then keeps out
# of the way. See docs/DESIGN.md -- routing a release through `terraform
# apply` buys a state lock and a plan to change one field.
#
# ECS cannot ignore only the image: it lives inside the task definition's
# JSON. So each service ignores `task_definition`, the nearest equivalent,
# and that has a cost Container Apps does not. A Terraform change to a task
# definition -- the policy, an env value, a secret -- registers a new
# revision that the running service does not pick up, and that revision
# carries `var.image`, the FIRST image. A release must derive its revision
# from the latest in the family and swap the image, or it drops the change;
# pointing a service at the family's latest by hand rolls the image back.

resource "aws_ecs_service" "verdict" {
  name            = "${var.name_prefix}-verdict"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.verdict.arn
  launch_type     = "FARGATE"
  propagate_tags  = "SERVICE"
  tags            = var.tags

  # 1: the org's verdict timeout covers connection
  # through response, so a cold start on the first governed prompt after an
  # idle period is a WEBHOOK FAILURE rather than a slow allow, and repeated
  # ones trip the circuit breaker.
  #
  # And not more than 1, because the session cache and the webhook-id dedupe
  # store are per-process: spreading frames across tasks makes the latency
  # numbers meaningless. Raise it deliberately, not by default.
  desired_count = 1

  # 100 / 200: a roll starts the new task before stopping the old, so two
  # run briefly. The alternative is a moment with none, which is the cold
  # start above.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  # gitleaksd compiles its rule set before the socket appears, and the
  # entrypoint binds the app only after it does -- up to 60 s on a
  # throttled task.
  health_check_grace_period_seconds = 120

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.task["verdict"].id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this["verdict"].arn
    container_name   = "verdict"
    container_port   = 8000
  }

  depends_on = [aws_lb_listener_rule.verdict, aws_iam_role_policy.execution]

  lifecycle {
    precondition {
      condition     = var.webhook_secret_arn != "" || length(var.webhook_secret_arns) > 0
      error_message = "webhook_secret_arn is empty and webhook_secret_arns names no org: the verdict server would have no signing secret, and the signature check is the only thing authenticating Anthropic."
    }
    precondition {
      condition     = var.compliance_key_secret_arn != "" || length(var.compliance_key_secret_arns) > 0
      error_message = "compliance_key_secret_arn is empty and compliance_key_secret_arns names no org: the ingest job would have no key."
    }
    precondition {
      condition     = length(local.org_secret_problems) == 0
      error_message = "${join("; ", local.org_secret_problems)}."
    }
    ignore_changes = [task_definition]
  }
}

resource "aws_ecs_service" "collector" {
  name            = "${var.name_prefix}-collector"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.collector.arn
  launch_type     = "FARGATE"
  propagate_tags  = "SERVICE"
  tags            = var.tags

  # An exporter has a timeout and drops or retries a batch that does not
  # answer, so a gap costs telemetry. 1 because the store sink queue is
  # per-process, and backpressure -- the 503 that makes an exporter hold its
  # batch -- only means anything with one queue.
  desired_count                      = 1
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 120

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.task["collector"].id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this["collector"].arn
    container_name   = "collector"
    container_port   = 8100
  }

  depends_on = [aws_lb_listener_rule.collector, aws_iam_role_policy.execution]

  lifecycle {
    ignore_changes = [task_definition]
  }
}

resource "aws_ecs_service" "dashboard" {
  name            = "${var.name_prefix}-dashboard"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.dashboard.arn
  launch_type     = "FARGATE"
  propagate_tags  = "SERVICE"
  tags            = var.tags

  desired_count                      = 1
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 60

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.task["dashboard"].id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this["dashboard"].arn
    container_name   = "dashboard"
    container_port   = 8080
  }

  depends_on = [aws_lb_listener_rule.dashboard, aws_lb_listener_rule.dashboard_healthz, aws_iam_role_policy.execution]

  lifecycle {
    ignore_changes = [task_definition]
  }
}

resource "aws_ecs_service" "intake" {
  count = var.enable_intake ? 1 : 0

  name            = "${var.name_prefix}-intake"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.intake[0].arn
  launch_type     = "FARGATE"
  propagate_tags  = "SERVICE"
  tags            = var.tags

  # A developer's hook waits on /scan inside a 200 ms budget and falls back
  # to scanning locally when it cannot connect, so a gap is silent.
  desired_count                      = 1
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 120

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.task["intake"].id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this["intake"].arn
    container_name   = "intake"
    container_port   = 8200
  }

  depends_on = [aws_lb_listener_rule.intake, aws_iam_role_policy.execution]

  lifecycle {
    ignore_changes = [task_definition]
  }
}

resource "aws_ecs_service" "connector" {
  count = var.connector_enabled ? 1 : 0

  name            = "${var.name_prefix}-connector"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.connector[0].arn
  launch_type     = "FARGATE"
  propagate_tags  = "SERVICE"
  tags            = var.tags

  desired_count                      = 1
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 60

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.task["connector"].id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this["connector"].arn
    container_name   = "connector"
    container_port   = 8090
  }

  depends_on = [aws_lb_listener_rule.connector, aws_iam_role_policy.execution]

  lifecycle {
    ignore_changes = [task_definition]
  }
}

# --- the ingest schedule -------------------------------------------------
#
# EventBridge Scheduler runs the task; it needs a role of its own to call
# RunTask and to pass the two roles the task runs with. It is not a task
# identity and holds no store permission.
resource "aws_iam_role" "scheduler" {
  name = "${var.name_prefix}-ingest-scheduler"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "run-ingest"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Any revision of the ingest family, because CI registers new ones.
        Effect   = "Allow"
        Action   = "ecs:RunTask"
        Resource = "arn:${local.partition}:ecs:${local.region}:${local.account_id}:task-definition/${aws_ecs_task_definition.ingest.family}:*"
        Condition = { ArnEquals = {
          "ecs:cluster" = aws_ecs_cluster.this.arn
        } }
      },
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = [aws_iam_role.execution["ingest"].arn, var.writer_role_arn]
        Condition = { StringEquals = {
          "iam:PassedToService" = "ecs-tasks.amazonaws.com"
        } }
      },
    ]
  })
}

# One pass walks every session updated since the last run plus every
# claude.ai chat. ECS has no task timeout, unlike the Container Apps job's
# 3600 s; a pass that hangs runs until someone stops it.
resource "aws_scheduler_schedule" "ingest" {
  name                         = "${var.name_prefix}-ingest"
  schedule_expression          = var.ingest_schedule
  schedule_expression_timezone = var.ingest_schedule_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_ecs_cluster.this.arn
    role_arn = aws_iam_role.scheduler.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.ingest.arn
      launch_type         = "FARGATE"
      task_count          = 1

      network_configuration {
        subnets          = var.subnet_ids
        security_groups  = [aws_security_group.task["ingest"].id]
        assign_public_ip = false
      }
    }
  }

  depends_on = [aws_iam_role_policy.execution]

  # CI owns the ingest revision the same way it owns the services'. See the
  # note above the services.
  lifecycle {
    ignore_changes = [target[0].ecs_parameters[0].task_definition_arn]
  }
}
