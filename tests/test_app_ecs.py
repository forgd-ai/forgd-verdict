"""The app-ecs module keeps the properties the Container Apps module keeps.

Parsed from the .tf source, because nothing here may call AWS and a plan
needs credentials. Each check first asserts it found what it is about, so a
rename or a parse that matches nothing fails rather than passing on an
empty list.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "deploy" / "terraform" / "modules" / "app-ecs"
MAIN = MODULE / "main.tf"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

# Environment names whose value is a secret. Any of these in a container's
# plain `environment` is a secret in the task definition, in state and in
# `DescribeTaskDefinition` output, readable by anyone with ecs:Describe*.
SECRET_NAMES = {
    "WEBHOOK_SECRET",
    "WEBHOOK_SECRET_PREVIOUS",
    "FORGD_HASH_SALT",
    "FORGD_METRICS_TOKEN",
    "ANTHROPIC_COMPLIANCE_ACCESS_KEY",
}
SECRET_PREFIXES = ("FORGD_OTEL_TOKEN_", "FORGD_INTAKE_TOKEN_")

# The services Anthropic or a laptop authenticates to by itself.
NO_SIGN_IN = ("verdict", "collector", "intake", "connector")


def _close(text: str, i: int, open_: str, close: str) -> int:
    """Index just past the bracket matching text[i], skipping quoted strings
    (which hold `${...}`) and comments."""
    depth, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "#" or text.startswith("//", i):
            i = text.index("\n", i)
        elif c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AssertionError(f"unbalanced {open_} in {MAIN}")


def _blocks(body: str) -> list[tuple[str, list[str], str]]:
    """The blocks directly inside `body`: (type, labels, inner text)."""
    out, i = [], 0
    header = re.compile(r'^\s*(\w+)((?:\s+"[^"]*")*)\s*\{', re.M)
    while True:
        m = header.search(body, i)
        if m is None:
            return out
        end = _close(body, m.end() - 1, "{", "}")
        out.append((m.group(1), re.findall(r'"([^"]*)"', m.group(2)), body[m.end():end - 1]))
        i = end


def _walk(body: str, kind: str) -> list[str]:
    """Every block of type `kind` at any depth."""
    found = []
    for k, _, inner in _blocks(body):
        if k == kind:
            found.append(inner)
        found.extend(_walk(inner, kind))
    return found


def _top_level(body: str) -> str:
    """`body` with every nested block removed, leaving its own attributes."""
    for _, _, inner in _blocks(body):
        body = body.replace("{" + inner + "}", "{}", 1)
    return body


def _attr(body: str, name: str) -> str | None:
    m = re.search(rf"^\s*{name}\s*=\s*(.+)$", _top_level(body), re.M)
    return m.group(1).strip() if m else None


def _resources(kind: str) -> dict[str, str]:
    text = MAIN.read_text(encoding="utf-8")
    return {labels[1]: inner for k, labels, inner in _blocks(text)
            if k == "resource" and labels[0] == kind}


def _locals() -> dict[str, str]:
    """name -> the expression text, for every local in main.tf."""
    text = MAIN.read_text(encoding="utf-8")
    out = {}
    for body in (inner for k, _, inner in _blocks(text) if k == "locals"):
        starts = list(re.finditer(r"^  (\w+)\s*=", body, re.M))
        out |= {
            m.group(1): body[m.end():(starts[i + 1].start() if i + 1 < len(starts) else len(body))]
            for i, m in enumerate(starts)
        }
    return out


def _bracket(body: str, name: str) -> str:
    """The text of `name = [ ... ]` inside `body`."""
    m = re.search(rf"\b{name}\s*=\s*\[", body)
    assert m, f"no {name} list"
    return body[m.end():_close(body, m.end() - 1, "[", "]") - 1]


def _is_secret(name: str) -> bool:
    return name in SECRET_NAMES or name.startswith(SECRET_PREFIXES)


# --- the shape of the module ---------------------------------------------

def test_the_module_is_exactly_main_variables_and_outputs():
    """Every check here reads main.tf. A resource in a fourth file, or in
    variables.tf or outputs.tf, is one none of them sees."""
    assert sorted(f.name for f in MODULE.glob("*.tf")) == ["main.tf", "outputs.tf", "variables.tf"]
    for other in ("outputs.tf", "variables.tf"):
        text = (MODULE / other).read_text(encoding="utf-8")
        assert not re.search(r'^\s*(resource|data|locals)\b', text, re.M), other


# --- routing and sign-in -------------------------------------------------

def _rules() -> dict[str, dict]:
    out = {}
    for name, body in _resources("aws_lb_listener_rule").items():
        actions = _walk(body, "action")
        out[name] = {
            "priority": int(_attr(body, "priority")),
            "types": [re.search(r'type\s*=\s*"([^"]+)"', a).group(1) for a in actions],
            "targets": [t for a in actions
                        for t in re.findall(r'aws_lb_target_group\.this\["(\w+)"\]', a)],
            "hosts": [v for c in _walk(body, "host_header") for v in re.findall(r"var\.\w+", c)],
            "paths": [v for c in _walk(body, "path_pattern") for v in re.findall(r'"([^"]*)"', c)],
        }
    return out


def test_no_rule_signs_in_on_the_way_to_verdict_collector_or_intake():
    """Anthropic signs its webhook and authenticates its OTLP export, and a
    laptop sends a bearer token. An ALB sign-in redirect in front of any of
    them turns every governed prompt, export or upload into a delivery
    failure."""
    rules = _rules()
    for svc in NO_SIGN_IN:
        forwarding = [r for r in rules.values() if svc in r["targets"]]
        assert forwarding, f"no rule forwards to {svc}"
        for r in forwarding:
            assert r["types"] and "authenticate-oidc" not in r["types"], (svc, r)

    # The parser does see authenticate-oidc where it belongs, so its
    # absence above is not a parse that read nothing.
    assert any("authenticate-oidc" in r["types"] for r in rules.values())
    # And the dashboard is the only place it appears in the file, including
    # a listener's default action.
    text = MAIN.read_text(encoding="utf-8")
    in_rules = sum(r["types"].count("authenticate-oidc") for r in rules.values()
                   if set(r["targets"]) == {"dashboard"})
    assert text.count('"authenticate-oidc"') == in_rules == 1


def test_the_dashboard_has_an_unauthenticated_healthz_rule_ahead_of_sign_in():
    """The deploy gate probes /healthz first. Behind sign-in the probe is
    redirected, verify_deployment.sh fails `dashboard.health` on a healthy
    deployment, and the checks that matter never run."""
    rules = _rules()
    sign_in = [r for r in rules.values() if "authenticate-oidc" in r["types"]]
    assert sign_in and all(r["targets"] == ["dashboard"] for r in sign_in), sign_in
    assert all(r["hosts"] == ["var.dashboard_host"] for r in sign_in), sign_in

    healthz = [
        r for r in rules.values()
        if r["targets"] == ["dashboard"] and r["types"] == ["forward"]
        and r["paths"] == ["/healthz"] and r["hosts"] == ["var.dashboard_host"]
    ]
    assert healthz, "no unauthenticated /healthz rule for the dashboard"
    # Lower number, evaluated first.
    assert all(h["priority"] < s["priority"] for h in healthz for s in sign_in), (healthz, sign_in)


# --- network -------------------------------------------------------------

def test_no_task_gets_a_public_ip():
    """Tasks run in the caller's private subnets and are reached through the
    ALB. A public IP bypasses it, and with it the dashboard's sign-in."""
    text = MAIN.read_text(encoding="utf-8")
    services = _resources("aws_ecs_service")
    schedules = _resources("aws_scheduler_schedule")
    assert sorted(services) == ["collector", "connector", "dashboard", "intake", "verdict"], sorted(services)
    assert sorted(schedules) == ["ingest"], sorted(schedules)

    for name, body in {**services, **schedules}.items():
        configs = _walk(body, "network_configuration")
        assert len(configs) == 1, name
        assert _attr(configs[0], "assign_public_ip") == "false", name

    # Nothing else in the file sets it, to anything.
    assert len(re.findall(r"\bassign_public_ip\b", text)) == len(services) + len(schedules)


def test_tasks_accept_traffic_from_the_alb_security_group_only():
    """Not from the VPC, not from each other, not from a CIDR. Anything that
    can reach a task directly skips the ALB, and so skips the dashboard's
    sign-in and the header the dashboard verifies."""
    text = MAIN.read_text(encoding="utf-8")
    # Rules only as standalone resources, which is what is checked below.
    assert not re.search(r'resource\s+"aws_security_group_rule"', text)
    for name, body in _resources("aws_security_group").items():
        assert not _walk(body, "ingress"), f"inline ingress on {name}"

    ingress = _resources("aws_vpc_security_group_ingress_rule")
    on_tasks = {n: b for n, b in ingress.items()
                if (_attr(b, "security_group_id") or "").startswith("aws_security_group.task[")}
    assert on_tasks, "found no task ingress rule"
    for name, body in on_tasks.items():
        assert _attr(body, "referenced_security_group_id") == "aws_security_group.alb.id", name
        for other in ("cidr_ipv4", "cidr_ipv6", "prefix_list_id"):
            assert _attr(body, other) is None, (name, other)

    # Every other ingress rule is on the ALB, so none reaches a task by a
    # security group id this check does not recognise.
    for name, body in ingress.items():
        if name not in on_tasks:
            assert _attr(body, "security_group_id") == "aws_security_group.alb.id", name


# --- secrets -------------------------------------------------------------

def _local_keys(expr: str, defs: dict[str, str], seen: frozenset = frozenset()) -> set[str]:
    """Map keys an expression can produce: literal `NAME = ...` keys, plus
    those of every local it references, recursively."""
    keys = set(re.findall(r"^\s*\{?\s*([A-Z][A-Z0-9_]*)\s*=", expr, re.M))
    keys |= set(re.findall(r"\{\s*([A-Z][A-Z0-9_]*)\s*=", expr))
    # `"FORGD_OTEL_TOKEN_${...}" => arn` builds its keys with a prefix.
    keys |= {p + "*" for p in re.findall(r'"([A-Z][A-Z0-9_]*_)\$\{', expr)}
    for ref in set(re.findall(r"\blocal\.(\w+)", expr)) - seen:
        keys |= _local_keys(defs[ref], defs, seen | {ref})
    return keys


def test_no_secret_is_a_plain_environment_value():
    """A secret goes in `secrets` as `valueFrom`, where the ECS agent fetches
    it at task start. In `environment` it is in the task definition and in
    state, and readable with nothing more than ecs:DescribeTaskDefinition."""
    defs = _locals()
    tasks = _resources("aws_ecs_task_definition")
    assert sorted(tasks) == ["collector", "connector", "dashboard", "ingest", "intake", "verdict"], sorted(tasks)

    for name, body in tasks.items():
        env = _bracket(body, "environment")
        keys = _local_keys(env, defs)
        # Not vacuous: every role's environment carries its role and the store.
        assert {"FORGD_ROLE", "FORGD_VERDICT_STORE"} <= keys, (name, keys)
        leaked = sorted(k for k in keys if _is_secret(k.rstrip("*")))
        assert not leaked, f"{name} passes {leaked} as plain environment"
        # A secret ARN or value by another name.
        assert not re.search(r"var\.\w*secret", env), (name, env)

    # And the secrets that exist really are passed through `secrets`: the
    # check above is only meaningful if they are somewhere.
    roles = _role_secrets(defs)
    used = set()
    for name in ("verdict", "collector", "intake", "ingest"):
        secrets = _bracket(tasks[name], "secrets")
        assert "valueFrom" in secrets, name
        role = re.search(r'local\.role_secrets\["(\w+)"\]', secrets).group(1)
        used |= _local_keys(roles[role], defs)
    assert used >= SECRET_NAMES, SECRET_NAMES - used
    assert used >= {p + "*" for p in SECRET_PREFIXES}, used


def test_the_verdict_server_always_runs():
    """A cold start on the first governed prompt after an idle period is a
    webhook failure, not a slow allow, and repeated ones trip Anthropic's
    circuit breaker."""
    count = _attr(_resources("aws_ecs_service")["verdict"], "desired_count")
    assert count is not None and count.isdigit(), f"desired_count is {count!r}, not a literal"
    assert int(count) >= 1


# --- releases ------------------------------------------------------------

def _ignored(body: str) -> list[str]:
    """The entries of the one lifecycle block's `ignore_changes` in `body`."""
    lifecycles = _walk(body, "lifecycle")
    assert len(lifecycles) == 1, f"{len(lifecycles)} lifecycle blocks"
    return [e.strip() for e in _bracket(lifecycles[0], "ignore_changes").split(",") if e.strip()]


def test_every_service_leaves_its_task_definition_to_ci():
    """CI registers each release's revision and points the service at it. A
    service that tracks `task_definition` rolls back to the revision in
    Terraform on the next apply."""
    services = _resources("aws_ecs_service")
    assert sorted(services) == ["collector", "connector", "dashboard", "intake", "verdict"], sorted(services)
    for name, body in services.items():
        assert "task_definition" in _ignored(body), name


def test_the_ingest_schedule_leaves_its_task_definition_to_ci():
    """The same for the scheduled ingest task, whose revision sits in the
    schedule's target rather than on a service."""
    schedules = _resources("aws_scheduler_schedule")
    assert sorted(schedules) == ["ingest"], sorted(schedules)
    assert "target[0].ecs_parameters[0].task_definition_arn" in _ignored(schedules["ingest"])


# --- execution roles -----------------------------------------------------

def _role_secrets(defs: dict[str, str]) -> dict[str, str]:
    """role -> the expression role_secrets gives it."""
    return dict(re.findall(r"^\s*(\w+)\s*=\s*(\S.*?)\s*$", defs["role_secrets"], re.M)) | dict(
        re.findall(r"\{\s*(\w+)\s*=\s*(local\.\w+)\s*\}", defs["role_secrets"]))


def test_each_execution_role_reads_only_its_own_tasks_secrets():
    """The ECS agent's role fetches the secrets; the container receives only
    the ones its definition names. A shared role would let the dashboard's
    task identity fetch the webhook secret, the Compliance key and every
    OTel token."""
    defs = _locals()
    text = MAIN.read_text(encoding="utf-8")
    tasks = _resources("aws_ecs_task_definition")

    # Each task runs under the execution role with its own key, and takes
    # its secrets from role_secrets under that same key.
    for name, body in tasks.items():
        assert _attr(body, "execution_role_arn") == f'aws_iam_role.execution["{name}"].arn', name
        refs = set(re.findall(r'local\.\w+(?:\["\w+"\])?', body[body.index("container_definitions"):]))
        secret_refs = {r for r in refs if "secret" in r}
        if name == "connector":
            assert not re.search(r"\bsecrets\s*=", body), f"the {name} is given secrets"
            assert not secret_refs, secret_refs
        else:
            assert secret_refs == {f'local.role_secrets["{name}"]'}, (name, secret_refs)

    roles = _role_secrets(defs)
    # The dashboard's is the form key and the signing key with admins
    # enabled, and nothing otherwise.
    assert roles.get("dashboard") == "local.dashboard_secrets", roles
    assert " ".join(re.sub(r"(?m)^\s*#.*$", "", defs["dashboard_secrets"]).split()) == (
        "var.dashboard_admins_enabled ? { FORGD_DASHBOARD_FORM_KEY = var.dashboard_form_key_secret_arn "
        "FORGD_OVERRIDES_SIGNING_KEY = var.dashboard_signing_key_secret_arn } : {}")
    assert roles.get("verdict") == "local.verdict_secrets", roles
    assert roles.get("ingest") == "local.ingest_secrets", roles

    # The policy grants each role exactly role_secrets[<its key>], and only
    # when that is non-empty -- so the dashboard gets neither a secret read
    # nor a KMS decrypt.
    policies = _resources("aws_iam_role_policy")
    assert sorted(policies) == ["execution", "scheduler"], sorted(policies)
    policy = policies["execution"]
    assert _attr(policy, "role") == "aws_iam_role.execution[each.key].id"
    assert _attr(policy, "for_each") == _attr(_resources("aws_iam_role")["execution"], "for_each")

    assert text.count("secretsmanager:GetSecretValue") == policy.count("secretsmanager:GetSecretValue") == 1
    assert text.count("kms:Decrypt") == policy.count("kms:Decrypt") == 1
    guard = r"length\(local\.role_secrets\[each\.key\]\)\s*==\s*0"
    assert re.search(guard + r'\s*\?\s*\[\]\s*:\s*\[\{\s*Sid\s*=\s*"ReadSecrets"', policy)
    assert re.search(guard + r'\s*\|\|[^?]*\?\s*\[\]\s*:\s*\[\{\s*Sid\s*=\s*"DecryptSecrets"', policy)

    read = policy[policy.index('"ReadSecrets"'):]
    read = read[:read.index("}")]
    resource = re.search(r"Resource\s*=\s*(.+)", read).group(1)
    refs = set(re.findall(r"\b(?:local|var)\.\w+(?:\[[^\]]+\])?", resource))
    assert refs == {"local.role_secrets[each.key]"}, resource

    # And nothing attaches a policy the checks above do not read.
    assert "aws_iam_role_policy_attachment" not in text
    assert "managed_policy_arns" not in text and "inline_policy" not in text


# --- liveness --------------------------------------------------------------

LIVEZ_ROLES = ("verdict", "collector", "intake")


def _container(resource: str) -> str:
    """The text of a task definition's `container_definitions = jsonencode(...)`."""
    body = _resources("aws_ecs_task_definition")[resource]
    m = re.search(r"\bcontainer_definitions\s*=\s*jsonencode\(", body)
    assert m, f"no container_definitions in {resource}"
    return body[m.end():_close(body, m.end() - 1, "(", ")") - 1]


def test_every_service_is_health_checked_with_python():
    """curl is purged from the image, so the check is urllib. urlopen raises
    on a 503, which is the non-zero exit ECS replaces a task on. The daemon
    roles are checked on /livez and then /healthz; the others on /healthz.
    tests/test_app_probes.py checks the rendered commands."""
    check = _locals()["container_check"]
    paths = _locals()["container_check_paths"]
    assert "for r in keys(local.ports)" in paths, paths
    daemon = re.search(r"contains\(\[([^\]]*)\], r\)", paths)
    assert daemon and tuple(re.findall(r'"(\w+)"', daemon.group(1))) == LIVEZ_ROLES, paths
    command = _bracket(check, "command")
    assert '"CMD", "python", "-c"' in command, command
    assert "urllib.request.urlopen('http://127.0.0.1:${local.ports[r]}${path}'" in command
    assert "curl" not in check
    for resource in LIVEZ_ROLES:
        assert (f'healthCheck      = var.dashboard_admins_enabled ? local.container_check["{resource}"] : '
                f'local.livez_check["{resource}"]') in _container(resource), resource
    for resource in ("dashboard", "connector"):
        assert ('}, var.dashboard_admins_enabled ? {\n'
                f'    healthCheck = local.container_check["{resource}"]\n  }} : {{}})]') in _container(resource)


def test_off_the_daemon_roles_are_health_checked_on_livez_with_python():
    """With dashboard admins off, the check each daemon role had before them;
    the dashboard and the connector have none."""
    check = _locals()["livez_check"]
    roles = re.search(r"for r in \[([^\]]*)\]", check)
    assert roles, check
    assert tuple(re.findall(r'"(\w+)"', roles.group(1))) == LIVEZ_ROLES
    command = _bracket(check, "command")
    assert '"CMD", "python", "-c"' in command, command
    assert "urllib.request.urlopen('http://127.0.0.1:${local.ports[r]}/livez'" in command
    assert "curl" not in check


def test_the_health_check_outlasts_the_daemon_compile_and_one_miss():
    """The entrypoint waits up to 60 s for gitleaksd's socket. A check that
    counted failures during that window, or on a single miss, would replace
    a task that was only starting or briefly slow. Both requests fit in the
    check's timeout."""
    check = _locals()["container_check"]
    num = {k: int(re.search(rf"^\s*{k}\s*=\s*(\d+)", check, re.M).group(1))
           for k in ("interval", "timeout", "retries", "startPeriod")}
    urllib_timeout = int(re.search(r"timeout=(\d+)\)", check).group(1))
    assert num["startPeriod"] > 60, num
    assert num["retries"] >= 2, num
    assert 2 * urllib_timeout < num["timeout"] < num["interval"], (urllib_timeout, num)


def test_ingest_has_no_health_check():
    """Ingest is a task that exits, and serves nothing."""
    assert "healthCheck" not in _container("ingest")


# --- the findings connector ------------------------------------------------

CONNECTOR_LOCALS = {"connector_resource", "connector_resource_malformed", "connector_env"}
CONNECTOR_RESOURCES = ["aws_ecs_service.connector", "aws_ecs_task_definition.connector",
                       "aws_lb_listener_rule.connector"]
# Every for_each resource keyed by role or service, which the connector joins.
KEYED_RESOURCES = ["aws_cloudwatch_log_group.this", "aws_iam_role.execution", "aws_iam_role_policy.execution",
                   "aws_lb_target_group.this", "aws_security_group.task",
                   "aws_vpc_security_group_egress_rule.task", "aws_vpc_security_group_ingress_rule.task_from_alb"]

# The pre-existing text the connector changes: (now, before).
MAIN_EDITS = [
    ("}, var.enable_intake ? { intake = local.intake_all } : {}, var.connector_enabled ? { connector = {} } : {})",
     "}, var.enable_intake ? { intake = local.intake_all } : {})"),
    ('roles = concat(var.enable_intake ? ["verdict", "collector", "dashboard", "intake", "ingest"] : '
     '["verdict", "collector", "dashboard", "ingest"], var.connector_enabled ? ["connector"] : [])',
     'roles = var.enable_intake ? ["verdict", "collector", "dashboard", "intake", "ingest"] : '
     '["verdict", "collector", "dashboard", "ingest"]'),
    ("ports = merge({", "ports = {"),
    ("  }, var.connector_enabled ? { connector = 8090 } : {})", "  }"),
    ("hosts = merge({", "hosts = {"),
    ("  }, var.connector_enabled ? { connector = var.connector_host } : {})", "  }"),
    ('services = concat(var.enable_intake ? ["verdict", "collector", "dashboard", "intake"] : '
     '["verdict", "collector", "dashboard"], var.connector_enabled ? ["connector"] : [])',
     'services = var.enable_intake ? ["verdict", "collector", "dashboard", "intake"] : '
     '["verdict", "collector", "dashboard"]'),
    ("dashboard_host, (with enable_intake) intake_host and (with connector_enabled) connector_host must",
     "dashboard_host and (with enable_intake) intake_host must"),
]
OUTPUT_EDITS = [
    ("  value = merge({\n    verdict   = aws_ecs_service.verdict.name",
     "  value = {\n    verdict   = aws_ecs_service.verdict.name"),
    ("  }, var.connector_enabled ? { connector = aws_ecs_service.connector[0].name } : {})", "  }"),
    ("  value = merge({\n    verdict   = aws_ecs_task_definition.verdict.family",
     "  value = {\n    verdict   = aws_ecs_task_definition.verdict.family"),
    ("  }, var.connector_enabled ? { connector = aws_ecs_task_definition.connector[0].family } : {})", "  }"),
    ("aws_ecs_service.intake, aws_ecs_service.connector) : s.id]", "aws_ecs_service.intake) : s.id]"),
    ("        var.connector_enabled ? aws_ecs_task_definition.connector[0].family : null,\n", ""),
]

ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:"
HOST = "mcp.example.com"
REQUIRED = {
    "vpc_id": "vpc-1", "subnet_ids": ["subnet-a"], "public_subnet_ids": ["subnet-p"],
    "certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/x",
    "verdict_host": "verdict.example.com", "collector_host": "collector.example.com",
    "dashboard_host": "dashboard.example.com",
    "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/fv:1",
    "ingest_image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/fv:1-ingest",
    "writer_role_arn": "arn:aws:iam::123456789012:role/writer",
    "reader_role_arn": "arn:aws:iam::123456789012:role/reader",
    "store_url": "s3://findings", "hash_salt_secret_arn": ARN + "salt-AbCdEf",
    "webhook_secret_arn": ARN + "webhook-AbCdEf", "otel_token_secret_arns": {"primary": ARN + "otel-AbCdEf"},
    "org_ids": {"primary": "00000000-0000-0000-0000-00000000000a"},
    "compliance_key_secret_arn": ARN + "compliance-AbCdEf",
    "oidc_issuer": "https://idp.example.com", "oidc_authorization_endpoint": "https://idp.example.com/a",
    "oidc_token_endpoint": "https://idp.example.com/t", "oidc_user_info_endpoint": "https://idp.example.com/u",
    "oidc_client_id": "client", "oidc_client_secret": "not-a-secret", "policy_yaml": "version: 1\n",
}
ON = {
    "connector_enabled": True, "connector_host": HOST,
    "connector_issuer": "https://login.example.com/tenant/v2.0",
    "connector_jwks_url": "https://login.example.com/tenant/discovery/v2.0/keys",
    "connector_audience": ["api-client-id"],
    "connector_required_scope": "findings.read",
}
ALL = {**ON, "connector_scopes": ["findings.read"], "connector_allowed_origins": ["https://claude.ai"],
       "connector_groups_claim": "roles",
       "connector_issuers": [{"issuer": ON["connector_issuer"], "jwks_url": ON["connector_jwks_url"],
                              "audience": ["api-client-id"]}]}
DERIVED = f"https://{HOST}/mcp"
REF = re.compile(r"\b(?:data\.)?aws_\w+\.\w+(?:\[[^\]]+\])?(?:\.\w+(?:\[\d+\])?)*")


def _files() -> dict[str, str]:
    return {n: (MODULE / n).read_text(encoding="utf-8") for n in ("main.tf", "variables.tf", "outputs.tf")}


def _revert(text: str, edits: list[tuple[str, str]]) -> str:
    for now, before in edits:
        assert text.count(now) == 1, now
        text = text.replace(now, before)
    return text


def _left_out() -> dict[str, str]:
    """The module's three files with the connector's blocks and settings
    removed and every pre-existing expression it changes as it was."""
    import test_app_aca as aca
    files = _files()
    main = aca._without(files["main.tf"], lambda k, labels, inner: (
        k == "locals" and set(re.findall(r"^  (\w+)\s*=", inner, re.M)) <= CONNECTOR_LOCALS)
        or (k == "resource" and ".".join(labels) in CONNECTOR_RESOURCES))
    variables = aca._without(files["variables.tf"],
                             lambda k, labels, _: k == "variable" and labels[0].startswith("connector_"))
    outputs = aca._without(files["outputs.tf"], lambda k, labels, _: k == "output" and labels == ["connector_url"])
    return {"main.tf": _revert(main, MAIN_EDITS), "variables.tf": variables,
            "outputs.tf": _revert(outputs, OUTPUT_EDITS)}


def _evaluate(root: Path, files: dict[str, str], **variables) -> dict:
    import test_app_aca as aca
    return aca._evaluate(root, files, required=REQUIRED, ref=REF, **variables)


def _connector_task() -> str:
    return _resources("aws_ecs_task_definition")["connector"]


def test_the_connector_is_off_by_default_and_every_setting_has_a_default():
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    bodies = {labels[0]: inner for k, labels, inner in _blocks(variables) if k == "variable"}
    connector = sorted(n for n in bodies if n.startswith("connector_"))
    assert len(connector) == 12, connector
    assert _attr(bodies["connector_enabled"], "default") == "false"
    assert _attr(bodies["connector_source_ranges"], "default") == "[]"
    for name in connector:
        assert _attr(bodies[name], "default") is not None, name


def test_leaving_the_connector_out_removes_every_mention_of_it():
    for name, text in _left_out().items():
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        assert "connector" not in code, name


def test_nothing_else_reads_a_connector_setting():
    """Outside the connector's own blocks, only the edits listed above."""
    import test_app_aca as aca
    ref = re.compile(r"var\.connector_|local\.connector_|\.connector\b|\.connector\[")
    edited_locals = {"role_secrets", "roles", "ports", "hosts", "services"}
    own = []
    for k, labels, inner in _blocks(MAIN.read_text(encoding="utf-8")):
        if k == "locals":
            for name, expr in aca._assignments(inner).items():
                if name not in CONNECTOR_LOCALS | edited_locals:
                    assert not ref.search(expr), name
        elif ref.search(inner):
            own.append(".".join(labels))
    assert sorted(own) == CONNECTOR_RESOURCES, own
    for name in CONNECTOR_RESOURCES:
        kind, label = name.split(".")
        assert _attr(_resources(kind)[label], "count") == "var.connector_enabled ? 1 : 0", name
    outputs = {labels[0]: inner for k, labels, inner in
               _blocks((MODULE / "outputs.tf").read_text(encoding="utf-8")) if k == "output"}
    uses = sorted(n for n, body in outputs.items() if ref.search(body))
    assert uses == ["ci_release", "connector_url", "service_names", "task_definition_families"], uses
    assert _attr(outputs["connector_url"], "value") == "var.connector_enabled ? local.connector_resource : null"


@requires_terraform
@pytest.mark.parametrize("intake", [False, True])
def test_off_evaluates_exactly_as_the_module_with_the_connector_left_out(tmp_path, intake):
    extra = {"enable_intake": intake, "intake_host": "intake.example.com" if intake else "",
             "org_ids": {"primary": "00000000-0000-0000-0000-00000000000a", "prod": "00000000-0000-0000-0000-00000000000b"},
             "metrics_token_secret_arn": ARN + "metrics-AbCdEf"}
    got = _evaluate(tmp_path / "off", _files(), **extra)
    before = _evaluate(tmp_path / "left-out", _left_out(), **extra)
    assert {k: v for k, v in got["locals"].items() if k not in CONNECTOR_LOCALS} == before["locals"]
    assert {k: v for k, v in got["resources"].items() if k not in CONNECTOR_RESOURCES} == before["resources"]
    assert all(got["resources"][r] == [] for r in CONNECTOR_RESOURCES), got["resources"]
    rest = lambda d: {k: v for k, v in d.items() if k not in ("locals", "resources")}  # noqa: E731
    assert rest(got) == rest(before)
    assert "o_connector_url" not in got


@requires_terraform
def test_on_adds_the_connector_to_every_role_keyed_resource_and_to_the_release(tmp_path):
    got = _evaluate(tmp_path / "on", _files(), **ON)
    before = _evaluate(tmp_path / "left-out", _left_out())
    want = {**before["resources"], **{r: ["0"] for r in CONNECTOR_RESOURCES},
            **{r: sorted([*before["resources"][r], "connector"]) for r in KEYED_RESOURCES}}
    assert got["resources"] == want
    # No secret for its execution role to read.
    assert got["locals"]["role_secrets"]["connector"] == {}
    assert got["locals"]["ports"]["connector"] == 8090
    assert got["locals"]["service_hosts"] == [*before["locals"]["service_hosts"], HOST]
    assert got["o_service_names"] == {**before["o_service_names"], "connector": "ref"}
    assert got["o_task_definition_families"] == {**before["o_task_definition_families"], "connector": "ref"}
    release, was = got["o_ci_release"], before["o_ci_release"]
    assert len(release["service_arns"]) == len(was["service_arns"]) + 1
    assert len(release["task_definition_arns"]) == len(was["task_definition_arns"]) + 1
    assert got["o_connector_url"] == DERIVED


def test_the_release_rolls_the_connector_like_the_other_services():
    outputs = (MODULE / "outputs.tf").read_text(encoding="utf-8")
    assert "var.connector_enabled ? aws_ecs_task_definition.connector[0].family : null" in outputs
    assert "aws_ecs_service.intake, aws_ecs_service.connector) : s.id]" in outputs
    assert "task_definition" in _ignored(_resources("aws_ecs_service")["connector"])


def test_its_rule_forwards_with_no_sign_in():
    rule = _rules()["connector"]
    assert rule["types"] == ["forward"] and rule["targets"] == ["connector"], rule
    assert rule["hosts"] == ["var.connector_host"], rule
    priorities = [r["priority"] for r in _rules().values()]
    assert len(set(priorities)) == len(priorities), priorities
    body = _resources("aws_lb_listener_rule")["connector"]
    assert "authenticate" not in body


def test_the_source_allowlist_is_a_rule_condition_only_when_given():
    body = _resources("aws_lb_listener_rule")["connector"]
    [(labels, inner)] = [(labels, inner) for k, labels, inner in _blocks(body) if k == "dynamic"]
    assert labels == ["condition"]
    assert _attr(inner, "for_each") == (
        "length(var.connector_source_ranges) == 0 ? [] : [var.connector_source_ranges]")
    [source] = _walk(inner, "source_ip")
    assert _attr(source, "values") == "condition.value"


def test_it_runs_on_the_reader_role_with_no_salt_no_secret_and_no_daemon():
    body = _connector_task()
    assert _attr(body, "task_role_arn") == "var.reader_role_arn"
    assert _attr(body, "execution_role_arn") == 'aws_iam_role.execution["connector"].arn'
    container = _container("connector")
    assert "secrets" not in container
    # A check only with dashboard admins, then /readyz only: no gitleaksd,
    # so no /livez (tests/test_app_probes.py).
    assert 'healthCheck = local.container_check["connector"]' in container
    assert _bracket(container, "environment").strip().startswith(
        "for k, v in merge(local.base_env, local.connector_env)")
    assert "gitleaks" not in container
    keys = _local_keys(_bracket(container, "environment"), _locals())
    assert not [k for k in keys if _is_secret(k.rstrip("*"))], keys


def test_it_runs_the_same_image_as_the_connector_role():
    container = _container("connector")
    assert re.search(r"^\s*image\s*=\s*var\.image\s*$", container, re.M)
    assert "containerPort = 8090" in container
    entrypoint = (ROOT / "deploy" / "entrypoint.sh").read_text()
    assert re.search(r"^\s*connector\)", entrypoint, re.M)
    # No PORT is set, so the entrypoint's default must be the container port.
    assert '--port "${PORT:-8090}"' in entrypoint
    assert re.search(r'FORGD_ROLE\s*=\s*"connector"', _locals()["connector_env"])


CHART_ONLY = {"PORT": "the entrypoint's default is the container port",
              "AZURE_CLIENT_ID": "the chart's Azure workload identity",
              "FORGD_VERDICT_POLICY": "the chart mounts policy.yaml; this module inlines it"}


@requires_terraform
def test_the_environment_is_the_charts_connector_environment(tmp_path):
    import test_helm_chart as chart
    if chart.helm is None:
        pytest.skip("helm is not installed")
    from forgd_verdict.policy import ENV_OVERRIDES

    got = _evaluate(tmp_path / "all", _files(), **ALL, org_ids={"primary": "00000000-0000-0000-0000-00000000000a"})["locals"]
    env = {**got["base_env"], **got["connector_env"]}
    rendered = set(chart.env_of(chart.pod_specs(chart.render(*chart.CONNECTOR_ALL))["connector"]))
    assert set(env) ^ rendered == {"FORGD_POLICY_INLINE_GZ", "AWS_REGION"} | set(CHART_ONLY), \
        set(env) ^ rendered
    assert {n for n in env if n.startswith("FORGD_CONNECTOR_")} == {
        n for n in ENV_OVERRIDES if n.startswith("FORGD_CONNECTOR_")}
    assert env["FORGD_CONNECTOR_AUDIENCE"] == '["api-client-id"]'
    assert json.loads(env["FORGD_CONNECTOR_ISSUERS"]) == [{**ALL["connector_issuers"][0], "groups_claim": ""}]
    assert env["FORGD_CONNECTOR_AUTH_MODE"] == "oidc_jwt"


# --- the refusals, evaluated by terraform ----------------------------------------

def _conditions(body: str) -> list[tuple[str, str]]:
    [lifecycle] = _walk(body, "lifecycle")
    return [(_attr(b, "condition"), _attr(b, "error_message")) for b in _walk(lifecycle, "precondition")]


def _preconditions() -> list[tuple[str, str]]:
    out = _conditions(_connector_task())
    assert len(out) == 11, out
    return out


def _harness(root: Path, names: set[str], preconditions: list[tuple[str, str]], count: str) -> Path:
    """variables.tf, the named locals and the preconditions, on a
    terraform_data resource with the given count."""
    import test_app_aca as aca
    root.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULE / "variables.tf", root / "variables.tf")
    defs = {n: e for block in (inner for k, _, inner in _blocks(MAIN.read_text(encoding="utf-8"))
                               if k == "locals")
            for n, e in aca._assignments(block).items() if n in names}
    assert set(defs) == names, sorted(defs)
    checks = "".join(f"    precondition {{\n      condition     = {c}\n      error_message = {m}\n    }}\n"
                     for c, m in preconditions)
    (root / "main.tf").write_text(
        "locals {\n" + "".join(f"  {n} = {REF.sub(chr(34) + 'ref' + chr(34), e)}\n" for n, e in defs.items())
        + "}\n"
        'resource "terraform_data" "guard" {\n'
        f"  count = {count}\n"
        "  lifecycle {\n" + checks + "  }\n}\n",
        encoding="utf-8")
    out = subprocess.run([terraform, f"-chdir={root}", "init", "-input=false", "-no-color"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return root


def _connector_harness(root: Path, preconditions: list[tuple[str, str]]) -> Path:
    return _harness(root, {"connector_resource", "connector_resource_malformed"}, preconditions,
                    _attr(_connector_task(), "count"))


def _plan(root: Path, **variables) -> subprocess.CompletedProcess:
    (root / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    return subprocess.run([terraform, f"-chdir={root}", "plan", "-input=false", "-no-color",
                           "-lock=false", "-refresh=false"], capture_output=True, text=True, timeout=120)


def _flat(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    return _connector_harness(tmp_path_factory.mktemp("ecs"), _preconditions())


@requires_terraform
def test_the_connector_off_plans_with_nothing_set(harness):
    out = _plan(harness)
    assert out.returncode == 0, out.stderr
    assert "terraform_data.guard" not in out.stdout


@requires_terraform
@pytest.mark.parametrize("variables", [
    {},
    {"connector_resource": DERIVED},
    {"connector_issuer": "", "connector_jwks_url": "", "connector_audience": [],
     "connector_issuers": ALL["connector_issuers"]},
    {"connector_required_scope": "", "policy_yaml": "connector:\n  required_scope: findings.read\n"},
    {"connector_source_ranges": ["160.79.104.0/21"]},
], ids=["derived", "the derived url given", "issuers", "a scope from policy.yaml", "a source range"])
def test_the_connector_on_accepts(harness, variables):
    out = _plan(harness, **{**ON, **variables})
    assert out.returncode == 0, out.stderr


# Each case trips exactly one precondition, named by a fragment of its message.
REFUSALS = {
    "no host": ({"connector_host": ""}, "connector_host is empty"),
    "no issuer": ({"connector_issuer": ""}, "connector_issuer is empty"),
    "no jwks url": ({"connector_jwks_url": ""}, "connector_jwks_url is empty"),
    "no audience": ({"connector_audience": []}, "connector_audience is empty"),
    "an issuers entry without an audience": ({
        "connector_issuer": "", "connector_jwks_url": "", "connector_audience": [],
        "connector_issuers": [
        {"issuer": "https://i.example", "jwks_url": "https://i.example/keys", "audience": []}]},
        "A connector_issuers entry has an empty"),
    "a single issuer beside a list": ({"connector_issuers": [{"issuer": "https://i.example", "jwks_url": "https://i.example/keys", "audience": ["a"]}]},
                                      "Set either connector_issuers"),
    "a policy scope placeholder": ({
        "connector_required_scope": "",
        "policy_yaml": "connector:\n  required_scope: $FORGD_CONNECTOR_REQUIRED_SCOPE\n"},
        "connector_required_scope is empty"),
    "no required scope": ({"connector_required_scope": ""}, "connector_required_scope is empty"),
    "a policy scope that is empty": ({"connector_required_scope": "",
                                      "policy_yaml": "connector:\n  required_scope: ''\n"},
                                     "connector_required_scope is empty"),
    "not https": ({"connector_resource": DERIVED.replace("https://", "http://")}, "must be an https URL"),
    "not lowercase": ({"connector_resource": DERIVED.replace("mcp.example", "MCP.example")}, "must be lowercase"),
    "not /mcp": ({"connector_resource": DERIVED + "/"}, "must end in /mcp"),
    "another host": ({"connector_resource": "https://other.example.com/mcp"}, "does not match https://"),
}


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_fires_at_plan(harness, case):
    variables, fragment = REFUSALS[case]
    out = _plan(harness, **{**ON, **variables})
    assert out.returncode != 0, out.stdout
    assert fragment in _flat(out.stderr), out.stderr


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_is_its_own_precondition(tmp_path, case):
    """Drop the precondition the case names and the same plan goes through,
    so no case passes on the back of a different guard."""
    variables, fragment = REFUSALS[case]
    kept = [(c, m) for c, m in _preconditions() if fragment not in m]
    assert len(kept) == 10, case
    out = _plan(_connector_harness(tmp_path, kept), **{**ON, **variables})
    assert out.returncode == 0, out.stderr


def test_every_precondition_has_a_refusal():
    fragments = {f for _, f in REFUSALS.values()}
    for _, message in _preconditions():
        assert sum(f in message for f in fragments) == 1, message


@requires_terraform
@pytest.mark.parametrize("host, enabled, refused", [
    (REQUIRED["dashboard_host"], True, True),
    (REQUIRED["verdict_host"], True, True),
    (REQUIRED["dashboard_host"], False, False),
    (HOST, True, False),
])
def test_the_connector_host_joins_the_collision_check(tmp_path, host, enabled, refused):
    """The dashboard rule's own precondition: a host shared with any other
    rule is served by that rule, without sign-in."""
    checks = _conditions(_resources("aws_lb_listener_rule")["dashboard"])
    assert len(checks) == 1
    root = _harness(tmp_path, {"hosts", "services", "service_hosts"}, checks, "1")
    out = _plan(root, **{**ON, "connector_enabled": enabled, "connector_host": host})
    assert (out.returncode != 0) == refused, out.stderr
    if refused:
        assert "must all differ" in _flat(out.stderr)


@requires_terraform
@pytest.mark.parametrize("ranges", [["160.79.104.0/21"] * 5, ["160.79.104.0"], ["not-a-cidr"]])
def test_the_source_ranges_are_cidrs_and_fit_one_rule(harness, ranges):
    out = _plan(harness, **ON, connector_source_ranges=ranges)
    assert out.returncode != 0, out.stdout
    assert "at most 4 CIDRs" in _flat(out.stderr)


# --- each OTel token needs its org's id --------------------------------------------

ORG_EU = "00000000-0000-0000-0000-00000000000d"


def _render_tokens(tmp_path, org_ids: dict) -> dict:
    import terraform_render
    return terraform_render.render_module(tmp_path, "app-ecs", {
        **REQUIRED, "org_ids": org_ids, "otel_token_secret_arns": {"eu-west": ARN + "otel-eu-AbCdEf"}})


@requires_terraform
@pytest.mark.parametrize(("org_ids", "message"), [
    ({}, r"otel_token_secret_arns\.eu-west has no non-empty org_ids entry"),
    ({"primary": "00000000-0000-0000-0000-00000000000a"}, r"otel_token_secret_arns\.eu-west has no non-empty org_ids entry"),
    ({"eu-west": ""}, r"org_ids\.eu-west is not an organization UUID"),
], ids=["no-orgs", "another-org", "empty-id"])
def test_a_token_without_an_org_id_is_refused(tmp_path, org_ids, message):
    with pytest.raises(AssertionError, match=message):
        _render_tokens(tmp_path, org_ids)


@requires_terraform
def test_a_token_matched_through_the_env_name_is_accepted(tmp_path):
    rendered = _render_tokens(tmp_path, {"EU_WEST": ORG_EU})
    [container] = json.loads(rendered["aws_ecs_task_definition.collector"]["container_definitions"])
    assert "FORGD_OTEL_TOKEN_EU_WEST" in {s["name"] for s in container["secrets"]}
    assert {"name": "FORGD_ORG_ID_EU_WEST", "value": ORG_EU} in container["environment"]


@requires_terraform
@pytest.mark.parametrize("value", ["", "not-a-uuid-SENTINEL"], ids=["empty", "word"])
def test_an_org_id_that_is_not_a_uuid_is_refused(tmp_path, value):
    with pytest.raises(AssertionError, match=r"org_ids\.eu-west is not an organization UUID") as raised:
        _render_tokens(tmp_path, {"eu-west": value})
    assert "SENTINEL" not in str(raised.value)


# --- the fleet's intake token ---------------------------------------------


def _intake_secrets(tmp_path, **variables) -> dict:
    import terraform_render
    rendered = terraform_render.render_module(tmp_path, "app-ecs", {
        **REQUIRED, "enable_intake": True, "intake_host": "intake.example.com", **variables})
    [task] = rendered["aws_ecs_task_definition.intake"]
    containers = json.loads(task["container_definitions"])
    [app] = [c for c in containers if any(s["name"] == "FORGD_HASH_SALT" for s in c.get("secrets", []))]
    return {s["name"]: s["valueFrom"] for s in app["secrets"]}


@requires_terraform
def test_the_fleet_token_and_its_predecessor_reach_the_intake(tmp_path):
    secrets = _intake_secrets(
        tmp_path, intake_fleet_token_secret_arn=ARN + "fleet-AbCdEf",
        intake_fleet_token_previous_secret_arn=ARN + "fleet-old-AbCdEf",
        intake_token_secret_arns={"invoice-bot": ARN + "bot-AbCdEf"})
    assert secrets["FORGD_INTAKE_FLEET_TOKEN"] == ARN + "fleet-AbCdEf"
    assert secrets["FORGD_INTAKE_FLEET_TOKEN_PREVIOUS"] == ARN + "fleet-old-AbCdEf"
    assert secrets["FORGD_INTAKE_TOKEN_INVOICE_BOT"] == ARN + "bot-AbCdEf"


@requires_terraform
def test_without_a_previous_fleet_token_none_is_wired(tmp_path):
    secrets = _intake_secrets(tmp_path, intake_fleet_token_secret_arn=ARN + "fleet-AbCdEf")
    assert "FORGD_INTAKE_FLEET_TOKEN" in secrets
    assert "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS" not in secrets


@requires_terraform
def test_a_fleet_token_that_is_not_an_arn_is_refused(tmp_path):
    with pytest.raises(AssertionError, match="intake_fleet_token_secret_arn must be empty or"):
        _intake_secrets(tmp_path, intake_fleet_token_secret_arn="fleet-token-value")


# --- per-org signing secrets, Compliance Access Keys and fleet tokens ------

PROD = "00000000-0000-0000-0000-00000000000c"


def _task_secrets(rendered: dict, role: str) -> dict:
    [task] = [rendered[f"aws_ecs_task_definition.{role}"]] \
        if isinstance(rendered[f"aws_ecs_task_definition.{role}"], dict) \
        else rendered[f"aws_ecs_task_definition.{role}"]
    containers = json.loads(task["container_definitions"])
    [app] = [c for c in containers if any(s["name"] == "FORGD_HASH_SALT" for s in c.get("secrets", []))]
    return {s["name"]: s["valueFrom"] for s in app["secrets"]}


def _render_org(tmp_path, **variables) -> dict:
    import terraform_render
    return terraform_render.render_module(tmp_path, "app-ecs", {
        **REQUIRED, "org_ids": {**REQUIRED["org_ids"], "prod": PROD}, **variables})


@requires_terraform
def test_each_org_gets_its_signing_secret_and_its_previous_one(tmp_path):
    rendered = _render_org(tmp_path, webhook_secret_arns={
        "prod": {"current": ARN + "wh-prod-AbCdEf", "previous": ARN + "wh-prod-old-AbCdEf"}})
    secrets = _task_secrets(rendered, "verdict")
    assert secrets["WEBHOOK_SECRET_PROD"] == ARN + "wh-prod-AbCdEf"
    assert secrets["WEBHOOK_SECRET_PROD_PREVIOUS"] == ARN + "wh-prod-old-AbCdEf"
    assert secrets["WEBHOOK_SECRET"] == REQUIRED["webhook_secret_arn"]
    [policy] = [p for k, p in rendered.items() if k.startswith("aws_iam_role_policy.execution")
                and "verdict" in json.dumps(p)]
    assert ARN + "wh-prod-old-AbCdEf" in json.dumps(policy)


@requires_terraform
def test_an_org_without_a_previous_secret_gets_no_previous_variable(tmp_path):
    secrets = _task_secrets(_render_org(tmp_path, webhook_secret_arns={
        "prod": {"current": ARN + "wh-prod-AbCdEf"}}), "verdict")
    assert "WEBHOOK_SECRET_PROD" in secrets and "WEBHOOK_SECRET_PROD_PREVIOUS" not in secrets


@requires_terraform
def test_with_per_org_secrets_the_single_slot_may_be_empty(tmp_path):
    secrets = _task_secrets(_render_org(tmp_path, webhook_secret_arn="", compliance_key_secret_arn="",
                                        webhook_secret_arns={"prod": {"current": ARN + "wh-prod-AbCdEf"}},
                                        compliance_key_secret_arns={"prod": ARN + "ck-prod-AbCdEf"}),
                            "verdict")
    assert "WEBHOOK_SECRET" not in secrets and "WEBHOOK_SECRET_PROD" in secrets


@requires_terraform
@pytest.mark.parametrize(("variables", "message"), [
    ({"webhook_secret_arn": ""}, "webhook_secret_arn is empty and webhook_secret_arns names no org"),
    ({"compliance_key_secret_arn": ""}, "compliance_key_secret_arn is empty and compliance_key_secret_arns names no org"),
], ids=["webhook", "compliance"])
def test_with_no_per_org_secret_the_single_slot_is_required(tmp_path, variables, message):
    with pytest.raises(AssertionError, match=message):
        _render_org(tmp_path, **variables)


@requires_terraform
def test_each_org_gets_its_compliance_key_and_no_previous(tmp_path):
    secrets = _task_secrets(_render_org(tmp_path, compliance_key_secret_arns={"prod": ARN + "ck-prod-AbCdEf"}),
                            "ingest")
    assert secrets["ANTHROPIC_COMPLIANCE_ACCESS_KEY_PROD"] == ARN + "ck-prod-AbCdEf"
    assert not any(n.endswith("_PREVIOUS") for n in secrets if n.startswith("ANTHROPIC_"))


@requires_terraform
def test_each_org_fleet_gets_its_token_and_its_previous_one(tmp_path):
    secrets = _intake_secrets(tmp_path, org_ids={**REQUIRED["org_ids"], "prod": PROD},
                              intake_fleet_token_secret_arns={"prod": {
                                  "current": ARN + "fleet-prod-AbCdEf", "previous": ARN + "fleet-prod-old-AbCdEf"}})
    assert secrets["FORGD_INTAKE_FLEET_TOKEN_PROD"] == ARN + "fleet-prod-AbCdEf"
    assert secrets["FORGD_INTAKE_FLEET_TOKEN_PROD_PREVIOUS"] == ARN + "fleet-prod-old-AbCdEf"


ORG_MAPS = {
    "webhook_secret_arns": lambda n: {"current": ARN + f"wh-{n}-AbCdEf"},
    "compliance_key_secret_arns": lambda n: ARN + f"ck-{n}-AbCdEf",
    "intake_fleet_token_secret_arns": lambda n: {"current": ARN + f"fl-{n}-AbCdEf"},
}
INTAKE = {"enable_intake": True, "intake_host": "intake.example.com"}


def _with_org_map(variable: str, *names: str, ids: dict | None = None) -> dict:
    ids = ids if ids is not None else {n: PROD for n in names}
    return {**INTAKE, "org_ids": {**REQUIRED["org_ids"], **ids},
            variable: {n: ORG_MAPS[variable](n.replace("_", "-")) for n in names}}


@requires_terraform
@pytest.mark.parametrize("variable", ORG_MAPS)
def test_a_per_org_secret_for_a_name_not_in_org_ids_is_refused(tmp_path, variable):
    with pytest.raises(AssertionError, match=rf"{variable}\.eu has no org_ids entry"):
        _render_org(tmp_path, **_with_org_map(variable, "eu", ids={}))


@requires_terraform
@pytest.mark.parametrize("variable", ["webhook_secret_arns", "intake_fleet_token_secret_arns"])
def test_an_org_named_previous_collides_with_the_single_slot(tmp_path, variable):
    with pytest.raises(AssertionError, match=r"collides.*_PREVIOUS"):
        _render_org(tmp_path, **_with_org_map(variable, "previous"))


@requires_terraform
@pytest.mark.parametrize("variable", ["webhook_secret_arns", "intake_fleet_token_secret_arns"])
def test_an_org_and_its_previous_name_collide(tmp_path, variable):
    with pytest.raises(AssertionError, match=r"collides.*_A_PREVIOUS"):
        _render_org(tmp_path, **_with_org_map(variable, "a", "a-previous"))


@requires_terraform
@pytest.mark.parametrize("variable", ORG_MAPS)
def test_two_names_for_one_variable_collide(tmp_path, variable):
    with pytest.raises(AssertionError, match=r"Two .* keys map to the same|collides.*_A_B"):
        _render_org(tmp_path, **_with_org_map(variable, "a-b", "a_b", ids={"a-b": PROD}))


@requires_terraform
@pytest.mark.parametrize("variables", [{}, INTAKE, {**INTAKE, **ON}], ids=["required", "intake", "intake-connector"])
def test_the_module_plans_as_it_did_at_v0_46_0_with_no_per_org_maps(tmp_path, variables):
    import terraform_render
    assert terraform_render.versus_commit(tmp_path, "app-ecs", {**REQUIRED, **variables}, "a9a62907") == []
