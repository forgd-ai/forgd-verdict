"""Dashboard admins in the app-ecs module.

Off by default, and then the module evaluates exactly as it did before them:
every local, resource key and output, the dashboard's task role and its
container definition. On, the dashboard task runs as the control role and
takes FORGD_DASHBOARD_FORM_KEY and FORGD_OVERRIDES_SIGNING_KEY from Secrets
Manager, its execution role reads those two secrets, every container gets
FORGD_OVERRIDES_VERIFY_KEY, the CD role may pass the control role, and the
connector stays on the reader. The refusals are evaluated by terraform on a
`terraform_data` resource.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import terraform_render
import test_app_aca as aca
import test_app_aca_admins as aca_admins
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_app_ecs import (
    ARN,
    MAIN,
    MODULE,
    REF,
    REQUIRED,
    _attr,
    _close,
    _files,
    _resources,
    _walk,
    requires_terraform,
    terraform,
)
from test_app_ecs import ON as CONNECTOR_ON

from forgd_verdict.overrides_signing import encode

CONTROL = "arn:aws:iam::123456789012:role/control"
FORM_KEY = ARN + "form-key-AbCdEf"
SIGNING_KEY = ARN + "signing-key-AbCdEf"
# Two made-up public keys, generated each run.
VERIFY_KEYS = [encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()) for _ in range(2)]
ON = {"dashboard_admins_enabled": True, "control_role_arn": CONTROL, "dashboard_form_key_secret_arn": FORM_KEY,
      "dashboard_signing_key_secret_arn": SIGNING_KEY, "overrides_verify_keys": VERIFY_KEYS,
      "overrides_writer_lockout": True, "overrides_writer_identities": [REQUIRED["writer_role_arn"]]}
ADMIN_VARIABLES = {"dashboard_admins_enabled", "control_role_arn", "dashboard_form_key_secret_arn",
                   "dashboard_signing_key_secret_arn", "overrides_verify_keys",
                   "overrides_writer_lockout", "overrides_writer_identities"}
WRITER_ROLES_EXPR = 'join(",", local.overrides_writer_roles)'
OVERRIDES_BLOCK = '  # The task role each writer role runs as.\n  writer_identity = merge(\n    { verdict = var.writer_role_arn, collector = var.writer_role_arn, ingest = var.writer_role_arn },\n    var.enable_intake ? { intake = var.writer_role_arn } : {},\n  )\n  writer_order = concat(["verdict", "collector"], var.enable_intake ? ["intake"] : [], ["ingest"])\n  # FORGD_OVERRIDES_WRITER_ROLES: one writer role per distinct store\n  # identity, the first in writer_order that runs as it. Ingest is last, so\n  # it is listed only when no long-running role shares its identity. The\n  # dashboard and the connector only read.\n  overrides_writer_roles = [\n    for i, role in local.writer_order : role\n    if !contains([for earlier in slice(local.writer_order, 0, i) : local.writer_identity[earlier]],\n    local.writer_identity[role])\n  ]\n\n  # Every role honours runtime overrides only while this is "true".\n  overrides_env = var.dashboard_admins_enabled ? {\n    FORGD_OVERRIDES_ENABLED      = "true"\n    FORGD_OVERRIDES_WRITER_ROLES = join(",", local.overrides_writer_roles)\n    FORGD_OVERRIDES_VERIFY_KEY   = join(",", var.overrides_verify_keys)\n  } : {}\n\n'
ADMIN_REF = re.compile(r"var\.(dashboard_admins_enabled|control_role_arn|dashboard_form_key_secret_arn"
                       r"|dashboard_signing_key_secret_arn|overrides_verify_keys"
                       r"|overrides_writer_lockout|overrides_writer_identities)\b"
                       r"|local\.(dashboard_secrets|dashboard_evidence_env)\b")

_TASK_ROLE_NOW = '''  execution_role_arn       = aws_iam_role.execution["dashboard"].arn
  # With dashboard_admins_enabled, store-s3's control role: the reader's
  # policy plus the runtime overrides writes.
  task_role_arn = var.dashboard_admins_enabled ? var.control_role_arn : var.reader_role_arn
  tags          = var.tags
'''
_TASK_ROLE_BEFORE = '''  execution_role_arn       = aws_iam_role.execution["dashboard"].arn
  task_role_arn            = var.reader_role_arn
  tags                     = var.tags
'''

CONTAINER_CHECK = '''  # With dashboard_admins_enabled, every container's check: /livez on the
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
'''
CONNECTOR_CHECK = '''    logConfiguration = local.log_config["connector"]
    }, var.dashboard_admins_enabled ? {
    healthCheck = local.container_check["connector"]
  } : {})])
'''
# The pre-existing text dashboard admins change: (now, before).
MAIN_EDITS = [
    (OVERRIDES_BLOCK, ""),
    *[(f'  task_role_arn            = local.writer_identity["{r}"]\n',
       "  task_role_arn            = var.writer_role_arn\n") for r in ("verdict", "collector", "intake")],
    ('  task_role_arn      = local.writer_identity["ingest"]\n',
     "  task_role_arn      = var.writer_role_arn\n"),
    ("  # The path the target group and each container check request for\n"
     "  # readiness. /healthz answers 200 however the runtime overrides read;\n"
     "  # /readyz answers 503 until they are confirmed.\n"
     '  ready_path = var.dashboard_admins_enabled ? "/readyz" : "/healthz"\n\n', ""),
    ("  }, local.org_env, local.overrides_env)\n", "  }, local.org_env)\n"),
    ("  # The writer identities the dashboard verifies the lockout of.\n"
     "  dashboard_evidence_env = var.dashboard_admins_enabled ? {\n"
     '    FORGD_OVERRIDES_WRITER_IDENTITIES = join(",", var.overrides_writer_identities)\n'
     "  } : {}\n\n", ""),
    ("    }, local.dashboard_evidence_env) : { name = k, value = v }]\n",
     "    }) : { name = k, value = v }]\n"),
    (CONTAINER_CHECK, ""),
    *[(f'    healthCheck      = var.dashboard_admins_enabled ? local.container_check["{r}"] : '
       f'local.livez_check["{r}"]\n', f'    healthCheck      = local.livez_check["{r}"]\n')
      for r in ("verdict", "collector", "intake")],
    ('  container_definitions = jsonencode([merge({\n    name             = "connector"',
     '  container_definitions = jsonencode([{\n    name             = "connector"'),
    (CONNECTOR_CHECK, '    logConfiguration = local.log_config["connector"]\n  }])\n'),
    ('    path                = local.ready_path\n', '    path                = "/healthz"\n'),
    ("  dashboard_secrets = var.dashboard_admins_enabled ? {\n"
     "    FORGD_DASHBOARD_FORM_KEY    = var.dashboard_form_key_secret_arn\n"
     "    FORGD_OVERRIDES_SIGNING_KEY = var.dashboard_signing_key_secret_arn\n"
     "  } : {}\n", ""),
    ("    dashboard = local.dashboard_secrets\n", "    dashboard = {}\n"),
    (_TASK_ROLE_NOW, _TASK_ROLE_BEFORE),
    ("  container_definitions = jsonencode([merge({\n    name         = \"dashboard\"",
     "  container_definitions = jsonencode([{\n    name         = \"dashboard\""),
    ('''    logConfiguration = local.log_config["dashboard"]
    }, length(local.role_secrets["dashboard"]) == 0 ? {} : {
    secrets = [for k, arn in local.role_secrets["dashboard"] : { name = k, valueFrom = arn }]
    }, var.dashboard_admins_enabled ? {
    healthCheck = local.container_check["dashboard"]
  } : {})])
''', '''    logConfiguration = local.log_config["dashboard"]
  }])
'''),
]
OUTPUT_EDITS = [
    (", var.dashboard_admins_enabled ? [var.control_role_arn] : []))", "))"),
]


def _without_lifecycle(main: str) -> str:
    """main.tf with the dashboard task's lifecycle block, which only admins add, removed."""
    start = main.index('resource "aws_ecs_task_definition" "dashboard" {')
    i = main.index("\n  lifecycle {", start)
    end = _close(main, main.index("{", i), "{", "}")
    return main[:i] + main[end:]


def _left_out() -> dict[str, str]:
    files = _files()
    main = _without_lifecycle(files["main.tf"])
    for now, before in MAIN_EDITS:
        assert main.count(now) == 1, now
        main = main.replace(now, before)
    outputs = files["outputs.tf"]
    for now, before in OUTPUT_EDITS:
        assert outputs.count(now) == 1, now
        outputs = outputs.replace(now, before)
    variables = aca._without(files["variables.tf"],
                             lambda k, labels, _: k == "variable" and labels[0] in ADMIN_VARIABLES)
    return {"main.tf": main, "variables.tf": variables, "outputs.tf": outputs}


def _dashboard_exprs(main: str) -> str:
    """Outputs for the dashboard task's role and container definitions, as written in `main`."""
    start = main.index('resource "aws_ecs_task_definition" "dashboard" {')
    body = main[start:_close(main, main.index("{", start), "{", "}")]
    role = re.search(r"^\s*task_role_arn\s*=\s*(.+)$", body, re.M).group(1)
    i = body.index("container_definitions = jsonencode(") + len("container_definitions = ")
    defs = body[i:_close(body, body.index("(", i), "(", ")")]
    return f'output "dash_role" {{\n  value = {role}\n}}\noutput "dash_defs" {{\n  value = {defs}\n}}\n'


def _evaluate(root: Path, files: dict[str, str], **variables) -> dict:
    files = {**files, "outputs.tf": files["outputs.tf"] + _dashboard_exprs(files["main.tf"])}
    return aca._evaluate(root, files, required=REQUIRED, ref=REF, **variables)


# --- off -------------------------------------------------------------------------

def test_admins_are_off_by_default_and_every_setting_has_a_default():
    text = (MODULE / "variables.tf").read_text(encoding="utf-8")
    bodies = {labels[0]: inner for k, labels, inner in aca._blocks(text) if k == "variable"}
    assert _attr(bodies["dashboard_admins_enabled"], "default") == "false"
    assert _attr(bodies["overrides_writer_lockout"], "default") == "false"
    for name in ("control_role_arn", "dashboard_form_key_secret_arn", "dashboard_signing_key_secret_arn"):
        assert _attr(bodies[name], "default") == '""', name
    assert _attr(bodies["overrides_verify_keys"], "default") == "[]"


def test_leaving_admins_out_removes_every_mention_of_them():
    for name, text in _left_out().items():
        assert not ADMIN_REF.search(text), name
        assert "FORGD_DASHBOARD_FORM_KEY" not in text and "control_role" not in text, name
        assert "FORGD_OVERRIDES_SIGNING_KEY" not in text and "FORGD_OVERRIDES_VERIFY_KEY" not in text, name


def test_only_the_dashboard_and_the_release_read_an_admin_setting():
    own = []
    for k, labels, inner in aca._blocks(MAIN.read_text(encoding="utf-8")):
        if k == "locals":
            for name, expr in aca._assignments(inner).items():
                if ADMIN_REF.search(expr):
                    own.append(f"local.{name}")
        elif ADMIN_REF.search(inner):
            own.append(".".join(labels))
    assert sorted(own) == ["aws_ecs_task_definition.collector", "aws_ecs_task_definition.connector",
                           "aws_ecs_task_definition.dashboard", "aws_ecs_task_definition.intake",
                           "aws_ecs_task_definition.verdict", "local.dashboard_evidence_env",
                           "local.dashboard_secrets", "local.overrides_env", "local.ready_path",
                           "local.role_secrets"], own
    outputs = {labels[0]: inner for k, labels, inner in
               aca._blocks((MODULE / "outputs.tf").read_text(encoding="utf-8")) if k == "output"}
    assert sorted(n for n, b in outputs.items() if ADMIN_REF.search(b)) == ["ci_release"]


@requires_terraform
@pytest.mark.parametrize("connector", [False, True])
def test_off_evaluates_exactly_as_the_module_with_admins_left_out(tmp_path, connector):
    extra = {"org_ids": {"prod": "00000000-0000-0000-0000-00000000000b"}, "metrics_token_secret_arn": ARN + "metrics-AbCdEf",
             **(CONNECTOR_ON if connector else {})}
    got = _evaluate(tmp_path / "off", _files(), **extra)
    before = _evaluate(tmp_path / "left-out", _left_out(), **extra)
    # writer_identity only names var.writer_role_arn; the resources compare
    # below shows every task role is unchanged.
    admins_only = ("dashboard_secrets", "overrides_env", "writer_identity", "writer_order",
                   "overrides_writer_roles", "ready_path", "dashboard_evidence_env",
                   "container_check_paths", "container_check")
    assert {k: v for k, v in got["locals"].items() if k not in admins_only} == before["locals"]
    assert got["locals"]["ready_path"] == "/healthz"
    assert got["locals"]["dashboard_secrets"] == {}
    assert got["locals"]["overrides_env"] == {}
    assert got["locals"]["dashboard_evidence_env"] == {}
    assert got["resources"] == before["resources"]
    rest = lambda d: {k: v for k, v in d.items() if k not in ("locals", "resources")}  # noqa: E731
    assert rest(got) == rest(before)
    assert got["o_dash_role"] == REQUIRED["reader_role_arn"]
    assert "secrets" not in json.loads(got["o_dash_defs"])[0]


# --- on -----------------------------------------------------------------------------

@requires_terraform
def test_on_the_dashboard_runs_as_the_control_role_with_the_form_key(tmp_path):
    got = _evaluate(tmp_path / "on", _files(), **ON)
    before = _evaluate(tmp_path / "off", _files())
    assert got["o_dash_role"] == CONTROL
    [defs] = json.loads(got["o_dash_defs"])
    assert defs["secrets"] == [{"name": "FORGD_DASHBOARD_FORM_KEY", "valueFrom": FORM_KEY},
                               {"name": "FORGD_OVERRIDES_SIGNING_KEY", "valueFrom": SIGNING_KEY}]
    names = {e["name"] for e in defs["environment"]}
    assert "FORGD_DASHBOARD_FORM_KEY" not in names and "FORGD_OVERRIDES_SIGNING_KEY" not in names
    [was] = json.loads(before["o_dash_defs"])
    assert "healthCheck" not in was
    check = defs.pop("healthCheck")
    assert "/readyz" in check["command"][-1]
    enabled = {"name": "FORGD_OVERRIDES_ENABLED", "value": "true"}
    roles = {"name": "FORGD_OVERRIDES_WRITER_ROLES", "value": "verdict"}
    verify = {"name": "FORGD_OVERRIDES_VERIFY_KEY", "value": ",".join(VERIFY_KEYS)}
    identities = {"name": "FORGD_OVERRIDES_WRITER_IDENTITIES", "value": REQUIRED["writer_role_arn"]}
    for added in (enabled, roles, verify, identities):
        assert added in defs["environment"] and added not in was["environment"]
        defs["environment"].remove(added)
    assert {k: v for k, v in defs.items() if k != "secrets"} == was
    assert got["locals"]["role_secrets"]["dashboard"] == {"FORGD_DASHBOARD_FORM_KEY": FORM_KEY,
                                                          "FORGD_OVERRIDES_SIGNING_KEY": SIGNING_KEY}
    assert {r: s for r, s in got["locals"]["role_secrets"].items() if r != "dashboard"} == \
        {r: s for r, s in before["locals"]["role_secrets"].items() if r != "dashboard"}
    assert got["resources"] == before["resources"]
    assert CONTROL in got["o_ci_release"]["task_role_arns"]
    assert CONTROL not in before["o_ci_release"]["task_role_arns"]


def test_the_connector_stays_on_the_reader_role():
    """Its only admin setting is the container check."""
    body = _resources("aws_ecs_task_definition")["connector"]
    assert _attr(body, "task_role_arn") == "var.reader_role_arn"
    assert {m.group(0) for m in ADMIN_REF.finditer(body)} == {"var.dashboard_admins_enabled"}
    assert body.count("var.dashboard_admins_enabled") == 1


def test_only_the_dashboard_takes_the_form_key_and_the_signing_key():
    for name, body in _resources("aws_ecs_task_definition").items():
        if name != "dashboard":
            assert "FORGD_DASHBOARD_FORM_KEY" not in body and 'role_secrets["dashboard"]' not in body, name
            assert "FORGD_OVERRIDES_SIGNING_KEY" not in body and "dashboard_signing_key" not in body, name


# --- the refusals, evaluated by terraform ------------------------------------------

def _preconditions() -> list[tuple[str, str]]:
    body = _resources("aws_ecs_task_definition")["dashboard"]
    [lifecycle] = _walk(body, "lifecycle")
    out = [(_attr(b, "condition"), _attr(b, "error_message")) for b in _walk(lifecycle, "precondition")]
    assert len(out) == 7, out
    return out


def _harness(root: Path, preconditions: list[tuple[str, str]]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULE / "variables.tf", root / "variables.tf")
    checks = "".join(
        f"    precondition {{\n      condition     = {c}\n      error_message = {m}\n    }}\n"
        for c, m in preconditions)
    (root / "main.tf").write_text(
        'resource "terraform_data" "dashboard" {\n  lifecycle {\n' + checks + "  }\n}\n", encoding="utf-8")
    out = subprocess.run([terraform, f"-chdir={root}", "init", "-input=false", "-no-color"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return root


def _plan(root: Path, **variables) -> subprocess.CompletedProcess:
    (root / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    return subprocess.run([terraform, f"-chdir={root}", "plan", "-input=false", "-no-color",
                           "-lock=false", "-refresh=false"], capture_output=True, text=True, timeout=120)


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    return _harness(tmp_path_factory.mktemp("ecs-admins"), _preconditions())


@requires_terraform
@pytest.mark.parametrize("variables", [{}, ON], ids=["off", "on"])
def test_plans_off_with_nothing_set_and_on_with_a_role_of_its_own(harness, variables):
    out = _plan(harness, **variables)
    assert out.returncode == 0, out.stderr


REFUSALS = {
    "no control role": ({"control_role_arn": ""}, "needs control_role_arn"),
    "the reader role": ({"control_role_arn": REQUIRED["reader_role_arn"]}, "control_role_arn equals"),
    "the writer role": ({"control_role_arn": REQUIRED["writer_role_arn"]}, "control_role_arn equals"),
    "no form key": ({"dashboard_form_key_secret_arn": ""}, "needs dashboard_form_key_secret_arn"),
    "no signing key": ({"dashboard_signing_key_secret_arn": ""}, "needs dashboard_signing_key_secret_arn"),
    "no verify keys": ({"overrides_verify_keys": []}, "needs overrides_verify_keys"),
    "no writer lockout": ({"overrides_writer_lockout": False}, "needs overrides_writer_lockout"),
    "no writer identities": ({"overrides_writer_identities": []}, "needs overrides_writer_identities"),
    "the writer role not listed": ({"overrides_writer_identities": ["arn:aws:iam::123456789012:role/other"]},
                                   "needs overrides_writer_identities"),
}


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_fires(harness, case):
    variables, fragment = REFUSALS[case]
    out = _plan(harness, **{**ON, **variables})
    assert out.returncode != 0, out.stdout
    assert fragment in aca._flat(out.stderr), out.stderr


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_is_its_own_precondition(tmp_path, case):
    variables, fragment = REFUSALS[case]
    kept = [(c, m) for c, m in _preconditions() if fragment not in m]
    assert len(kept) == 6, case
    out = _plan(_harness(tmp_path, kept), **{**ON, **variables})
    assert out.returncode == 0, out.stderr


@requires_terraform
def test_a_form_key_that_is_not_a_full_secret_arn_is_refused(harness):
    out = _plan(harness, **{**ON, "dashboard_form_key_secret_arn": ARN + "form-key"})
    assert out.returncode != 0 and "full Secrets Manager secret ARN" in aca._flat(out.stderr), out.stderr


@requires_terraform
def test_a_signing_key_that_is_not_a_full_secret_arn_is_refused(harness):
    out = _plan(harness, **{**ON, "dashboard_signing_key_secret_arn": ARN + "signing-key"})
    assert out.returncode != 0, out.stdout
    assert "dashboard_signing_key_secret_arn must be empty or a full Secrets Manager secret ARN" in \
        aca._flat(out.stderr), out.stderr


BAD_VERIFY_KEYS = {
    "one short": VERIFY_KEYS[0][:42],
    "one long": VERIFY_KEYS[0] + "A",
    "padded": VERIFY_KEYS[0][:42] + "=",
    "standard base64": "+/" + VERIFY_KEYS[0][2:],
    "a space": " " + VERIFY_KEYS[0][1:],
    "empty": "",
}


@requires_terraform
@pytest.mark.parametrize("case", sorted(BAD_VERIFY_KEYS))
def test_a_verify_key_that_is_not_43_url_safe_characters_is_refused(harness, case):
    out = _plan(harness, **{**ON, "overrides_verify_keys": [VERIFY_KEYS[0], BAD_VERIFY_KEYS[case]]})
    assert out.returncode != 0, out.stdout
    assert "Each overrides_verify_keys entry must be an Ed25519 public key" in aca._flat(out.stderr), out.stderr


# --- FORGD_OVERRIDES_ENABLED, over the full rendering -------------------------------

ENABLED = "FORGD_OVERRIDES_ENABLED"
WRITER_ROLES = "FORGD_OVERRIDES_WRITER_ROLES"
# Every task: the connector and the intake on.
RENDER = {**REQUIRED, **CONNECTOR_ON, "enable_intake": True, "intake_host": "intake.example.com",
          "intake_token_secret_arns": {"dev": ARN + "intake-AbCdEf"}}
NO_INTAKE = {**REQUIRED, **CONNECTOR_ON, "enable_intake": False}


def _containers(rendered: dict) -> dict[str, dict]:
    """"address.name" -> container, decoded from every container_definitions
    the rendering holds."""
    out = {}

    def walk(value, path):
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "container_definitions" and isinstance(v, str):
                    for c in json.loads(v):
                        out[".".join(map(str, (*path, c["name"])))] = c
                else:
                    walk(v, (*path, k))
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(v, (*path, i))

    walk(rendered, ())
    return out


@requires_terraform
def test_on_every_container_has_overrides_enabled(tmp_path):
    """Mutation: drop overrides_env from base_env, or from one task's environment."""
    containers = _containers(terraform_render.render_module(tmp_path, "app-ecs", {**RENDER, **ON}))
    assert len(containers) >= 6, sorted(containers)
    for name, c in containers.items():
        env = [e for e in c.get("environment", []) if e["name"] == ENABLED]
        assert env == [{"name": ENABLED, "value": "true"}], name


@requires_terraform
@pytest.mark.parametrize("intake", [True, False], ids=["intake", "no-intake"])
@pytest.mark.parametrize("left_set", [False, True], ids=["unset", "control-values-left-set"])
def test_off_no_resource_has_overrides_enabled_and_the_plan_is_the_baseline(tmp_path, left_set, intake):
    """Every resource, rendered in full, equals the pinned baseline's rendering
    of the same variables.

    Mutation: set FORGD_OVERRIDES_ENABLED or FORGD_OVERRIDES_WRITER_ROLES
    whatever dashboard_admins_enabled says."""
    variables = RENDER if intake else NO_INTAKE
    current = {k: v for k, v in ON.items() if k != "dashboard_admins_enabled"} if left_set else {}
    assert terraform_render.off_versus_baseline(tmp_path, "app-ecs", variables, current) == []
    rendered = terraform_render.render_module(tmp_path / "off", "app-ecs", {**variables, **current})
    assert _containers(rendered)
    assert ENABLED not in json.dumps(rendered)
    assert WRITER_ROLES not in json.dumps(rendered)


@requires_terraform
def test_on_the_baseline_comparison_sees_the_variable(tmp_path):
    """The comparison above can see the change."""
    found = terraform_render.off_versus_baseline(tmp_path, "app-ecs", RENDER, ON)
    assert any(ENABLED in d for d in found), found
    assert any(WRITER_ROLES in d for d in found), found


# --- the signing keys, over the full rendering ------------------------------------

VERIFY = "FORGD_OVERRIDES_VERIFY_KEY"
SIGNING = "FORGD_OVERRIDES_SIGNING_KEY"


def _execution_policies(rendered: dict) -> dict[str, dict]:
    """role => its execution role's policy document."""
    return {role: json.loads(p["policy"]) for role, p in rendered["aws_iam_role_policy.execution"].items()}


def _secret_reads(policy: dict) -> set[str]:
    return {r for s in policy["Statement"] if "secretsmanager:GetSecretValue" in s["Action"]
            for r in ([s["Resource"]] if isinstance(s["Resource"], str) else s["Resource"])}


@requires_terraform
def test_on_only_the_dashboard_holds_the_signing_key_and_its_execution_role_reads_it(tmp_path):
    """Mutation: drop FORGD_OVERRIDES_SIGNING_KEY from dashboard_secrets, point
    it at another ARN, or give it to another role."""
    rendered = terraform_render.render_module(tmp_path, "app-ecs", {**RENDER, **ON})
    containers = _containers(rendered)
    holders = {n: [s["valueFrom"] for s in c.get("secrets", []) if s["name"] == SIGNING]
               for n, c in containers.items()}
    assert {n: v for n, v in holders.items() if v} == {
        n: [SIGNING_KEY] for n in holders if n.startswith("aws_ecs_task_definition.dashboard")}, holders
    assert any(n.startswith("aws_ecs_task_definition.dashboard") for n in holders), holders
    for name, c in containers.items():
        assert SIGNING not in {e["name"] for e in c.get("environment", [])}, name
        if not name.startswith("aws_ecs_task_definition.dashboard"):
            assert SIGNING_KEY not in json.dumps(c), name
    policies = _execution_policies(rendered)
    assert len(policies) >= 6, sorted(policies)
    reads = {role: _secret_reads(p) for role, p in policies.items()}
    assert reads["dashboard"] == {FORM_KEY, SIGNING_KEY}, reads["dashboard"]
    assert [role for role, r in reads.items() if SIGNING_KEY in r] == ["dashboard"], reads


@requires_terraform
def test_on_every_container_has_the_verify_keys(tmp_path):
    """Mutation: drop FORGD_OVERRIDES_VERIFY_KEY from overrides_env, or join
    the keys with anything but a comma."""
    envs = _envs(terraform_render.render_module(tmp_path, "app-ecs", {**RENDER, **ON}))
    assert {n.split(".")[1] for n in envs} >= {
        "verdict", "collector", "intake", "ingest", "dashboard", "connector"}, sorted(envs)
    for name, env in envs.items():
        assert env.get(VERIFY) == ",".join(VERIFY_KEYS), name


@requires_terraform
def test_off_no_resource_has_a_signing_key_or_a_verify_key(tmp_path):
    current = {k: v for k, v in ON.items() if k != "dashboard_admins_enabled"}
    rendered = json.dumps(terraform_render.render_module(tmp_path, "app-ecs", {**RENDER, **current}))
    for absent in (SIGNING, VERIFY, SIGNING_KEY, *VERIFY_KEYS):
        assert absent not in rendered, absent


# --- FORGD_OVERRIDES_WRITER_ROLES, over the full rendering --------------------------

def _envs(rendered: dict) -> dict[str, dict[str, str]]:
    return {n: {e["name"]: e["value"] for e in c.get("environment", [])}
            for n, c in _containers(rendered).items()}


@requires_terraform
@pytest.mark.parametrize("variables,roles", [
    (RENDER, "verdict"),
    (NO_INTAKE, "verdict"),
], ids=["intake", "no-intake"])
def test_on_every_container_has_the_writer_roles_the_module_deploys(tmp_path, variables, roles):
    """ECS always runs verdict, collector and ingest, and intake with
    enable_intake, all as the one writer role: only verdict is listed, and
    ingest never is.

    Mutation: list a role the module does not deploy, or ingest beside a
    long-running role on the same identity."""
    envs = _envs(terraform_render.render_module(tmp_path, "app-ecs", {**variables, **ON}))
    assert len(envs) >= 5, sorted(envs)
    assert ("intake" in {e["FORGD_ROLE"] for e in envs.values()}) == variables["enable_intake"]
    assert aca_admins.writer_roles_problems(envs) == []
    assert {e[WRITER_ROLES] for e in envs.values()} == {roles}


@requires_terraform
def test_a_writer_roles_list_that_always_names_intake_is_caught(tmp_path):
    """The check above fails on a module that lists intake whether or not it deploys it."""
    edit = (WRITER_ROLES_EXPR, '"verdict,collector,intake,ingest"')
    envs = _envs(terraform_render.render_edited(tmp_path, "app-ecs", {**NO_INTAKE, **ON}, [edit]))
    assert "intake" not in {e["FORGD_ROLE"] for e in envs.values()}
    assert len(aca_admins.writer_roles_problems(envs)) == len(envs)


@requires_terraform
def test_ingest_on_a_role_of_its_own_is_listed(tmp_path):
    """The list follows writer_identity, which the task definitions use."""
    edit = ("collector = var.writer_role_arn, ingest = var.writer_role_arn }",
            "collector = var.writer_role_arn, ingest = var.reader_role_arn }")
    envs = _envs(terraform_render.render_edited(tmp_path, "app-ecs", {**RENDER, **ON}, [edit]))
    assert {e[WRITER_ROLES] for e in envs.values()} == {"verdict,ingest"}
    assert aca_admins.writer_roles_problems(envs, {"ingest": "own"}) == []


def test_each_writer_task_runs_as_its_writer_identity():
    """Mutation: point a writer task's role past writer_identity."""
    main = (MODULE / "main.tf").read_text(encoding="utf-8")
    for role in ("verdict", "collector", "intake", "ingest"):
        body = main[main.index(f'resource "aws_ecs_task_definition" "{role}"'):]
        body = body[:body.index("\n}\n")]
        assert re.search(rf'task_role_arn\s+= local\.writer_identity\["{role}"\]', body), role


# --- the lockout verification's inputs, over the full rendering ---------------------


@requires_terraform
def test_on_only_the_dashboard_gets_the_writer_identities(tmp_path):
    """Mutation: give every role the variable, or render a list other than
    the store output's."""
    envs = _envs(terraform_render.render_module(tmp_path, "app-ecs", {**RENDER, **ON}))
    found = {n: e.get("FORGD_OVERRIDES_WRITER_IDENTITIES") for n, e in envs.items()}
    assert {n: v for n, v in found.items() if v is not None} == {
        n: REQUIRED["writer_role_arn"] for n in found if n.startswith("aws_ecs_task_definition.dashboard")}, found
    assert any(n.startswith("aws_ecs_task_definition.dashboard") for n in found), found


@requires_terraform
def test_off_no_container_gets_the_writer_identities(tmp_path):
    current = {k: v for k, v in ON.items() if k != "dashboard_admins_enabled"}
    rendered = terraform_render.render_module(tmp_path, "app-ecs", {**RENDER, **current})
    assert "FORGD_OVERRIDES_WRITER_IDENTITIES" not in json.dumps(rendered)
