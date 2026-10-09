"""The app-cloudrun module keeps the properties app-ecs and app-aca keep.

Parsed from the .tf source, because nothing here may call Google and a plan
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
from test_app_ecs import SECRET_NAMES, SECRET_PREFIXES, _blocks, _bracket, _close, _top_level, _walk

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "deploy" / "terraform" / "modules" / "app-cloudrun"
MAIN = MODULE / "main.tf"

# The services Anthropic or a laptop authenticates to by itself.
NO_SIGN_IN = ("verdict", "collector", "intake", "connector")
SERVICES = ["collector", "connector", "dashboard", "intake", "verdict"]
ROLES = ["collector", "dashboard", "ingest", "intake", "verdict"]

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")


def _text() -> str:
    return MAIN.read_text(encoding="utf-8")


def _attr(body: str, name: str) -> str | None:
    m = re.search(rf"^\s*{name}\s*=\s*(.+)$", _top_level(body), re.M)
    return m.group(1).strip() if m else None


def _resources(kind: str) -> dict[str, str]:
    return {labels[1]: inner for k, labels, inner in _blocks(_text())
            if k == "resource" and labels[0] == kind}


def _locals() -> dict[str, str]:
    """name -> the expression text, for every local in every locals block."""
    out: dict[str, str] = {}
    for k, _, body in _blocks(_text()):
        if k != "locals":
            continue
        starts = list(re.finditer(r"^  (\w+)\s*=", body, re.M))
        for i, m in enumerate(starts):
            out[m.group(1)] = body[m.end():(starts[i + 1].start() if i + 1 < len(starts) else len(body))]
    return out


def _list_literals(expr: str) -> list[list[str]]:
    """Every `[ "a", "b" ]` in an expression, as lists of strings."""
    return [re.findall(r'"(\w+)"', m) for m in re.findall(r"\[([^\[\]]*)\]", expr)]


def _services() -> dict[str, str]:
    services = _resources("google_cloud_run_v2_service")
    assert sorted(services) == SERVICES, sorted(services)
    return services


def _role_secrets() -> dict[str, str]:
    """role -> the expression role_secrets gives it."""
    expr = _locals()["role_secrets"]
    return dict(re.findall(r"^\s*(\w+)\s*=\s*(\S.*?)\s*$", expr, re.M)) | dict(
        re.findall(r"\{\s*(\w+)\s*=\s*(local\.\w+)\s*\}", expr))


def _local_keys(expr: str, defs: dict[str, str], seen: frozenset = frozenset()) -> set[str]:
    """Map keys an expression can produce: literal `NAME = ...` keys, plus
    those of every local it references, recursively."""
    keys = set(re.findall(r"^\s*\{?\s*([A-Z][A-Z0-9_]*)\s*=", expr, re.M))
    keys |= set(re.findall(r"\{\s*([A-Z][A-Z0-9_]*)\s*=", expr))
    keys |= {p + "*" for p in re.findall(r'"([A-Z][A-Z0-9_]*_)\$\{', expr)}
    for ref in set(re.findall(r"\blocal\.(\w+)", expr)) - seen:
        if ref in defs:
            keys |= _local_keys(defs[ref], defs, seen | {ref})
    return keys


def _envs(body: str) -> tuple[list[str], list[str]]:
    """(plain, secret) `for_each` expressions of a container's dynamic env
    blocks. A secret one has a value_source; a plain one has a value."""
    plain, secret = [], []
    for kind, labels, inner in _blocks_deep(body):
        if kind == "dynamic" and labels == ["env"]:
            for_each = re.search(r"for_each\s*=\s*", inner)
            assert for_each, inner
            start = for_each.end()
            if inner[start:].startswith("merge("):
                expr = inner[start:_close(inner, start + len("merge"), "(", ")")]
            else:
                expr = inner[start:inner.index("\n", start)]
            (secret if "value_source" in inner else plain).append(expr)
    return plain, secret


def _blocks_deep(body: str) -> list[tuple[str, list[str], str]]:
    out = []
    for block in _blocks(body):
        out.append(block)
        out.extend(_blocks_deep(block[2]))
    return out


# --- the shape of the module ---------------------------------------------

def test_the_module_is_exactly_main_variables_and_outputs():
    """Every check here reads main.tf. A resource in a fourth file, or in
    variables.tf or outputs.tf, is one none of them sees."""
    assert sorted(f.name for f in MODULE.glob("*.tf")) == ["main.tf", "outputs.tf", "variables.tf"]
    for other in ("outputs.tf", "variables.tf"):
        text = (MODULE / other).read_text(encoding="utf-8")
        assert not re.search(r'^\s*(resource|data|locals)\b', text, re.M), other


def test_the_google_provider_is_one_with_iap_on_cloud_run():
    """`iap_enabled` on google_cloud_run_v2_service first appears in 7.x.
    On an older provider the dashboard's IAP setting is an unknown argument,
    and on none at all a plan could silently pick one."""
    m = re.search(r'google\s*=\s*\{[^}]*version\s*=\s*"~>\s*(\d+)\.\d+"', _text(), re.S)
    assert m, "no pinned google provider"
    assert int(m.group(1)) >= 7


# --- who may call what ---------------------------------------------------

def test_exactly_the_webhook_services_allow_unauthenticated_invocation():
    """Anthropic signs its webhook and authenticates its OTLP export, and a
    laptop sends a bearer token. An IAM invoker check in front of any of
    them turns every call into a 403 before the app sees it. The dashboard
    must never be public."""
    members = _resources("google_cloud_run_v2_service_iam_member")
    public = {n: b for n, b in members.items() if _attr(b, "member") == '"allUsers"'}
    assert sorted(public) == ["connector_public_invoke", "public_invoke"], sorted(public)
    connector = public["connector_public_invoke"]
    assert _attr(connector, "role") == '"roles/run.invoker"'
    assert _attr(connector, "count") == "var.connector_enabled ? 1 : 0"
    assert _attr(connector, "name") == "google_cloud_run_v2_service.connector[0].name"
    body = public["public_invoke"]
    assert _attr(body, "role") == '"roles/run.invoker"'
    assert _attr(body, "for_each") == "toset(local.public_services)"
    assert _attr(body, "name") == "local.service_names[each.key]"

    # With and without intake: exactly the three, or the two.
    lists = _list_literals(_locals()["public_services"])
    assert sorted(map(sorted, lists)) == [["collector", "intake", "verdict"], ["collector", "verdict"]], lists
    assert re.match(r"\s*var\.enable_intake\s*\?\s*\[[^\]]*\"intake\"", _locals()["public_services"])

    # And nothing else in the file grants allUsers or allAuthenticatedUsers.
    text = _text()
    assert text.count('"allUsers"') == 2
    assert "allAuthenticatedUsers" not in text
    assert not _resources("google_cloud_run_v2_service_iam_binding")
    assert not _resources("google_cloud_run_v2_service_iam_policy")


def test_iap_is_on_the_dashboard_and_off_on_the_other_three():
    services = _services()
    for name, body in services.items():
        want = "true" if name == "dashboard" else "false"
        assert _attr(body, "iap_enabled") == want, (name, _attr(body, "iap_enabled"))
    assert len(re.findall(r"\biap_enabled\s*=", _text())) == len(services)


def test_only_the_iap_agent_invokes_the_dashboard_and_people_come_through_iap():
    """With IAP on the service, IAP calls it as its service agent; the people
    allowed are IAP accessors on this service, not invokers and not bound at
    project level."""
    members = _resources("google_cloud_run_v2_service_iam_member")
    on_dashboard = {n: b for n, b in members.items()
                    if _attr(b, "name") == "google_cloud_run_v2_service.dashboard.name"}
    assert sorted(on_dashboard) == ["dashboard_iap_invoke"], sorted(on_dashboard)
    assert _attr(on_dashboard["dashboard_iap_invoke"], "member") == "local.iap_service_agent"
    agent = _locals()["iap_service_agent"]
    assert "@gcp-sa-iap.iam.gserviceaccount.com" in agent and "data.google_project.this.number" in agent

    access = _resources("google_iap_web_cloud_run_service_iam_member")
    assert sorted(access) == ["dashboard_access"], sorted(access)
    body = access["dashboard_access"]
    assert _attr(body, "cloud_run_service_name") == "google_cloud_run_v2_service.dashboard.name"
    assert _attr(body, "role") == '"roles/iap.httpsResourceAccessor"'
    assert _attr(body, "for_each") == "toset(var.dashboard_iap_members)"
    text = _text()
    assert not re.search(r'resource\s+"google_iap_\w+_iam_(binding|policy)"', text)
    assert len(re.findall(r'resource\s+"google_iap_', text)) == 1


def test_the_iap_members_have_no_default_and_refuse_everyone():
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    body = next(inner for k, labels, inner in _blocks(variables)
                if k == "variable" and labels == ["dashboard_iap_members"])
    assert _attr(body, "default") is None
    assert re.search(r"length\(var\.dashboard_iap_members\)\s*>\s*0", body)
    pattern = re.search(r'regex\("(\^\([^"]+)"', body).group(1).replace("\\\\", "\\")
    for ok in ("user:a@example.com", "group:sec@example.com", "domain:example.com"):
        assert re.match(pattern, ok), ok
    for bad in ("allUsers", "allAuthenticatedUsers", "a@example.com", "user:"):
        assert not re.match(pattern, bad), bad


def test_the_dashboard_verifies_the_audience_it_is_given():
    """The audience is IAP's for a service it fronts directly, and the
    dashboard runs with it and platform iap."""
    audience = _locals()["dashboard_iap_audience"].strip()
    assert audience == ('"/projects/${data.google_project.this.number}/locations/${var.region}'
                        '/services/${local.names["dashboard"]}"'), audience
    plain, _ = _envs(_services()["dashboard"])
    env = "".join(plain)
    assert re.search(r'FORGD_DASHBOARD_PLATFORM\s*=\s*"iap"', env)
    assert re.search(r'FORGD_DASHBOARD_AUTH_MODE\s*=\s*"oidc_jwt"', env)
    assert re.search(r"FORGD_DASHBOARD_AUDIENCE\s*=\s*local\.dashboard_iap_audience", env)
    outputs = (MODULE / "outputs.tf").read_text(encoding="utf-8")
    assert re.search(r'output "dashboard_iap_audience"\s*\{\s*value\s*=\s*local\.dashboard_iap_audience', outputs)


# --- identities and IAM --------------------------------------------------

def test_no_iam_is_granted_at_project_level_or_on_the_bucket():
    """Every grant names one service, one job or one secret. A project-level
    role would reach every secret and service in the project, and bucket IAM
    belongs to store-gcs, which binds this module's accounts."""
    text = _text()
    kinds = set(re.findall(r'resource\s+"(\w+)"', text))
    assert kinds, "parsed no resources"
    assert not {k for k in kinds if k.startswith(("google_project_iam", "google_organization_iam",
                                                  "google_folder_iam", "google_storage_",
                                                  "google_service_account_iam"))}, kinds
    iam = {k for k in kinds if "_iam_" in k}
    assert iam == {
        "google_secret_manager_secret_iam_member",
        "google_cloud_run_v2_service_iam_member",
        "google_cloud_run_v2_job_iam_member",
        "google_iap_web_cloud_run_service_iam_member",
    }, iam
    # No role that lets one account act as another, by any resource.
    assert "serviceAccountTokenCreator" not in text and "serviceAccountUser" not in text


def test_each_role_runs_as_its_own_account_and_the_scheduler_as_another():
    accounts = _resources("google_service_account")
    assert sorted(accounts) == ["connector", "role", "scheduler"], sorted(accounts)
    assert _attr(accounts["connector"], "count") == "var.connector_enabled ? 1 : 0"
    assert _attr(accounts["connector"], "account_id") == "local.connector_name"
    assert _attr(accounts["role"], "for_each") == "toset(local.roles)"
    roles = _list_literals(_locals()["roles"])
    assert sorted(map(sorted, roles)) == [
        ["collector", "dashboard", "ingest", "intake", "verdict"],
        ["collector", "dashboard", "ingest", "verdict"]], roles

    for name, body in _services().items():
        sa = _attr(_walk(body, "template")[0], "service_account")
        want = ("google_service_account.connector[0].email" if name == "connector"
                else f'google_service_account.role["{name}"].email')
        assert sa == want, (name, sa)
    job = _resources("google_cloud_run_v2_job")["ingest"]
    assert _attr(_walk(job, "template")[1], "service_account") == 'google_service_account.role["ingest"].email'


def _outputs() -> dict[str, str]:
    outputs = (MODULE / "outputs.tf").read_text(encoding="utf-8")
    return {labels[0]: inner for k, labels, inner in _blocks(outputs) if k == "output"}


def test_the_store_members_are_the_accounts_own_member_strings():
    """Keyed by role, so store-gcs's binding keys do not shift when
    enable_intake changes. `.member` is right for every project id, including
    domain-scoped ones whose account emails do not follow
    `<id>@<project>.iam.gserviceaccount.com`."""
    outputs = _outputs()
    assert _attr(outputs["writer_members"], "value") == (
        "{ for r in local.writer_roles : r => google_service_account.role[r].member }")
    assert _attr(outputs["reader_members"], "value") == (
        'merge(var.dashboard_admins_enabled ? {} : { dashboard = google_service_account.role["dashboard"].member }, '
        'var.connector_enabled ? { connector = google_service_account.connector[0].member } : {})')
    assert _attr(outputs["control_members"], "value") == (
        'var.dashboard_admins_enabled ? { dashboard = google_service_account.role["dashboard"].member } : {}')


@requires_terraform
@pytest.mark.parametrize("intake", [False, True])
def test_the_writer_roles_are_every_role_but_the_dashboard(tmp_path, intake):
    """Evaluated by terraform with no provider, from the module's own locals."""
    defs = _locals()
    main = (
        'variable "enable_intake" { type = bool }\n'
        'variable "name_prefix" { type = string }\n'
        "locals {\n" + "".join(f"  {n} = {defs[n].strip()}\n" for n in ("names", "roles", "writer_roles"))
        + "}\n"
        'output "writer_roles" {\n  value = local.writer_roles\n}\n'
    )
    (tmp_path / "main.tf").write_text(main, encoding="utf-8")
    (tmp_path / "terraform.tfvars.json").write_text(json.dumps(
        {"enable_intake": intake, "name_prefix": "forgd-verdict"}), encoding="utf-8")
    for args in (["init", "-input=false"], ["apply", "-auto-approve", "-input=false"]):
        out = subprocess.run([terraform, f"-chdir={tmp_path}", *args, "-no-color"],
                             capture_output=True, text=True, timeout=120)
        assert out.returncode == 0, out.stderr
    got = json.loads(subprocess.run([terraform, f"-chdir={tmp_path}", "output", "-json"],
                                    capture_output=True, text=True, timeout=60, check=True).stdout)
    writers = ["verdict", "collector", "intake", "ingest"] if intake else ["verdict", "collector", "ingest"]
    assert sorted(got["writer_roles"]["value"]) == sorted(writers), got


def test_each_account_reads_only_its_own_secrets_one_binding_per_secret():
    """The account a role runs as is the one Cloud Run resolves its secrets
    with. A shared account, or a project-level accessor, would let the
    dashboard read the webhook secret, the Compliance key and every OTel
    token."""
    roles = _role_secrets()
    # The dashboard's is the form key and the overrides signing key with
    # admins enabled, and nothing otherwise.
    assert roles.get("dashboard") == "local.dashboard_secrets", roles
    assert " ".join(re.sub(r"(?m)^\s*#.*$", "", _locals()["dashboard_secrets"]).split()) == (
        "var.dashboard_admins_enabled ? { FORGD_DASHBOARD_FORM_KEY = var.dashboard_form_key_secret_id "
        "FORGD_OVERRIDES_SIGNING_KEY = var.dashboard_signing_key_secret_id } : {}")
    assert roles.get("verdict") == "local.verdict_secrets", roles
    assert roles.get("collector") == "local.collector_secrets", roles
    assert roles.get("ingest") == "local.ingest_secrets", roles
    assert roles.get("intake") == "local.intake_all", roles

    access = _resources("google_secret_manager_secret_iam_member")
    assert sorted(access) == ["access"], sorted(access)
    body = access["access"]
    assert _attr(body, "for_each") == "local.secret_access"
    assert _attr(body, "secret_id") == "each.value.secret"
    assert _attr(body, "role") == '"roles/secretmanager.secretAccessor"'
    assert _attr(body, "member") == "google_service_account.role[each.value.role].member"

    pairs = _locals()["secret_access"]
    assert re.search(r"for id in values\(local\.role_secrets\[role\]\)\s*:\s*\{\s*role\s*=\s*role,\s*secret\s*=\s*id\s*\}", pairs), pairs
    assert "for role in local.roles" in pairs
    assert not _resources("google_secret_manager_secret_iam_binding")
    assert not _resources("google_secret_manager_secret_iam_policy")

    # Each container's secret env names exactly its own role's map.
    containers = {**_services(), "ingest": _resources("google_cloud_run_v2_job")["ingest"]}
    for name, body in containers.items():
        _, secret = _envs(body)
        if name == "connector":
            assert secret == [], secret
            assert "value_source" not in body
        else:
            assert [s.strip() for s in secret] == [f'local.role_secrets["{name}"]'], (name, secret)


# The dashboard's secrets with admins enabled.
ADMIN_SECRET_NAMES = {"FORGD_DASHBOARD_FORM_KEY", "FORGD_OVERRIDES_SIGNING_KEY"}


def test_no_secret_is_a_plain_environment_value():
    """A secret goes in as `value_source.secret_key_ref`. As a plain value it
    is in the revision spec and in state, readable by anyone who can view
    the service."""
    defs = _locals()
    containers = {**_services(), "ingest": _resources("google_cloud_run_v2_job")["ingest"]}
    used: set[str] = set()
    for name, body in containers.items():
        plain, secret = _envs(body)
        assert plain, name
        keys = set().union(*(_local_keys(p, defs) for p in plain))
        assert {"FORGD_ROLE", "FORGD_VERDICT_STORE"} <= keys, (name, keys)
        leaked = sorted(k for k in keys if k.rstrip("*") in SECRET_NAMES | ADMIN_SECRET_NAMES
                        or k.rstrip("*").startswith(SECRET_PREFIXES))
        assert not leaked, f"{name} passes {leaked} as plain environment"
        assert not any(re.search(r"var\.\w*secret", p) for p in plain), (name, plain)
        for s in secret:
            role = re.search(r'local\.role_secrets\["(\w+)"\]', s).group(1)
            used |= _local_keys(_role_secrets()[role], defs)
    assert used >= SECRET_NAMES, SECRET_NAMES - used
    assert used >= {p + "*" for p in SECRET_PREFIXES}, used


def test_no_secret_value_is_an_input_or_an_output():
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    names = re.findall(r'variable "(\w+)"', variables)
    # overrides_verify_keys holds public keys, passed as plain environment.
    secretish = [n for n in names if re.search(r"secret|token|salt|key", n) and n != "overrides_verify_keys"]
    assert secretish, names
    assert all(re.search(r"_secret(_previous)?_ids?$", n) for n in secretish), secretish
    assert "sensitive" not in variables
    outputs = (MODULE / "outputs.tf").read_text(encoding="utf-8")
    values = [_attr(inner, "value") for k, _, inner in _blocks(outputs) if k == "output"]
    assert values and all(values), values
    assert not [v for v in values if re.search(r"secret|token|salt", v, re.I)], values


# --- the scheduler -------------------------------------------------------

def test_the_scheduler_may_run_the_ingest_job_and_nothing_else():
    grants = _resources("google_cloud_run_v2_job_iam_member")
    assert sorted(grants) == ["scheduler_runs_ingest"], sorted(grants)
    body = grants["scheduler_runs_ingest"]
    assert _attr(body, "name") == "google_cloud_run_v2_job.ingest.name"
    assert _attr(body, "role") == '"roles/run.invoker"'
    assert _attr(body, "member") == "google_service_account.scheduler.member"
    text = _text()
    # The scheduler account appears in no other grant.
    assert text.count("google_service_account.scheduler.member") == 1

    job = _resources("google_cloud_scheduler_job")["ingest"]
    token = _walk(job, "oauth_token")
    assert len(token) == 1
    assert _attr(token[0], "service_account_email") == "google_service_account.scheduler.email"
    assert "/jobs/${google_cloud_run_v2_job.ingest.name}:run" in job


# --- gitleaksd -------------------------------------------------------------

DAEMON_ROLES = ("verdict", "collector", "intake")


def test_the_daemon_roles_start_gitleaksd_in_their_one_container():
    """As on Container Apps, ECS and the chart: the entrypoint starts
    gitleaksd in the app's container and binds the app only once the socket
    exists, so the app never comes up believing the secrets tier is present
    when it is not. A second container would need its own ordering to make
    the same promise."""
    socket = _locals()["gitleaks_env"]
    assert re.search(r'FORGD_GITLEAKS_SOCKET\s*=\s*"/run/forgd/gitleaksd\.sock"', socket), socket
    for name, body in _services().items():
        containers = _walk(body, "containers")
        assert len(containers) == 1, (name, len(containers))
        plain, _ = _envs(body)
        has = any("local.gitleaks_env" in p for p in plain)
        assert has == (name in DAEMON_ROLES), name
    job = _resources("google_cloud_run_v2_job")["ingest"]
    assert "gitleaks" not in job


def test_the_daemon_roles_wait_out_the_compile_and_restart_on_livez():
    """The entrypoint waits up to 60 s for the socket. A startup probe that
    gave up sooner would kill an instance that was only starting; /livez is
    what answers 503 when the daemon dies."""
    for name in DAEMON_ROLES:
        body = _services()[name]
        start = _walk(body, "startup_probe")
        assert len(start) == 1, name
        assert "local.ready_path" in _walk(start[0], "http_get")[0]
        period = int(_attr(start[0], "period_seconds"))
        failures = int(_attr(start[0], "failure_threshold"))
        assert period * failures > 60, (name, period, failures)
        live = _walk(body, "liveness_probe")
        assert len(live) == 1, name
        assert '"/livez"' in _walk(live[0], "http_get")[0], name
        assert int(_attr(live[0], "failure_threshold")) >= 2, name


def test_the_verdict_server_always_runs():
    """A cold start on the first governed prompt after an idle period is a
    webhook failure, not a slow allow."""
    scaling = _walk(_walk(_services()["verdict"], "template")[0], "scaling")
    assert len(scaling) == 1
    count = _attr(scaling[0], "min_instance_count")
    assert count is not None and count.isdigit() and int(count) >= 1, count


# --- releases ------------------------------------------------------------

def _ignored(body: str) -> list[str]:
    lifecycles = _walk(body, "lifecycle")
    assert len(lifecycles) == 1, f"{len(lifecycles)} lifecycle blocks"
    return [e.strip() for e in _bracket(lifecycles[0], "ignore_changes").split(",") if e.strip()]


def test_every_service_and_the_job_leave_the_image_to_ci():
    """CI rolls the image. A service that tracks it rolls back to the image
    of the first apply on the next `terraform apply`."""
    for name, body in _services().items():
        assert len(_walk(body, "containers")) == 1, name
        assert "template[0].containers[0].image" in _ignored(body), name
    jobs = _resources("google_cloud_run_v2_job")
    assert sorted(jobs) == ["ingest"], sorted(jobs)
    assert len(_walk(jobs["ingest"], "containers")) == 1
    assert "template[0].template[0].containers[0].image" in _ignored(jobs["ingest"])


def test_every_service_and_the_job_take_deletion_protection_from_one_variable():
    """Left at the provider's default, nothing in the module could turn it
    off, and turning enable_intake off would fail with no way through."""
    targets = {**_services(), **_resources("google_cloud_run_v2_job")}
    assert "ingest" in targets
    for name, body in targets.items():
        assert _attr(body, "deletion_protection") == "var.deletion_protection", name
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    block = re.search(r'variable "deletion_protection" \{(.*?)\n\}', variables, re.S)
    assert block and re.search(r"^\s*default\s*=\s*true\s*$", block.group(1), re.M), block


# --- the findings connector ------------------------------------------------

CONNECTOR_LOCALS = {"connector_name", "connector_host", "connector_resource",
                    "connector_resource_malformed", "connector_env"}
CONNECTOR_RESOURCES = ["google_cloud_run_v2_service.connector",
                       "google_cloud_run_v2_service_iam_member.connector_public_invoke",
                       "google_service_account.connector"]
# The one pre-existing block the connector changes, reader_members: (now, before).
READER_MEMBERS_WAS = 'var.dashboard_admins_enabled ? {} : { dashboard = google_service_account.role["dashboard"].member }'
READER_MEMBERS_NOW = (f'merge({READER_MEMBERS_WAS}, '
                      'var.connector_enabled ? { connector = google_service_account.connector[0].member } : {})')
OUTPUT_EDITS = [
    ("merge({ for role, sa in google_service_account.role : role => sa.email }, var.connector_enabled ? "
     "{ connector = google_service_account.connector[0].email } : {})",
     "{ for role, sa in google_service_account.role : role => sa.email }"),
    (" ci-gcp's cloudrun.runtime_service_accounts takes these values.", ""),
    (READER_MEMBERS_NOW, READER_MEMBERS_WAS),
    ("The dashboard's (unless dashboard_admins_enabled) and (with connector_enabled) the connector's accounts by role",
     "The dashboard's (unless dashboard_admins_enabled) account by role"),
]

PROJECT_NUMBER = "123456789012"
DERIVED = f"https://forgd-verdict-connector-{PROJECT_NUMBER}.europe-west2.run.app/mcp"
SECRET = "projects/p/secrets/"
REQUIRED = {
    "project_id": "example-project", "region": "europe-west2",
    "image": "europe-west2-docker.pkg.dev/p/r/fv:1", "ingest_image": "europe-west2-docker.pkg.dev/p/r/fv:1-ingest",
    "store_url": "gs://findings", "hash_salt_secret_id": SECRET + "salt",
    "webhook_secret_id": SECRET + "webhook", "otel_token_secret_ids": {"primary": SECRET + "otel"},
    "org_ids": {"primary": "00000000-0000-0000-0000-00000000000a"},
    "compliance_key_secret_id": SECRET + "compliance", "dashboard_iap_members": ["group:sec@example.com"],
    "policy_yaml": "version: 1\n",
}
ON = {
    "connector_enabled": True,
    "connector_issuer": "https://login.example.com/tenant/v2.0",
    "connector_jwks_url": "https://login.example.com/tenant/discovery/v2.0/keys",
    "connector_audience": ["api-client-id"],
    "connector_required_scope": "findings.read",
}
ALL = {**ON, "connector_scopes": ["findings.read"], "connector_allowed_origins": ["https://claude.ai"],
       "connector_groups_claim": "roles",
       "connector_issuers": [{"issuer": ON["connector_issuer"], "jwks_url": ON["connector_jwks_url"],
                              "audience": ["api-client-id"]}]}
REF = re.compile(r"\b(?:data\.)?google_\w+\.\w+(?:\[[^\]]+\])?(?:\.\w+(?:\[\d+\])?)*")


def _files() -> dict[str, str]:
    return {n: (MODULE / n).read_text(encoding="utf-8") for n in ("main.tf", "variables.tf", "outputs.tf")}


def _left_out() -> dict[str, str]:
    """The module's three files with the connector's blocks and settings
    removed and reader_members as it was."""
    import test_app_aca as aca
    files = _files()
    main = aca._without(files["main.tf"], lambda k, labels, inner: (
        k == "locals" and set(re.findall(r"^  (\w+)\s*=", inner, re.M)) <= CONNECTOR_LOCALS)
        or (k == "resource" and ".".join(labels) in CONNECTOR_RESOURCES))
    variables = aca._without(files["variables.tf"],
                             lambda k, labels, _: k == "variable" and labels[0].startswith("connector_"))
    outputs = aca._without(files["outputs.tf"], lambda k, labels, _: k == "output" and labels in (
        ["connector_url"], ["connector_service_name"]))
    for now, before in OUTPUT_EDITS:
        assert outputs.count(now) == 1, now
        outputs = outputs.replace(now, before)
    return {"main.tf": main, "variables.tf": variables, "outputs.tf": outputs}


def _evaluate(root: Path, files: dict[str, str], **variables) -> dict:
    import test_app_aca as aca
    return aca._evaluate(root, files, required=REQUIRED, ref=REF, **variables)


def _connector() -> str:
    return _services()["connector"]


def test_the_connector_is_off_by_default_and_every_setting_has_a_default():
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    bodies = {labels[0]: inner for k, labels, inner in _blocks(variables) if k == "variable"}
    connector = sorted(n for n in bodies if n.startswith("connector_"))
    assert len(connector) == 10, connector
    assert _attr(bodies["connector_enabled"], "default") == "false"
    for name in connector:
        assert _attr(bodies[name], "default") is not None, name


def test_leaving_the_connector_out_removes_every_mention_of_it():
    for name, text in _left_out().items():
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        assert "connector" not in code, name


def test_nothing_outside_the_connector_depends_on_it_but_reader_members():
    import test_app_aca as aca
    ref = re.compile(r"var\.connector_|local\.connector_|\.connector\b|\.connector\[")
    own = []
    for k, labels, inner in _blocks(_text()):
        if k == "locals":
            for name, expr in aca._assignments(inner).items():
                if name not in CONNECTOR_LOCALS:
                    assert not ref.search(expr), name
        elif ref.search(inner):
            own.append(".".join(labels))
    assert sorted(own) == CONNECTOR_RESOURCES, own
    for name in CONNECTOR_RESOURCES:
        kind, label = name.split(".")
        assert _attr(_resources(kind)[label], "count") == "var.connector_enabled ? 1 : 0", name
    uses = sorted(n for n, body in _outputs().items() if ref.search(body))
    assert uses == ["connector_service_name", "connector_url", "reader_members", "service_account_emails"], uses
    assert _attr(_outputs()["connector_url"], "value") == "var.connector_enabled ? local.connector_resource : null"


@requires_terraform
@pytest.mark.parametrize("intake", [False, True])
def test_off_evaluates_exactly_as_the_module_with_the_connector_left_out(tmp_path, intake):
    extra = {"enable_intake": intake, "org_ids": {"primary": "00000000-0000-0000-0000-00000000000a", "prod": "00000000-0000-0000-0000-00000000000b"},
             "metrics_token_secret_id": SECRET + "metrics"}
    got = _evaluate(tmp_path / "off", _files(), **extra)
    before = _evaluate(tmp_path / "left-out", _left_out(), **extra)
    assert {k: v for k, v in got["locals"].items() if k not in CONNECTOR_LOCALS} == before["locals"]
    assert {k: v for k, v in got["resources"].items() if k not in CONNECTOR_RESOURCES} == before["resources"]
    assert all(got["resources"][r] == [] for r in CONNECTOR_RESOURCES), got["resources"]
    rest = lambda d: {k: v for k, v in d.items() if k not in ("locals", "resources")}  # noqa: E731
    assert rest(got) == rest(before)
    assert "o_connector_url" not in got and "o_connector_service_name" not in got


@requires_terraform
def test_on_adds_the_connector_on_a_reader_account_and_nothing_else(tmp_path):
    got = _evaluate(tmp_path / "on", _files(), **ON)
    before = _evaluate(tmp_path / "left-out", _left_out())
    assert got["resources"] == {**before["resources"], **{r: ["0"] for r in CONNECTOR_RESOURCES}}
    # A reader, not a writer, and no secret access.
    assert got["o_reader_members"] == {**before["o_reader_members"], "connector": "ref"}
    assert got["o_writer_members"] == before["o_writer_members"]
    assert "connector" not in got["o_writer_members"]
    assert not [k for k in got["locals"]["secret_access"] if "connector" in k]
    assert got["o_connector_url"] == "https://forgd-verdict-connector-ref.europe-west2.run.app/mcp"
    assert got["o_connector_service_name"] == "ref"
    assert got["o_service_account_emails"] == {**before["o_service_account_emails"], "connector": "ref"}
    rest = lambda d: {k: v for k, v in d.items()  # noqa: E731
                      if k not in ("locals", "resources", "o_reader_members", "o_connector_url",
                                   "o_connector_service_name", "o_service_account_emails")}
    assert rest(got) == rest(before)


def test_it_is_public_with_iap_off():
    body = _connector()
    assert _attr(body, "ingress") == '"INGRESS_TRAFFIC_ALL"'
    assert _attr(body, "iap_enabled") == "false"
    invoke = _resources("google_cloud_run_v2_service_iam_member")["connector_public_invoke"]
    assert (_attr(invoke, "member"), _attr(invoke, "role")) == ('"allUsers"', '"roles/run.invoker"')
    assert "connector" not in "".join(_resources("google_iap_web_cloud_run_service_iam_member").values())


def test_it_runs_as_its_own_account_with_no_salt_and_no_secret():
    body = _connector()
    assert _attr(_walk(body, "template")[0], "service_account") == "google_service_account.connector[0].email"
    plain, secret = _envs(body)
    assert secret == [] and "value_source" not in body
    assert [p.strip() for p in plain] == ["merge(local.base_env, local.connector_env)"]
    assert "FORGD_HASH_SALT" not in _local_keys(plain[0], _locals())
    assert "local.gitleaks_env" not in body


def test_it_runs_the_same_image_as_the_connector_role_and_leaves_it_to_ci():
    body = _connector()
    [container] = _walk(body, "containers")
    assert _attr(container, "image") == "var.image"
    assert _attr(_walk(container, "ports")[0], "container_port") == "8090"
    assert re.search(r'FORGD_ROLE\s*=\s*"connector"', _locals()["connector_env"])
    assert re.search(r"^\s*connector\)", (ROOT / "deploy" / "entrypoint.sh").read_text(), re.M)
    assert _ignored(body) == ["template[0].containers[0].image", "client", "client_version"]


# Set by the platform, or by the chart only.
CHART_ONLY = {"PORT": "Cloud Run sets it to the container port",
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
    assert set(env) ^ rendered == {"FORGD_POLICY_INLINE_GZ"} | set(CHART_ONLY), set(env) ^ rendered
    assert {n for n in env if n.startswith("FORGD_CONNECTOR_")} == {
        n for n in ENV_OVERRIDES if n.startswith("FORGD_CONNECTOR_")}
    assert env["FORGD_CONNECTOR_AUDIENCE"] == '["api-client-id"]'
    assert json.loads(env["FORGD_CONNECTOR_ISSUERS"]) == [
        {**ALL["connector_issuers"][0], "groups_claim": ""}]
    assert env["FORGD_CONNECTOR_AUTH_MODE"] == "oidc_jwt"


# --- the refusals, evaluated by terraform ----------------------------------------

def _preconditions() -> list[tuple[str, str]]:
    [lifecycle] = _walk(_connector(), "lifecycle")
    out = [(_attr(b, "condition"), _attr(b, "error_message")) for b in _walk(lifecycle, "precondition")]
    assert len(out) == 10, out
    return out


def _harness(root: Path, preconditions: list[tuple[str, str]]) -> Path:
    """variables.tf, the connector's locals and its preconditions, on a
    terraform_data resource with the connector's own count."""
    import test_app_aca as aca
    root.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULE / "variables.tf", root / "variables.tf")
    defs = {n: e for block in (inner for k, _, inner in _blocks(_text()) if k == "locals")
            for n, e in aca._assignments(block).items() if n in CONNECTOR_LOCALS}
    assert set(defs) == CONNECTOR_LOCALS, sorted(defs)
    checks = "".join(f"    precondition {{\n      condition     = {c}\n      error_message = {m}\n    }}\n"
                     for c, m in preconditions)
    (root / "main.tf").write_text(
        'variable "test_project_number" { type = string }\n'
        "locals {\n" + "".join(
            f"  {n} = {e.replace('data.google_project.this.number', 'var.test_project_number')}\n"
            for n, e in defs.items()) + "}\n"
        'resource "terraform_data" "connector" {\n'
        f"  count = {_attr(_connector(), 'count')}\n"
        "  lifecycle {\n" + checks + "  }\n}\n"
        'output "resource" { value = local.connector_resource }\n',
        encoding="utf-8")
    out = subprocess.run([terraform, f"-chdir={root}", "init", "-input=false", "-no-color"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return root


def _plan(root: Path, **variables) -> subprocess.CompletedProcess:
    (root / "terraform.tfvars.json").write_text(
        json.dumps({**REQUIRED, "test_project_number": PROJECT_NUMBER, **variables}), encoding="utf-8")
    return subprocess.run([terraform, f"-chdir={root}", "plan", "-input=false", "-no-color",
                           "-lock=false", "-refresh=false"], capture_output=True, text=True, timeout=120)


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    return _harness(tmp_path_factory.mktemp("cloudrun"), _preconditions())


@requires_terraform
def test_the_connector_off_plans_with_nothing_set(harness):
    out = _plan(harness)
    assert out.returncode == 0, out.stderr
    assert "terraform_data.connector" not in out.stdout


@requires_terraform
def test_the_connector_on_derives_the_deterministic_url_at_plan(harness):
    out = _plan(harness, **ON)
    assert out.returncode == 0, out.stderr
    assert f'resource = "{DERIVED}"' in out.stdout


@requires_terraform
@pytest.mark.parametrize("variables", [
    {"connector_resource": DERIVED},
    {"connector_issuer": "", "connector_jwks_url": "", "connector_audience": [],
     "connector_issuers": ALL["connector_issuers"]},
    {"connector_required_scope": "", "policy_yaml": "connector:\n  required_scope: findings.read\n"},
], ids=["the derived url given", "issuers", "a scope from policy.yaml"])
def test_the_connector_on_accepts(harness, variables):
    out = _plan(harness, **{**ON, **variables})
    assert out.returncode == 0, out.stderr


# Each case trips exactly one precondition, named by a fragment of its message.
REFUSALS = {
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
    "not lowercase": ({"connector_resource": DERIVED.replace("connector", "Connector")}, "must be lowercase"),
    "not /mcp": ({"connector_resource": DERIVED + "/"}, "must end in /mcp"),
    "another host": ({"connector_resource": "https://mcp.example.com/mcp"}, "does not match https://"),
    "another project number": ({"connector_resource": DERIVED.replace(PROJECT_NUMBER, "999")},
                               "does not match https://"),
}


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_fires_at_plan(harness, case):
    variables, fragment = REFUSALS[case]
    out = _plan(harness, **{**ON, **variables})
    assert out.returncode != 0, out.stdout
    assert fragment in " ".join(out.stderr.split()), out.stderr


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_is_its_own_precondition(tmp_path, case):
    """Drop the precondition the case names and the same plan goes through,
    so no case passes on the back of a different guard."""
    variables, fragment = REFUSALS[case]
    kept = [(c, m) for c, m in _preconditions() if fragment not in m]
    assert len(kept) == 9, case
    out = _plan(_harness(tmp_path, kept), **{**ON, **variables})
    assert out.returncode == 0, out.stderr


def test_every_precondition_has_a_refusal():
    fragments = {f for _, f in REFUSALS.values()}
    for _, message in _preconditions():
        assert sum(f in message for f in fragments) == 1, message


# --- each OTel token needs its org's id --------------------------------------------

ORG_EU = "00000000-0000-0000-0000-00000000000d"


def _render_tokens(tmp_path, org_ids: dict) -> dict:
    import terraform_render
    return terraform_render.render_module(tmp_path, "app-cloudrun", {
        **REQUIRED, "org_ids": org_ids, "otel_token_secret_ids": {"eu-west": SECRET + "otel-eu"}})


@requires_terraform
@pytest.mark.parametrize(("org_ids", "message"), [
    ({}, r"otel_token_secret_ids\.eu-west has no non-empty org_ids entry"),
    ({"primary": "00000000-0000-0000-0000-00000000000a"}, r"otel_token_secret_ids\.eu-west has no non-empty org_ids entry"),
    ({"eu-west": ""}, r"org_ids\.eu-west is not an organization UUID"),
], ids=["no-orgs", "another-org", "empty-id"])
def test_a_token_without_an_org_id_is_refused(tmp_path, org_ids, message):
    with pytest.raises(AssertionError, match=message):
        _render_tokens(tmp_path, org_ids)


@requires_terraform
def test_a_token_matched_through_the_env_name_is_accepted(tmp_path):
    rendered = _render_tokens(tmp_path, {"EU_WEST": ORG_EU})
    [template] = rendered["google_cloud_run_v2_service.collector"]["template"]
    [container] = template["containers"]
    env = {e["name"]: e for e in container["env"]}
    assert env["FORGD_ORG_ID_EU_WEST"]["value"] == ORG_EU
    assert env["FORGD_OTEL_TOKEN_EU_WEST"]["value_source"]


@requires_terraform
@pytest.mark.parametrize("value", ["", "not-a-uuid-SENTINEL"], ids=["empty", "word"])
def test_an_org_id_that_is_not_a_uuid_is_refused(tmp_path, value):
    with pytest.raises(AssertionError, match=r"org_ids\.eu-west is not an organization UUID") as raised:
        _render_tokens(tmp_path, {"eu-west": value})
    assert "SENTINEL" not in str(raised.value)


# --- the fleet's intake token ---------------------------------------------


def _intake_env(tmp_path, **variables) -> dict:
    import terraform_render
    rendered = terraform_render.render_module(tmp_path, "app-cloudrun", {
        **REQUIRED, "enable_intake": True, **variables})
    [service] = rendered["google_cloud_run_v2_service.intake"]
    [template] = service["template"]
    [app] = [c for c in template["containers"]
             if any(e["name"] == "FORGD_HASH_SALT" for e in c.get("env", []))]
    return {e["name"]: e for e in app["env"]}


@requires_terraform
def test_the_fleet_token_and_its_predecessor_reach_the_intake(tmp_path):
    env = _intake_env(
        tmp_path, intake_fleet_token_secret_id=SECRET + "fleet",
        intake_fleet_token_previous_secret_id=SECRET + "fleet-old",
        intake_token_secret_ids={"invoice-bot": SECRET + "bot"})
    for name in ("FORGD_INTAKE_FLEET_TOKEN", "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS",
                 "FORGD_INTAKE_TOKEN_INVOICE_BOT"):
        assert env[name]["value_source"], name


@requires_terraform
def test_without_a_previous_fleet_token_none_is_wired(tmp_path):
    env = _intake_env(tmp_path, intake_fleet_token_secret_id=SECRET + "fleet")
    assert "FORGD_INTAKE_FLEET_TOKEN" in env
    assert "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS" not in env


@requires_terraform
def test_a_fleet_token_that_is_not_a_secret_id_is_refused(tmp_path):
    with pytest.raises(AssertionError, match="intake_fleet_token_secret_id must be empty or"):
        _intake_env(tmp_path, intake_fleet_token_secret_id="fleet-token-value")


# --- per-org signing secrets, Compliance Access Keys and fleet tokens ------

PROD = "00000000-0000-0000-0000-00000000000c"


def _secret_env(rendered: dict, address: str) -> dict:
    [resource] = rendered[address] if isinstance(rendered[address], list) else [rendered[address]]
    [template] = resource["template"]
    if "template" in template:
        [template] = template["template"]
    [app] = [c for c in template["containers"]
             if any(e["name"] == "FORGD_HASH_SALT" for e in c.get("env", []))]
    return {e["name"]: e["value_source"][0]["secret_key_ref"][0]["secret"]
            for e in app["env"] if e.get("value_source")}


def _render_org(tmp_path, **variables) -> dict:
    import terraform_render
    return terraform_render.render_module(tmp_path, "app-cloudrun", {
        **REQUIRED, "org_ids": {**REQUIRED["org_ids"], "prod": PROD}, **variables})


VERDICT = "google_cloud_run_v2_service.verdict"
INGEST = "google_cloud_run_v2_job.ingest"


@requires_terraform
def test_each_org_gets_its_signing_secret_and_its_previous_one(tmp_path):
    rendered = _render_org(tmp_path, webhook_secret_ids={
        "prod": {"current": SECRET + "wh-prod", "previous": SECRET + "wh-prod-old"}})
    env = _secret_env(rendered, VERDICT)
    assert env["WEBHOOK_SECRET_PROD"] == SECRET + "wh-prod"
    assert env["WEBHOOK_SECRET_PROD_PREVIOUS"] == SECRET + "wh-prod-old"
    assert env["WEBHOOK_SECRET"] == REQUIRED["webhook_secret_id"]
    access = [r for k, r in rendered.items() if k.startswith("google_secret_manager_secret_iam_member.access")]
    assert SECRET + "wh-prod-old" in json.dumps(access)


@requires_terraform
def test_an_org_without_a_previous_secret_gets_no_previous_variable(tmp_path):
    env = _secret_env(_render_org(tmp_path, webhook_secret_ids={"prod": {"current": SECRET + "wh-prod"}}), VERDICT)
    assert "WEBHOOK_SECRET_PROD" in env and "WEBHOOK_SECRET_PROD_PREVIOUS" not in env


@requires_terraform
def test_with_per_org_secrets_the_single_slot_may_be_empty(tmp_path):
    env = _secret_env(_render_org(tmp_path, webhook_secret_id="", compliance_key_secret_id="",
                                  webhook_secret_ids={"prod": {"current": SECRET + "wh-prod"}},
                                  compliance_key_secret_ids={"prod": SECRET + "ck-prod"}), VERDICT)
    assert "WEBHOOK_SECRET" not in env and "WEBHOOK_SECRET_PROD" in env


@requires_terraform
@pytest.mark.parametrize(("variables", "message"), [
    ({"webhook_secret_id": ""}, "webhook_secret_id is empty and webhook_secret_ids names no org"),
    ({"compliance_key_secret_id": ""}, "compliance_key_secret_id is empty and compliance_key_secret_ids names no org"),
], ids=["webhook", "compliance"])
def test_with_no_per_org_secret_the_single_slot_is_required(tmp_path, variables, message):
    with pytest.raises(AssertionError, match=message):
        _render_org(tmp_path, **variables)


@requires_terraform
def test_each_org_gets_its_compliance_key_and_no_previous(tmp_path):
    env = _secret_env(_render_org(tmp_path, compliance_key_secret_ids={"prod": SECRET + "ck-prod"}), INGEST)
    assert env["ANTHROPIC_COMPLIANCE_ACCESS_KEY_PROD"] == SECRET + "ck-prod"
    assert not any(n.endswith("_PREVIOUS") for n in env if n.startswith("ANTHROPIC_"))


@requires_terraform
def test_each_org_fleet_gets_its_token_and_its_previous_one(tmp_path):
    env = _intake_env(tmp_path, org_ids={**REQUIRED["org_ids"], "prod": PROD},
                      intake_fleet_token_secret_ids={"prod": {
                          "current": SECRET + "fleet-prod", "previous": SECRET + "fleet-prod-old"}})
    assert env["FORGD_INTAKE_FLEET_TOKEN_PROD"]["value_source"][0]["secret_key_ref"][0]["secret"] == SECRET + "fleet-prod"
    assert "FORGD_INTAKE_FLEET_TOKEN_PROD_PREVIOUS" in env


ORG_MAPS = {
    "webhook_secret_ids": lambda n: {"current": SECRET + f"wh-{n}"},
    "compliance_key_secret_ids": lambda n: SECRET + f"ck-{n}",
    "intake_fleet_token_secret_ids": lambda n: {"current": SECRET + f"fl-{n}"},
}


def _with_org_map(variable: str, *names: str, ids: dict | None = None) -> dict:
    ids = ids if ids is not None else {n: PROD for n in names}
    return {"enable_intake": True, "org_ids": {**REQUIRED["org_ids"], **ids},
            variable: {n: ORG_MAPS[variable](n.replace("_", "-")) for n in names}}


@requires_terraform
@pytest.mark.parametrize("variable", ORG_MAPS)
def test_a_per_org_secret_for_a_name_not_in_org_ids_is_refused(tmp_path, variable):
    with pytest.raises(AssertionError, match=rf"{variable}\.eu has no org_ids entry"):
        _render_org(tmp_path, **_with_org_map(variable, "eu", ids={}))


@requires_terraform
@pytest.mark.parametrize("variable", ["webhook_secret_ids", "intake_fleet_token_secret_ids"])
def test_an_org_named_previous_collides_with_the_single_slot(tmp_path, variable):
    with pytest.raises(AssertionError, match=r"collides.*_PREVIOUS"):
        _render_org(tmp_path, **_with_org_map(variable, "previous"))


@requires_terraform
@pytest.mark.parametrize("variable", ["webhook_secret_ids", "intake_fleet_token_secret_ids"])
def test_an_org_and_its_previous_name_collide(tmp_path, variable):
    with pytest.raises(AssertionError, match=r"collides.*_A_PREVIOUS"):
        _render_org(tmp_path, **_with_org_map(variable, "a", "a-previous"))


@requires_terraform
@pytest.mark.parametrize("variable", ORG_MAPS)
def test_two_names_for_one_variable_collide(tmp_path, variable):
    with pytest.raises(AssertionError, match=r"Two .* keys map to the same|collides.*_A_B"):
        _render_org(tmp_path, **_with_org_map(variable, "a-b", "a_b", ids={"a-b": PROD}))


@requires_terraform
@pytest.mark.parametrize("variables", [{}, {"enable_intake": True}, {"enable_intake": True, **ON}],
                         ids=["required", "intake", "intake-connector"])
def test_the_module_plans_as_it_did_at_v0_46_0_with_no_per_org_maps(tmp_path, variables):
    import terraform_render
    assert terraform_render.versus_commit(tmp_path, "app-cloudrun", {**REQUIRED, **variables}, "a9a62907") == []
