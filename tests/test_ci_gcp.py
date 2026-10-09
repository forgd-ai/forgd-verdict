"""The ci-gcp module: the CD account can roll a release and do nothing else.

Parsed from the .tf source, because nothing here may call GCP and a plan
needs credentials. Each check first asserts it found what it is about, so a
rename or a parse that matches nothing fails rather than passing on an
empty list.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml
from test_app_ecs import _attr, _blocks, _close

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "deploy" / "terraform" / "modules" / "ci-gcp"
MAIN = MODULE / "main.tf"
VARIABLES = MODULE / "variables.tf"
OUTPUTS = MODULE / "outputs.tf"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

FORBIDDEN_ROLE = re.compile(r"storage|editor|owner|run\.admin", re.I)

# Resource types that bind a role above a single resource.
BROAD_IAM = re.compile(r"^google_(project|folder|organization)_iam_")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _resources() -> dict[tuple[str, str], str]:
    """(type, name) -> body, for every resource in main.tf."""
    return {(labels[0], labels[1]): inner for k, labels, inner in _blocks(_text(MAIN)) if k == "resource"}


def _iam_members() -> dict[tuple[str, str], str]:
    found = {key: body for key, body in _resources().items() if _attr(body, "role") is not None}
    assert found, "parsed no IAM members"
    return found


def _role(body: str) -> str:
    return _attr(body, "role").strip('"')


def _locals() -> dict[str, str]:
    body = next(inner for k, _, inner in _blocks(_text(MAIN)) if k == "locals")
    starts = list(re.finditer(r"^  (\w+)\s*=", body, re.M))
    body_of = {m.group(1): body[m.end():(starts[i + 1].start() if i + 1 < len(starts) else len(body))]
               for i, m in enumerate(starts)}
    return {name: re.sub(r"^\s*#.*$", "", expr, flags=re.M).strip() for name, expr in body_of.items()}


def _variable_default(name: str) -> str | None:
    """The default literal of variables.tf's `name`, or None if it has none."""
    (body,) = [inner for k, labels, inner in _blocks(_text(VARIABLES))
               if k == "variable" and labels == [name]]
    return _attr(body, "default")


def _provider() -> str:
    return _resources()[("google_iam_workload_identity_pool_provider", "github")]


# --- the shape of the module ---------------------------------------------

def test_the_module_is_exactly_main_variables_and_outputs():
    """Every check here reads main.tf. A resource in a fourth file, or in
    variables.tf or outputs.tf, is one none of them sees."""
    files = sorted(p.name for p in MODULE.iterdir() if p.is_file() and not p.name.startswith("."))
    assert files == ["main.tf", "outputs.tf", "variables.tf"], files
    for other in (OUTPUTS, VARIABLES):
        assert not re.search(r"^\s*(resource|data|locals|module)\b", _text(other), re.M), other.name


def test_every_iam_member_is_a_member_resource():
    """A _binding or _policy resource replaces everyone else's grants on
    the resource, and would hide from the checks below that read _member."""
    types = {t for t, _ in _resources()}
    assert not [t for t in types if re.search(r"_iam_(binding|policy)$", t)], sorted(types)
    for (t, name), _ in _iam_members().items():
        assert t.endswith("_iam_member"), (t, name)


# --- who may impersonate it ----------------------------------------------

def test_the_provider_admits_one_environment_of_one_repository():
    provider = _provider()
    m = re.search(r'attribute_condition\s*=\s*join\("\s*&&\s*",\s*\[', provider)
    assert m, "attribute_condition is not a join of clauses"
    clauses = _strings(provider[m.end():_close(provider, m.end() - 1, "[", "]") - 1])
    assert clauses == [
        "assertion.repository_id == ${jsonencode(var.github_repository_id)}",
        "assertion.repository_owner_id == ${jsonencode(var.github_owner_id)}",
        "assertion.environment == ${jsonencode(var.github_environment)}",
    ], clauses
    assert _variable_default("github_environment") == '"verdict-cd-gcp"'

    (oidc,) = [inner for k, _, inner in _blocks(provider) if k == "oidc"]
    assert _attr(oidc, "issuer_uri") == '"https://token.actions.githubusercontent.com"'
    assert _attr(oidc, "allowed_audiences") is None


def test_the_attributes_the_condition_reads_are_mapped():
    mapping = dict(re.findall(r'"((?:google|attribute)\.\w+)"\s*=\s*"([^"]+)"', _provider()))
    assert mapping == {
        "google.subject": "assertion.sub",
        "attribute.repository_id": "assertion.repository_id",
        "attribute.repository_owner_id": "assertion.repository_owner_id",
        "attribute.environment": "assertion.environment",
    }, mapping


def test_workload_identity_user_is_granted_to_the_repository_principal_set_only():
    grants = {key: body for key, body in _iam_members().items() if _role(body) == "roles/iam.workloadIdentityUser"}
    assert list(grants) == [("google_service_account_iam_member", "deploy_workload_identity")], sorted(grants)
    (body,) = grants.values()
    assert _attr(body, "service_account_id") == "google_service_account.deploy.name"
    assert _attr(body, "member") == "local.deployer_member"
    assert _attr(body, "for_each") is None and _attr(body, "count") is None
    assert _locals()["deployer_member"] == (
        '"principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}'
        '/attribute.repository_id/${var.github_repository_id}"'
    )
    # And no token-minting role on anything.
    assert "serviceAccountTokenCreator" not in _text(MAIN)


def test_every_other_grant_is_to_the_cd_account():
    for key, body in _iam_members().items():
        if key[1] == "deploy_workload_identity":
            continue
        assert _attr(body, "member") == "google_service_account.deploy.member", key


def test_the_repository_ids_have_no_default_and_must_be_numeric():
    variables = {labels[0]: inner for k, labels, inner in _blocks(_text(VARIABLES)) if k == "variable"}
    for name in ("github_repository_id", "github_owner_id", "project_id", "artifact_registry"):
        assert name in variables, name
        assert _attr(variables[name], "default") is None, name
    for name in ("github_repository_id", "github_owner_id"):
        assert _attr(variables[name], "type") == "string", name
        assert f'can(regex("^[0-9]+$", var.{name}))' in variables[name], name


# --- what it may do ------------------------------------------------------

def test_no_role_is_storage_editor_owner_or_run_admin():
    roles = re.findall(r'"(roles/[^"]+)"', _text(MAIN))
    assert "roles/run.developer" in roles, roles
    assert [r for r in roles if FORBIDDEN_ROLE.search(r)] == [], roles


def test_the_roles_granted_are_exactly_these():
    assert sorted({(t, _role(body)) for (t, _), body in _iam_members().items()}) == [
        ("google_artifact_registry_repository_iam_member", "roles/artifactregistry.writer"),
        ("google_cloud_run_v2_job_iam_member", "roles/run.developer"),
        ("google_cloud_run_v2_service_iam_member", "roles/run.developer"),
        ("google_project_iam_member", "roles/container.clusterViewer"),
        ("google_service_account_iam_member", "roles/iam.serviceAccountUser"),
        ("google_service_account_iam_member", "roles/iam.workloadIdentityUser"),
    ]


def test_the_only_project_level_grant_is_gke_and_only_with_gke():
    broad = {key: body for key, body in _resources().items() if BROAD_IAM.match(key[0])}
    assert list(broad) == [("google_project_iam_member", "deploy_gke")], sorted(broad)
    (body,) = broad.values()
    assert _role(body) == "roles/container.clusterViewer"
    assert _attr(body, "count") == "var.gke == null ? 0 : 1"
    assert _attr(body, "condition") is None


def test_service_account_user_is_only_on_the_listed_runtime_accounts():
    text = _text(MAIN)
    assert text.count("roles/iam.serviceAccountUser") == 1
    grants = {key: body for key, body in _iam_members().items() if _role(body) == "roles/iam.serviceAccountUser"}
    assert list(grants) == [("google_service_account_iam_member", "deploy_act_as")], sorted(grants)
    (body,) = grants.values()
    assert _attr(body, "for_each") == "local.runtime_accounts"
    assert _attr(body, "service_account_id") == '"projects/${var.project_id}/serviceAccounts/${each.value}"'
    assert _locals()["runtime_accounts"] == \
        "var.cloudrun == null ? toset([]) : toset(var.cloudrun.runtime_service_accounts)"


def test_each_grant_names_one_resource_from_an_input():
    members = _iam_members()
    ar = members[("google_artifact_registry_repository_iam_member", "deploy")]
    assert _attr(ar, "repository") == "var.artifact_registry.repository_id"
    service = members[("google_cloud_run_v2_service_iam_member", "deploy")]
    assert _attr(service, "for_each") == "local.cloudrun_services"
    assert _attr(service, "name") == "each.value"
    assert _locals()["cloudrun_services"] == "var.cloudrun == null ? {} : var.cloudrun.services"
    job = members[("google_cloud_run_v2_job_iam_member", "deploy")]
    assert _attr(job, "name") == "var.cloudrun.ingest_job"
    assert _attr(job, "count") == "var.cloudrun == null ? 0 : 1"
    assert '"*"' not in _text(MAIN)


def _rbac_manifest() -> list[dict]:
    expr = _locals()["gke_rbac_manifest"]
    m = re.fullmatch(r"var\.gke == null \? null : <<-EOT\n(.*)\n\s*EOT", expr, re.S)
    assert m, expr
    docs = list(yaml.safe_load_all(textwrap.dedent(m.group(1))))
    assert docs and all(docs), docs
    return docs


def test_nothing_is_installed_in_the_cluster():
    """The namespaced RBAC is the customer's to apply; the module only
    outputs it."""
    types = {t for t, _ in _resources()}
    assert not [t for t in types if t.startswith(("kubernetes_", "helm_"))], sorted(types)
    assert '"hashicorp/kubernetes"' not in _text(MAIN) and '"hashicorp/helm"' not in _text(MAIN)
    output = next(inner for k, labels, inner in _blocks(_text(OUTPUTS)) if k == "output" and labels == ["gke_rbac_manifest"])
    assert _attr(output, "value") == "local.gke_rbac_manifest"


def test_the_rbac_manifest_is_namespaced_and_covers_the_charts_gke_resources():
    docs = _rbac_manifest()
    assert "ClusterRoleBinding" not in _locals()["gke_rbac_manifest"]
    assert sorted(d["kind"] for d in docs) == ["Role", "RoleBinding", "RoleBinding"], docs
    for d in docs:
        assert d["metadata"]["namespace"] == "${var.gke.namespace}", d

    (role,) = [d for d in docs if d["kind"] == "Role"]
    rules = {(g, r) for rule in role["rules"] for g in rule["apiGroups"] for r in rule["resources"]}
    assert rules == {("cloud.google.com", "backendconfigs"), ("networking.gke.io", "managedcertificates")}, rules
    for rule in role["rules"]:
        assert rule["verbs"] == ["get", "list", "watch", "create", "update", "patch", "delete"], rule

    bindings = [d for d in docs if d["kind"] == "RoleBinding"]
    assert sorted((b["roleRef"]["kind"], b["roleRef"]["name"]) for b in bindings) == [
        ("ClusterRole", "edit"), ("Role", role["metadata"]["name"])]
    for b in bindings:
        assert b["subjects"] == [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User",
                                  "name": "${google_service_account.deploy.email}"}], b


# --- what it tells the workflow ------------------------------------------

def test_the_repository_variables():
    expr = _locals()["repository_variables"]
    names = _strings(expr)
    assert names[0] == "GCP_WORKLOAD_IDENTITY_PROVIDER", names
    assert names == [
        "GCP_WORKLOAD_IDENTITY_PROVIDER", "GCP_SERVICE_ACCOUNT", "GCP_PROJECT_ID", "GCP_REGION",
        "GCP_ARTIFACT_REPOSITORY", "GCP_DEPLOY_TARGET",
        "FORGD_VERDICT_URL", "FORGD_COLLECTOR_URL", "FORGD_DASHBOARD_URL", "FORGD_CONNECTOR_URL", "FORGD_INTAKE_URL",
        "GCP_IMAGE_PLATFORM", "GCP_ALLOW_CROSS_BUILD",
        "GCP_RUN_VERDICT_SERVICE", "GCP_RUN_COLLECTOR_SERVICE", "GCP_RUN_DASHBOARD_SERVICE", "GCP_RUN_INTAKE_SERVICE",
        "GCP_RUN_CONNECTOR_SERVICE", "GCP_RUN_INGEST_JOB",
        "GCP_GKE_CLUSTER", "GCP_GKE_LOCATION", "GCP_GKE_NAMESPACE", "GCP_GKE_RELEASE", "GCP_GKE_CHART",
    ], names
    assert 'var.cloudrun == null ? [] : [\n      "GCP_RUN_VERDICT_SERVICE"' in expr
    assert 'var.gke == null ? [] : ["GCP_GKE_CLUSTER"' in expr


def _strings(expr: str) -> list[str]:
    return re.findall(r'"((?:[^"\\]|\\.)*)"', expr)


# --- validations, checked by terraform ----------------------------------

REQUIRED = {
    "project_id": "acme-verdict", "region": "europe-west2",
    "github_repository_id": "123456789", "github_owner_id": "987654",
    "artifact_registry": {"location": "europe-west2", "repository_id": "forgd-verdict"},
}
CLOUDRUN = {
    "services": {"verdict": "fv-verdict", "collector": "fv-collector", "dashboard": "fv-dashboard"},
    "ingest_job": "fv-ingest",
    "runtime_service_accounts": ["fv-verdict@acme-verdict.iam.gserviceaccount.com"],
}


def _apply(tmp_path: Path, **variables) -> subprocess.CompletedProcess:
    """`terraform apply` of variables.tf alone, which runs the variables'
    validations and needs no provider."""
    shutil.copy(VARIABLES, tmp_path / "variables.tf")
    (tmp_path / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    out = subprocess.run([terraform, f"-chdir={tmp_path}", "init", "-input=false", "-no-color"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return subprocess.run([terraform, f"-chdir={tmp_path}", "apply", "-auto-approve", "-input=false", "-no-color"],
                          capture_output=True, text=True, timeout=120)


@requires_terraform
@pytest.mark.parametrize("environment", [None, "acme-deploy"])
def test_the_provider_admits_the_environment_the_input_names(tmp_path, environment):
    """Rendered with a mocked provider: unset, the condition names the default;
    set, it names the input and not the default."""
    from terraform_render import _google, plugin_dir, render_once

    def overrides(block: str, kind: str, name: str) -> dict:
        if kind == "google_iam_workload_identity_pool":
            return {"name": "projects/1/locations/global/workloadIdentityPools/p",
                    "workload_identity_pool_id": "p"}
        return _google(block, kind, name)

    variables = {**REQUIRED, "cloudrun": CLOUDRUN,
                 **({"github_environment": environment} if environment else {})}
    got = render_once(tmp_path / "render", MODULE, variables, providers=["google"],
                      plugins=plugin_dir(MODULE), mock_data={}, overrides=overrides)
    condition = got["google_iam_workload_identity_pool_provider.github"]["attribute_condition"]
    want = environment or "verdict-cd-gcp"
    assert f'assertion.environment == "{want}"' in condition, condition
    if environment:
        assert "verdict-cd-gcp" not in condition, condition


@requires_terraform
def test_well_formed_inputs_are_accepted(tmp_path):
    out = _apply(tmp_path, cloudrun={**CLOUDRUN, "services": {**CLOUDRUN["services"], "intake": "fv-intake",
                                                             "connector": "fv-connector"}},
                 gke={"cluster": "fv", "location": "europe-west2", "namespace": "forgd-verdict"})
    assert out.returncode == 0, out.stderr


@requires_terraform
@pytest.mark.parametrize("name,value", [
    ("github_repository_id", "acme/forgd-verdict"),
    ("github_repository_id", "*"),
    ("github_owner_id", "acme"),
    ("github_owner_id", ""),
])
def test_a_repository_or_owner_id_must_be_numeric(tmp_path, name, value):
    out = _apply(tmp_path, **{name: value})
    assert out.returncode != 0
    assert name in out.stderr


# Each would end the CEL string literal, or is not one environment name.
UNSAFE_ENVIRONMENTS = ['a"||true||"', "a\\", "a b", "a\nb", "", "a" * 256, "*", "a:b"]


@requires_terraform
@pytest.mark.parametrize("value", UNSAFE_ENVIRONMENTS)
def test_the_environment_must_be_one_plain_name(tmp_path, value):
    out = _apply(tmp_path, github_environment=value)
    assert out.returncode != 0
    assert "github_environment" in out.stderr


@requires_terraform
@pytest.mark.parametrize("value", ["acme-deploy", "Prod.eu_1", "a" * 255])
def test_a_plain_environment_name_is_accepted(tmp_path, value):
    out = _apply(tmp_path, github_environment=value)
    assert out.returncode == 0, out.stderr


CLAUSE = re.compile(r'(assertion\.[a-z_]+) == ("(?:[^"\\]|\\.)*")')


@requires_terraform
@pytest.mark.parametrize("environment, validated", [
    ("acme-deploy", True),
    ('a"b', False),
    ("a\\", False),
    ('x" || true || "', False),
])
def test_the_condition_is_three_comparisons_with_string_literals(tmp_path, environment, validated):
    """Each right-hand side is one JSON string literal equal to its input. The
    unsafe names are rendered with the environment's validation removed, so
    the quoting is shown to hold on its own."""
    from terraform_render import _google, plugin_dir, render_once

    module = MODULE
    if not validated:
        module = tmp_path / "ci-gcp"
        module.mkdir()
        for f in MODULE.glob("*.tf"):
            shutil.copy(f, module / f.name)
        text = (module / "variables.tf").read_text(encoding="utf-8")
        bypassed = re.sub(r'(variable "github_environment" \{.*?)\n  validation \{.*?\n  \}',
                          r"\1", text, count=1, flags=re.S)
        assert bypassed != text
        (module / "variables.tf").write_text(bypassed, encoding="utf-8")

    def overrides(block: str, kind: str, name: str) -> dict:
        if kind == "google_iam_workload_identity_pool":
            return {"name": "projects/1/locations/global/workloadIdentityPools/p",
                    "workload_identity_pool_id": "p"}
        return _google(block, kind, name)

    got = render_once(tmp_path / "render", module, {**REQUIRED, "cloudrun": CLOUDRUN, "github_environment": environment},
                      providers=["google"], plugins=plugin_dir(MODULE), mock_data={},
                      overrides=overrides)
    condition = got["google_iam_workload_identity_pool_provider.github"]["attribute_condition"]
    clauses = condition.split(" && ")
    parsed = [CLAUSE.fullmatch(c) for c in clauses]
    assert len(clauses) == 3 and all(parsed), condition
    assert [(m[1], json.loads(m[2])) for m in parsed] == [
        ("assertion.repository_id", REQUIRED["github_repository_id"]),
        ("assertion.repository_owner_id", REQUIRED["github_owner_id"]),
        ("assertion.environment", environment),
    ], condition


@requires_terraform
@pytest.mark.parametrize("cloudrun", [
    {**CLOUDRUN, "services": {"verdict": "fv-verdict", "collector": "fv-collector"}},
    {**CLOUDRUN, "services": {**CLOUDRUN["services"], "ingest": "fv-ingest"}},
    {**CLOUDRUN, "services": {**CLOUDRUN["services"], "verdict": "fv-*"}},
    {**CLOUDRUN, "runtime_service_accounts": []},
    {**CLOUDRUN, "runtime_service_accounts": ["*"]},
])
def test_a_malformed_cloudrun_input_is_refused(tmp_path, cloudrun):
    out = _apply(tmp_path, cloudrun=cloudrun)
    assert out.returncode != 0
    assert "cloudrun" in out.stderr


def test_the_readme_limits_the_gcp_environment_to_v_tags_only():
    """docs/RELEASING.md limits each deploy environment to `v*` tags. The
    default branch as well would let a workflow pushed there assume the
    identity, with no tag and no reviewer."""
    readme = (Path(__file__).resolve().parent.parent / "deploy" / "terraform" / "README.md").read_text(encoding="utf-8")
    section = readme[readme.index("## The GCP CD identity"):]
    section = " ".join(section[:section.index("\n## ", 1)].split())
    assert "default branch in its GitHub settings" not in section
    assert "without adding a reviewer" not in section
    assert "to `v*` tags only" in section
    assert "../../docs/RELEASING.md#a-forks-deploy-workflow" in section
