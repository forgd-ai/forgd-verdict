"""The chart's dashboard admins: off by default, and on a control identity of their own.

With `dashboard.admins.enabled` the dashboard runs as the control service
account, which the store modules grant the reader's reads plus writes to the
runtime overrides object and the audit prefix (docs/OVERRIDES.md, "Store
access"). The
connector stays on the reader, so nothing a caller Claude signs in reaches
can write.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest
import test_app_aca_admins as aca_admins
import yaml
from test_helm_chart import (
    CHART,
    INTAKE,
    READER_ID,
    REPO,
    WRITER_ID,
    _argv,
    by_kind,
    env_of,
    overrides_verify_key,
    pod_specs,
    render,
    render_eks,
    render_error,
    render_gke,
    requires_helm,
)
from test_helm_chart import helm as helm_bin
from test_helm_gke import render_error as gke_render_error

pytestmark = requires_helm

FULL = "rel-forgd-verdict"
CONTROL_ID = "33333333-3333-3333-3333-333333333333"
SIGNING_SECRET = "forgd-overrides-signing"
VERIFY_KEYS = (overrides_verify_key(), overrides_verify_key())
OIDC = (
    "--set", "dashboard.auth.mode=oidc_jwt",
    "--set", "dashboard.auth.jwksUrl=https://login.example.com/t/discovery/v2.0/keys",
    "--set", "dashboard.auth.issuer=https://login.example.com/t/v2.0",
    "--set", "dashboard.auth.audience=dashboard-client-id",
)
ADMINS = (
    *OIDC,
    "--set", "dashboard.admins.enabled=true",
    "--set", f"serviceAccounts.control.clientId={CONTROL_ID}",
    "--set", "secrets.dashboardFormKey=a-form-key",
    "--set", "dashboard.admins.writerIdentities={00000000-0000-0000-0000-00000000000a}",
    "--set", "dashboard.admins.storageAccountId=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct",
    "--set", f"dashboard.admins.signingKey.secretName={SIGNING_SECRET}",
    "--set", f"dashboard.admins.verifyKeys={{{','.join(VERIFY_KEYS)}}}",
)
CONNECTOR = (
    "--set", "connector.enabled=true",
    "--set", "connector.auth.issuer=https://login.example.com/t/v2.0",
    "--set", "connector.auth.jwksUrl=https://login.example.com/t/keys",
    "--set", "connector.auth.audience={api-client-id}",
    "--set", "connector.requiredScope=findings.read",
)
EKS_READER = "arn:aws:iam::123456789012:role/forgd-dashboard-reader"
EKS_WRITER = "arn:aws:iam::123456789012:role/forgd-verdict-writer"
EKS_CONTROL = "arn:aws:iam::123456789012:role/forgd-dashboard-control"
EKS_ROLE = "eks.amazonaws.com/role-arn"
EKS_ADMINS = (
    "--set", "dashboard.admins.enabled=true",
    "--set", f"dashboard.admins.writerIdentities={{{EKS_WRITER}}}",
    "--set-string", f"serviceAccounts.reader.annotations.eks\\.amazonaws\\.com/role-arn={EKS_READER}",
    "--set-string", f"serviceAccounts.writer.annotations.eks\\.amazonaws\\.com/role-arn={EKS_WRITER}",
    "--set", f"dashboard.admins.verifyKeys={{{','.join(VERIFY_KEYS)}}}",
)
ADMINS_POLICY = "dashboard:\n  admins:\n    groups:\n      - {group: forgd-operators}\n"


def _sa(docs, name):
    return by_kind(docs, "ServiceAccount").get(f"{FULL}-{name}")


# --- off -------------------------------------------------------------------

# The chart as it was before dashboard admins.
BASELINE_CHART = REPO / "tests" / "pinned" / "helm-baseline" / "forgd-verdict"
# Labels whose values follow Chart.yaml, which every release bumps.
# `checksum/policy` hashes the rendered policy ConfigMap, labels included,
# so it follows Chart.yaml too; the ConfigMap itself is compared.
RELEASE_LABELS = ("helm.sh/chart", "app.kubernetes.io/version", "checksum/policy")
TAGS = ("--set", "image.tag=deadbeef", "--set", "ingest.image.tag=deadbeef-ingest")
PLATFORM_VALUES = {"aks": None, "eks": "values-eks.example.yaml", "gke": "values-gke.example.yaml"}
OFF = {
    "omitted": (),
    "false": ("--set", "dashboard.admins.enabled=false"),
    "false-with-keys": ("--set", "dashboard.admins.enabled=false",
                        "--set", "dashboard.admins.signingKey.secretName=forgd-overrides-signing",
                        "--set", "dashboard.admins.signingKey.key=signing",
                        "--set", f"dashboard.admins.verifyKeys={{{overrides_verify_key()}}}"),
}
WORKLOADS = {
    "default": (),
    "intake-connector": (*INTAKE, *CONNECTOR),
    "no-ingest-no-collector": ("--set", "ingest.enabled=false", "--set", "collector.enabled=false"),
}


def _chart_argv(chart, platform: str, extra: tuple[str, ...]) -> list[str]:
    """`helm template` of `chart` as the platform's renderer runs it."""
    values = PLATFORM_VALUES[platform]
    if values is None:
        argv = _argv(extra, None)
        return [str(chart) if a == str(CHART) else a for a in argv]
    return [helm_bin, "template", "rel", str(chart), "-f", str(chart / values),
            "--set-file", f"policy.inline={REPO / 'policy.yaml'}", *TAGS, *extra]


def _rendered(chart, platform: str, extra: tuple[str, ...]) -> list:
    """Every rendered object, the release labels blanked, in a stable order."""
    out = subprocess.run(_chart_argv(chart, platform, extra), capture_output=True, text=True,
                         timeout=120)
    assert out.returncode == 0, out.stderr

    def blank(node):
        if isinstance(node, dict):
            return {k: "<release>" if k in RELEASE_LABELS else blank(v) for k, v in node.items()}
        if isinstance(node, list):
            return [blank(v) for v in node]
        return node

    docs = [blank(d) for d in yaml.safe_load_all(out.stdout) if d]
    return sorted(docs, key=lambda d: (d.get("kind", ""), d["metadata"]["name"]))


@pytest.mark.parametrize("workloads", sorted(WORKLOADS))
@pytest.mark.parametrize("off", sorted(OFF))
@pytest.mark.parametrize("platform", sorted(PLATFORM_VALUES))
def test_off_every_object_renders_exactly_as_the_chart_before_admins(platform, off, workloads):
    """Admins omitted or false, on every platform and with the optional
    workloads: the whole render equals the pinned chart's.

    Mutation: emit any change with admins off."""
    extra = (*OFF[off], *WORKLOADS[workloads])
    assert _rendered(CHART, platform, extra) == _rendered(BASELINE_CHART, platform, extra)


def test_the_full_comparison_catches_an_off_state_change(tmp_path):
    chart = tmp_path / "forgd-verdict"
    shutil.copytree(CHART, chart)
    target = chart / "templates" / "verdict.yaml"
    text = target.read_text(encoding="utf-8")
    anchor = "      serviceAccountName:"
    assert text.count(anchor) == 1
    target.write_text(text.replace(anchor, "      enableServiceLinks: false\n" + anchor),
                      encoding="utf-8")
    assert _rendered(chart, "aks", ()) != _rendered(BASELINE_CHART, "aks", ())


def test_the_pinned_chart_is_the_chart_before_admins():
    """The pinned chart mentions neither admins nor overrides."""
    files = sorted(p.relative_to(BASELINE_CHART).as_posix()
                   for p in BASELINE_CHART.rglob("*") if p.is_file())
    for name in files:
        text = (BASELINE_CHART / name).read_text(encoding="utf-8")
        assert "admins" not in text and "FORGD_OVERRIDES" not in text, name


@pytest.mark.parametrize("renderer", [render, render_eks, render_gke])
def test_off_by_default_nothing_changes(renderer):
    """A diagnostic beside the full comparison above: names what an admins
    artifact leaking into the off render would look like."""
    docs = renderer()
    assert not [d for d in docs if d["metadata"]["name"].endswith("-control")]
    text = json.dumps(docs)
    assert "FORGD_DASHBOARD_FORM_KEY" not in text
    assert "dashboard-form-key" not in text
    assert "FORGD_OVERRIDES_SIGNING_KEY" not in text
    assert "overrides-signing-key" not in text
    assert "FORGD_OVERRIDES_VERIFY_KEY" not in text
    assert '"forgd.ai/store-access": "control"' not in text


def test_off_the_dashboard_stays_on_the_reader():
    spec = pod_specs(render(*CONNECTOR))["dashboard"]
    assert spec["serviceAccountName"] == f"{FULL}-reader"
    assert env_of(spec)["AZURE_CLIENT_ID"]["value"] == READER_ID


# --- on --------------------------------------------------------------------

def test_on_the_dashboard_runs_as_the_control_identity():
    docs = render(*ADMINS)
    spec = pod_specs(docs)["dashboard"]
    assert spec["serviceAccountName"] == f"{FULL}-control"
    assert env_of(spec)["AZURE_CLIENT_ID"]["value"] == CONTROL_ID
    control = _sa(docs, "control")
    assert control["metadata"]["labels"]["forgd.ai/store-access"] == "control"
    assert control["metadata"]["annotations"]["azure.workload.identity/client-id"] == CONTROL_ID


def test_on_no_other_role_runs_as_the_control_identity():
    specs = pod_specs(render(*ADMINS, *CONNECTOR))
    others = {r: s["serviceAccountName"] for r, s in specs.items() if r != "dashboard"}
    assert others and not [r for r, sa in others.items() if sa.endswith("-control")], others
    for role, spec in specs.items():
        if role != "dashboard":
            assert env_of(spec).get("AZURE_CLIENT_ID", {}).get("value") != CONTROL_ID, role


def test_on_the_connector_stays_on_the_reader():
    docs = render(*ADMINS, *CONNECTOR)
    spec = pod_specs(docs)["connector"]
    assert spec["serviceAccountName"] == f"{FULL}-connector"
    assert env_of(spec)["AZURE_CLIENT_ID"]["value"] == READER_ID
    connector = _sa(docs, "connector")
    assert connector["metadata"]["labels"]["forgd.ai/store-access"] == "reader"
    assert connector["metadata"]["annotations"]["azure.workload.identity/client-id"] == READER_ID


def test_on_the_form_key_is_a_secret_reference_the_chart_manages():
    docs = render(*ADMINS)
    env = env_of(pod_specs(docs)["dashboard"])["FORGD_DASHBOARD_FORM_KEY"]
    assert "value" not in env
    assert env["valueFrom"]["secretKeyRef"] == {"name": f"{FULL}-secrets", "key": "dashboard-form-key"}
    [secret] = by_kind(docs, "Secret").values()
    assert secret["stringData"]["dashboard-form-key"] == "a-form-key"


def test_on_only_the_dashboard_gets_the_form_key():
    specs = pod_specs(render(*ADMINS, *CONNECTOR))
    holders = [r for r, s in specs.items() if "FORGD_DASHBOARD_FORM_KEY" in env_of(s)]
    assert holders == ["dashboard"], holders


def test_on_the_form_key_is_required_without_an_existing_secret():
    err = render_error(*ADMINS, "--set", "secrets.dashboardFormKey=")
    assert "secrets.dashboardFormKey is required" in err


def test_on_an_existing_secret_supplies_the_form_key():
    docs = render(*ADMINS, "--set", "secrets.dashboardFormKey=", "--set", "secrets.existingSecret=from-vault")
    assert not by_kind(docs, "Secret")
    env = env_of(pod_specs(docs)["dashboard"])["FORGD_DASHBOARD_FORM_KEY"]
    assert env["valueFrom"]["secretKeyRef"] == {"name": "from-vault", "key": "dashboard-form-key"}


def test_the_control_service_account_honours_its_name():
    docs = render(*ADMINS, "--set", "serviceAccounts.control.name=forgd-verdict-control")
    assert "forgd-verdict-control" in by_kind(docs, "ServiceAccount")
    assert pod_specs(docs)["dashboard"]["serviceAccountName"] == "forgd-verdict-control"


# --- refused -----------------------------------------------------------------

@pytest.mark.parametrize("client_id,needle", [
    (READER_ID, "equals serviceAccounts.reader.clientId"),
    (WRITER_ID, "equals serviceAccounts.writer.clientId"),
    ("", "serviceAccounts.control.clientId is required"),
])
def test_a_control_client_id_that_is_not_its_own_is_refused(client_id, needle):
    err = render_error(*ADMINS, "--set", f"serviceAccounts.control.clientId={client_id}")
    assert needle in err, err


@pytest.mark.parametrize("name", ["forgd-verdict-reader", "forgd-verdict-writer", "forgd-verdict-connector"])
def test_a_control_service_account_name_already_in_use_is_refused(name):
    err = render_error(
        *ADMINS, *CONNECTOR,
        "--set", "serviceAccounts.writer.name=forgd-verdict-writer",
        "--set", "serviceAccounts.reader.name=forgd-verdict-reader",
        "--set", "serviceAccounts.connector.name=forgd-verdict-connector",
        "--set", f"serviceAccounts.control.name={name}",
    )
    assert "a service account of its own" in err, err



# --- FORGD_OVERRIDES_ENABLED ------------------------------------------------

ENABLED = "FORGD_OVERRIDES_ENABLED"


def _workload_containers(docs) -> dict[str, list[dict]]:
    """"Kind/name" -> containers, for every rendered object with a pod template."""
    out = {}
    for d in docs:
        spec = d.get("spec") or {}
        template = spec.get("template") or ((spec.get("jobTemplate") or {}).get("spec")
                                            or {}).get("template")
        if template:
            out[f"{d['kind']}/{d['metadata']['name']}"] = template["spec"]["containers"]
    return out


@pytest.mark.parametrize("renderer,flags", [
    (render, (*ADMINS, *CONNECTOR, *INTAKE)),
    (render_eks, (*EKS_ADMINS, "--set-string",
                  f"serviceAccounts.control.annotations.eks\\.amazonaws\\.com/role-arn={EKS_CONTROL}",
                  "--set", "secrets.dashboardFormKey=x")),
], ids=["aks", "eks"])
def test_on_every_workload_has_overrides_enabled(renderer, flags):
    """Mutation: drop commonEnv from one workload, or the variable from it."""
    workloads = _workload_containers(renderer(*flags))
    assert len(workloads) >= 4, workloads
    for name, containers in workloads.items():
        for c in containers:
            env = {e["name"]: e for e in c.get("env", [])}
            assert env.get(ENABLED) == {"name": ENABLED, "value": "true"}, (name, c["name"])


@pytest.mark.parametrize("renderer,flags", [
    (render, ()),
    (render, (*CONNECTOR, *INTAKE)),
    (render, (*CONNECTOR, *INTAKE, "--set", "dashboard.admins.enabled=false")),
    (render, (*CONNECTOR, *INTAKE, *OFF["false-with-keys"])),
    (render_eks, ()),
    (render_gke, ()),
], ids=["aks", "aks-all-workloads", "aks-explicit-false", "aks-false-with-keys", "eks", "gke"])
def test_off_no_object_has_overrides_enabled(renderer, flags):
    """Mutation: emit any of the variables whatever dashboard.admins.enabled says."""
    docs = renderer(*flags)
    assert _workload_containers(docs)
    text = json.dumps(docs)
    for name in (ENABLED, WRITER_ROLES, SIGNING_KEY, VERIFY_KEY):
        assert name not in text, name


# --- FORGD_OVERRIDES_WRITER_ROLES -------------------------------------------

WRITER_ROLES = "FORGD_OVERRIDES_WRITER_ROLES"
# The helper's first branch; dropping `else` lists ingest beside verdict.
INGEST_IN_HELPER = "{{- else if .Values.ingest.enabled -}}ingest"


def _envs(docs) -> dict[str, dict[str, str]]:
    """"Kind/name/container" -> {name: value} for every literal env entry."""
    return {f"{name}/{c['name']}": {e["name"]: e["value"] for e in c.get("env", []) if "value" in e}
            for name, containers in _workload_containers(docs).items() for c in containers}


@pytest.mark.parametrize("renderer,flags,roles", [
    (render, (*ADMINS, *CONNECTOR, *INTAKE), "verdict"),
    (render, (*ADMINS, *CONNECTOR), "verdict"),
    (render, (*ADMINS, *INTAKE, "--set", "verdict.enabled=false"), "collector"),
    (render, (*ADMINS, *INTAKE, "--set", "verdict.enabled=false", "--set", "collector.enabled=false"),
     "intake"),
    (render, (*ADMINS, "--set", "verdict.enabled=false", "--set", "collector.enabled=false"), "ingest"),
    (render, (*ADMINS, "--set", "collector.enabled=false", "--set", "ingest.enabled=false"), "verdict"),
    (render_eks, (*EKS_ADMINS, "--set-string",
                  f"serviceAccounts.control.annotations.eks\\.amazonaws\\.com/role-arn={EKS_CONTROL}",
                  "--set", "secrets.dashboardFormKey=x"), "verdict"),
], ids=["all", "no-intake", "no-verdict", "intake-first", "ingest-only", "verdict-only", "eks"])
def test_on_every_workload_has_one_writer_role_for_the_writer_identity(renderer, flags, roles):
    """Verdict, collector, intake and ingest all run as the writer service
    account, so exactly one is listed: the first deployed, with ingest only
    when no long-running writer is. The dashboard and the connector are never
    listed.

    Mutation: list a role the release does not deploy, or ingest beside a
    long-running writer."""
    envs = _envs(renderer(*flags))
    assert envs and aca_admins.writer_roles_problems(envs) == []
    assert {e.get(WRITER_ROLES) for e in envs.values()} == {roles}


def test_a_writer_roles_list_that_names_ingest_beside_verdict_is_caught(tmp_path):
    """The check above fails on a chart that lists the ingest CronJob beside
    a long-running writer on the same service account."""
    chart = tmp_path / "chart"
    shutil.copytree(CHART, chart)
    helpers = chart / "templates" / "_helpers.tpl"
    text = helpers.read_text(encoding="utf-8")
    assert text.count(INGEST_IN_HELPER) == 1
    helpers.write_text(text.replace(INGEST_IN_HELPER, "{{- end -}}\n{{- if .Values.ingest.enabled -}},ingest"),
                       encoding="utf-8")
    argv = [str(chart) if a == str(CHART) else a for a in _argv((*ADMINS, *CONNECTOR), None)]
    out = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    envs = _envs([d for d in yaml.safe_load_all(out.stdout) if d])
    assert {e.get(WRITER_ROLES) for e in envs.values()} == {"verdict,ingest"}
    assert len(aca_admins.writer_roles_problems(envs)) == len(envs)


def test_every_writer_workload_runs_as_the_writer_service_account():
    """The single-role list holds only while every writer workload shares
    one service account.

    Mutation: give a writer workload a service account of its own."""
    for template in ("verdict.yaml", "collector.yaml", "intake.yaml", "ingest-cronjob.yaml"):
        text = (CHART / "templates" / template).read_text(encoding="utf-8")
        accounts = re.findall(r"serviceAccountName: (.*)", text)
        assert accounts == ['{{ include "forgd-verdict.writerServiceAccountName" . }}'], template


def test_on_eks_the_control_role_annotation_is_rendered():
    docs = render_eks(*EKS_ADMINS, "--set-string",
                      f"serviceAccounts.control.annotations.eks\\.amazonaws\\.com/role-arn={EKS_CONTROL}",
                      "--set", "secrets.dashboardFormKey=x")
    control = _sa(docs, "control")
    assert control["metadata"]["annotations"] == {EKS_ROLE: EKS_CONTROL}
    assert pod_specs(docs)["dashboard"]["serviceAccountName"] == f"{FULL}-control"
    assert "AZURE_CLIENT_ID" not in env_of(pod_specs(docs)["dashboard"])


@pytest.mark.parametrize("arn", [EKS_READER, EKS_WRITER])
def test_on_eks_a_control_role_equal_to_the_reader_or_writer_is_refused(arn):
    out = subprocess.run(
        [helm_bin, "template", "rel", str(CHART), "-f", str(CHART / "values-eks.example.yaml"),
         "--set-file", f"policy.inline={REPO / 'policy.yaml'}", *EKS_ADMINS,
         "--set-string", f"serviceAccounts.control.annotations.eks\\.amazonaws\\.com/role-arn={arn}"],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode != 0
    assert "equals the reader's or the writer's" in out.stderr, out.stderr


def test_admins_are_refused_outside_oidc_jwt():
    err = render_error("--set", "dashboard.admins.enabled=true",
                       "--set", f"serviceAccounts.control.clientId={CONTROL_ID}",
                       "--set", "secrets.dashboardFormKey=k",
                       "--set", f"dashboard.admins.verifyKeys={{{VERIFY_KEYS[0]}}}")
    assert "needs the effective dashboard.auth.mode to be oidc_jwt" in err, err


def test_admins_are_refused_behind_iap():
    err = gke_render_error("--set", "dashboard.admins.enabled=true",
                           "--set", f"dashboard.admins.verifyKeys={{{VERIFY_KEYS[0]}}}")
    assert "Identity-Aware Proxy tokens carry no groups" in err, err


def test_a_policy_with_admins_is_refused_while_the_chart_has_them_off():
    policy = (REPO / "policy.yaml").read_text() + "\n" + ADMINS_POLICY
    err = render_error(*OIDC, policy=policy)
    assert "sets dashboard.admins.groups but dashboard.admins.enabled is false" in err, err
    docs = render(*ADMINS, policy=policy)
    assert pod_specs(docs)["dashboard"]["serviceAccountName"] == f"{FULL}-control"


# --- the lockout verification's inputs -----------------------------------------

AZ_WRITER = "00000000-0000-0000-0000-00000000000a"


def test_on_only_the_dashboard_gets_the_writer_identities_and_account():
    """Mutation: give every role the variables, or join the list wrongly."""
    specs = pod_specs(render(*ADMINS, *CONNECTOR, "--set",
                             f"dashboard.admins.writerIdentities={{{AZ_WRITER},{EKS_WRITER}}}"))
    env = env_of(specs["dashboard"])
    assert env["FORGD_OVERRIDES_WRITER_IDENTITIES"]["value"] == f"{AZ_WRITER},{EKS_WRITER}"
    assert env["FORGD_OVERRIDES_STORAGE_ACCOUNT_ID"]["value"].endswith("/storageAccounts/acct")
    for role, spec in specs.items():
        if role != "dashboard":
            assert not {"FORGD_OVERRIDES_WRITER_IDENTITIES",
                        "FORGD_OVERRIDES_STORAGE_ACCOUNT_ID"} & set(env_of(spec)), role


def test_the_gcs_audit_attestation_reaches_only_the_dashboard():
    specs = pod_specs(render(*ADMINS, *CONNECTOR, "--set",
                             "dashboard.admins.gcsInheritedAuditedBy=platform team 2026-10-03"))
    env = env_of(specs["dashboard"])
    assert env["FORGD_OVERRIDES_GCS_INHERITED_AUDITED_BY"]["value"] == "platform team 2026-10-03"
    for role, spec in specs.items():
        if role != "dashboard":
            assert "FORGD_OVERRIDES_GCS_INHERITED_AUDITED_BY" not in env_of(spec), role
    unset = env_of(pod_specs(render(*ADMINS))["dashboard"])
    assert "FORGD_OVERRIDES_GCS_INHERITED_AUDITED_BY" not in unset


def test_on_an_empty_writer_identity_list_is_refused():
    """Mutation: drop the fail, and the dashboard starts verifying nothing."""
    err = render_error(*ADMINS, "--set", "dashboard.admins.writerIdentities=null")
    assert "needs dashboard.admins.writerIdentities" in err, err


@pytest.mark.parametrize("entries", ['[""]', '["00000000-0000-0000-0000-00000000000a", "  "]'])
def test_on_a_blank_writer_identity_is_refused(entries):
    """Mutation: drop the blank-entry fail."""
    i = ADMINS.index("dashboard.admins.writerIdentities={00000000-0000-0000-0000-00000000000a}")
    args = ADMINS[:i - 1] + ADMINS[i + 1:]
    err = render_error(*args, "--set-json", f"dashboard.admins.writerIdentities={entries}")
    assert "writerIdentities has a blank entry" in err, err
    render(*args, "--set-json", 'dashboard.admins.writerIdentities=["00000000-0000-0000-0000-00000000000a"]')


def test_on_an_azure_store_without_the_storage_account_is_refused():
    err = render_error(*ADMINS, "--set", "dashboard.admins.storageAccountId=")
    assert "needs dashboard.admins.storageAccountId" in err, err


def test_on_eks_the_storage_account_is_not_needed():
    env = env_of(pod_specs(render_eks(*EKS_ADMINS, "--set-string",
                                      f"serviceAccounts.control.annotations.eks\\.amazonaws\\.com/role-arn={EKS_CONTROL}"))["dashboard"])
    assert env["FORGD_OVERRIDES_WRITER_IDENTITIES"]["value"] == EKS_WRITER
    assert "FORGD_OVERRIDES_STORAGE_ACCOUNT_ID" not in env


def test_off_no_workload_gets_the_writer_identities():
    docs = render(*CONNECTOR, "--set", f"dashboard.admins.writerIdentities={{{AZ_WRITER}}}")
    for role, spec in pod_specs(docs).items():
        assert "FORGD_OVERRIDES_WRITER_IDENTITIES" not in env_of(spec), role


# --- the override signing keys ---------------------------------------------

SIGNING_KEY = "FORGD_OVERRIDES_SIGNING_KEY"
VERIFY_KEY = "FORGD_OVERRIDES_VERIFY_KEY"
# Every workload that reads runtime overrides, by "Kind/name".
OVERRIDES_READERS = {f"{kind}/{FULL}-{role}" for kind, role in [
    ("Deployment", "verdict"), ("Deployment", "collector"), ("Deployment", "intake"),
    ("Deployment", "dashboard"), ("Deployment", "connector"), ("CronJob", "ingest"),
]}


def _without(flags: tuple[str, ...], prefix: str) -> tuple[str, ...]:
    """`flags` less the `--set <prefix>...` pair."""
    [i] = [n for n, a in enumerate(flags) if a.startswith(prefix)]
    return flags[:i - 1] + flags[i + 1:]


def _env_entries(docs, name: str) -> dict[str, dict]:
    """"Kind/name/container" -> the env entry called `name`, where there is one."""
    out = {}
    for workload, containers in _workload_containers(docs).items():
        for c in containers:
            for e in c.get("env", []):
                if e["name"] == name:
                    out[f"{workload}/{c['name']}"] = e
    return out


def test_on_the_signing_key_reaches_the_dashboard_and_nothing_else():
    """Mutation: put the variable in commonEnv, or the key in the chart Secret."""
    docs = render(*ADMINS, *CONNECTOR, *INTAKE)
    assert set(_workload_containers(docs)) == OVERRIDES_READERS
    holders = _env_entries(docs, SIGNING_KEY)
    assert list(holders) == [f"Deployment/{FULL}-dashboard/dashboard"], holders
    [entry] = holders.values()
    assert entry == {"name": SIGNING_KEY, "valueFrom": {"secretKeyRef": {
        "name": SIGNING_SECRET, "key": "overrides-signing-key"}}}
    [secret] = by_kind(docs, "Secret").values()
    assert "overrides-signing-key" not in secret["stringData"]
    assert "overrides-signing-key" not in json.dumps(secret)
    others = [d for d in docs if d["metadata"]["name"] != f"{FULL}-dashboard"]
    assert SIGNING_KEY not in json.dumps(others)


def test_on_the_signing_key_name_within_the_secret_is_honoured():
    docs = render(*ADMINS, "--set", "dashboard.admins.signingKey.key=ed25519")
    ref = env_of(pod_specs(docs)["dashboard"])[SIGNING_KEY]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": SIGNING_SECRET, "key": "ed25519"}


def test_on_an_existing_secret_supplies_the_signing_key():
    """Mutation: drop the secrets.existingSecret fallback."""
    flags = _without(ADMINS, "dashboard.admins.signingKey.secretName=")
    docs = render(*flags, "--set", "secrets.dashboardFormKey=", "--set", "secrets.existingSecret=from-vault")
    ref = env_of(pod_specs(docs)["dashboard"])[SIGNING_KEY]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": "from-vault", "key": "overrides-signing-key"}


def test_on_a_named_signing_secret_wins_over_the_existing_secret():
    docs = render(*ADMINS, "--set", "secrets.dashboardFormKey=", "--set", "secrets.existingSecret=from-vault")
    ref = env_of(pod_specs(docs)["dashboard"])[SIGNING_KEY]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": SIGNING_SECRET, "key": "overrides-signing-key"}


def test_on_eks_the_signing_key_comes_from_the_example_existing_secret():
    docs = render_eks(*EKS_ADMINS, "--set-string",
                      f"serviceAccounts.control.annotations.eks\\.amazonaws\\.com/role-arn={EKS_CONTROL}")
    ref = env_of(pod_specs(docs)["dashboard"])[SIGNING_KEY]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": "forgd-verdict", "key": "overrides-signing-key"}


def test_on_no_signing_key_secret_is_refused():
    """Mutation: drop the fail, and the dashboard refuses to start instead."""
    err = render_error(*_without(ADMINS, "dashboard.admins.signingKey.secretName="))
    assert "dashboard.admins.signingKey.secretName is required while dashboard.admins.enabled" in err, err
    assert "signs every runtime-override record with it" in err, err


def test_on_an_empty_signing_key_name_is_refused():
    err = render_error(*ADMINS, "--set", "dashboard.admins.signingKey.key=")
    assert "dashboard.admins.signingKey.key is empty" in err, err


@pytest.mark.parametrize("renderer,flags", [
    (render, (*ADMINS, *CONNECTOR, *INTAKE)),
    (render_eks, (*EKS_ADMINS, *CONNECTOR, *INTAKE, "--set-string",
                  f"serviceAccounts.control.annotations.eks\\.amazonaws\\.com/role-arn={EKS_CONTROL}")),
], ids=["aks", "eks"])
def test_on_every_overrides_reader_has_the_verify_keys(renderer, flags):
    """Mutation: drop the variable from commonEnv, or join the list wrongly."""
    docs = renderer(*flags)
    assert set(_workload_containers(docs)) == OVERRIDES_READERS
    entries = _env_entries(docs, VERIFY_KEY)
    assert {k.rsplit("/", 1)[0] for k in entries} == OVERRIDES_READERS
    for where, entry in entries.items():
        assert entry == {"name": VERIFY_KEY, "value": ",".join(VERIFY_KEYS)}, where


@pytest.mark.parametrize("value", ["null", "[]"])
def test_on_no_verify_keys_is_refused(value):
    """Mutation: drop the empty-list fail."""
    flags = _without(ADMINS, "dashboard.admins.verifyKeys=")
    err = render_error(*flags, "--set-json", f"dashboard.admins.verifyKeys={value}")
    assert "dashboard.admins.verifyKeys is required while dashboard.admins.enabled" in err, err


@pytest.mark.parametrize("entries,n", [
    (lambda k: ["", k], 1),
    (lambda k: [k, "   "], 2),
])
def test_on_a_blank_verify_key_is_refused(entries, n):
    """Mutation: drop the blank-entry fail."""
    flags = _without(ADMINS, "dashboard.admins.verifyKeys=")
    err = render_error(*flags, "--set-json",
                       f"dashboard.admins.verifyKeys={json.dumps(entries(VERIFY_KEYS[0]))}")
    assert f"dashboard.admins.verifyKeys entry {n} is blank" in err, err


@pytest.mark.parametrize("malformed", [
    lambda k: k[:-1],                       # 42 characters
    lambda k: k + "A",                      # 44 characters
    lambda k: k + "=",                      # padded
    lambda k: "+" + k[1:],                  # standard, not URL-safe, alphabet
    lambda k: " " + k,                      # surrounding whitespace
    lambda k: f"{k},{overrides_verify_key()}",  # two keys in one entry
], ids=["short", "long", "padded", "std-alphabet", "whitespace", "comma"])
def test_on_a_malformed_verify_key_is_refused_without_echoing_it(malformed):
    """Mutation: drop the format check. A malformed entry may be a pasted
    private key, so the message names its position only."""
    bad = malformed(overrides_verify_key())
    flags = _without(ADMINS, "dashboard.admins.verifyKeys=")
    err = render_error(*flags, "--set-json",
                       f"dashboard.admins.verifyKeys={json.dumps([VERIFY_KEYS[0], bad])}")
    assert "dashboard.admins.verifyKeys entry 2 is not an Ed25519 public key" in err, err
    assert bad.strip() not in err


def _with_account(name: str) -> tuple[str, ...]:
    return tuple(a.replace("storageAccounts/acct", f"storageAccounts/{name}") for a in ADMINS)


def test_a_storage_account_id_naming_another_account_is_refused():
    err = render_error(*_with_account("other"))
    assert "dashboard.admins.storageAccountId does not name the storage account store.url is on" in err, err


def test_a_storage_account_id_matches_the_store_url_whatever_the_case():
    render(*_with_account("ACCT"))
