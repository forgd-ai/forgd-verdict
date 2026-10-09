"""Per-org signing secrets, Compliance Access Keys and fleet tokens in the
Helm chart. Each role's org names are a non-secret list whose entries are
`orgIds` keys, so a deployment on `secrets.existingSecret` gets the variable
names without listing secrets in values. With the lists empty the chart
renders as it did before they existed."""

from __future__ import annotations

import re
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml
from test_helm_chart import BASE, CHART, REPO, env_of, helm, pod_specs, render, render_error

requires_helm = pytest.mark.skipif(helm is None, reason="helm is not installed")

PROD = "00000000-0000-0000-0000-00000000000a"
DEV = "00000000-0000-0000-0000-00000000000b"
ORGS = ("--set", f"orgIds.prod={PROD}", "--set", f"orgIds.dev={DEV}")
EXISTING = ("--set", "secrets.existingSecret=forgd-from-vault")
FLEET = ("--set", "intake.enabled=true", "--set", "intake.fleet.enabled=true",
         "--set", "secrets.intakeFleetToken=" + "f" * 32)


def _secret_ref(env: dict, name: str) -> dict:
    return env[name]["valueFrom"]["secretKeyRef"]


def _secret_data(docs: list[dict]) -> dict:
    [secret] = [d for d in docs if d["kind"] == "Secret"]
    return secret.get("stringData") or {}


# -- verdict: one signing secret per org --------------------------------------

@requires_helm
def test_each_signing_org_gets_a_current_and_an_optional_previous_secret():
    docs = render(*ORGS, "--set", "verdict.signingOrgs={prod,dev}",
                  "--set", "secrets.webhookSecrets.prod.current=whsec_prod",
                  "--set", "secrets.webhookSecrets.prod.previous=whsec_prod_old",
                  "--set", "secrets.webhookSecrets.dev.current=whsec_dev")
    env = env_of(pod_specs(docs)["verdict"])
    for name in ("PROD", "DEV"):
        ref = _secret_ref(env, f"WEBHOOK_SECRET_{name}")
        assert ref["key"] == f"webhook-secret-{name.lower()}" and "optional" not in ref
        prev = _secret_ref(env, f"WEBHOOK_SECRET_{name}_PREVIOUS")
        assert prev == {**prev, "key": f"webhook-secret-{name.lower()}-previous", "optional": True}
    data = _secret_data(docs)
    assert data["webhook-secret-prod"] == "whsec_prod"
    assert data["webhook-secret-prod-previous"] == "whsec_prod_old"
    assert data["webhook-secret-dev"] == "whsec_dev"
    assert "webhook-secret-dev-previous" not in data


@requires_helm
def test_signing_orgs_on_an_existing_secret_need_no_secret_values():
    env = env_of(pod_specs(render(*ORGS, *EXISTING, "--set", "verdict.signingOrgs={prod}"))["verdict"])
    assert _secret_ref(env, "WEBHOOK_SECRET_PROD")["name"] == "forgd-from-vault"


@requires_helm
def test_with_signing_orgs_the_single_slot_secret_is_optional():
    docs = render(*ORGS, "--set", "verdict.signingOrgs={prod}", "--set", "secrets.webhookSecret=",
                  "--set", "secrets.webhookSecrets.prod.current=whsec_prod")
    env = env_of(pod_specs(docs)["verdict"])
    assert _secret_ref(env, "WEBHOOK_SECRET")["optional"] is True
    assert "webhook-secret" not in _secret_data(docs)


# -- ingest: one Compliance Access Key per org --------------------------------

@requires_helm
def test_each_compliance_org_gets_a_required_key_and_no_previous():
    docs = render(*ORGS, "--set", "ingest.complianceOrgs={prod,dev}",
                  "--set", "secrets.complianceKeys.prod=sk-prod", "--set", "secrets.complianceKeys.dev=sk-dev")
    env = env_of(pod_specs(docs)["ingest"])
    for name in ("PROD", "DEV"):
        ref = _secret_ref(env, f"ANTHROPIC_COMPLIANCE_ACCESS_KEY_{name}")
        assert ref["key"] == f"compliance-key-{name.lower()}" and "optional" not in ref
        assert f"ANTHROPIC_COMPLIANCE_ACCESS_KEY_{name}_PREVIOUS" not in env
    data = _secret_data(docs)
    assert data["compliance-key-prod"] == "sk-prod" and data["compliance-key-dev"] == "sk-dev"


@requires_helm
def test_with_compliance_orgs_the_single_slot_key_is_optional():
    docs = render(*ORGS, "--set", "ingest.complianceOrgs={prod}", "--set", "secrets.complianceKey=",
                  "--set", "secrets.complianceKeys.prod=sk-prod")
    env = env_of(pod_specs(docs)["ingest"])
    assert _secret_ref(env, "ANTHROPIC_COMPLIANCE_ACCESS_KEY")["optional"] is True


# -- intake: one fleet token pair per org -------------------------------------

@requires_helm
def test_each_fleet_org_gets_a_required_token_and_an_optional_previous():
    docs = render(*ORGS, "--set", "intake.enabled=true", "--set", "intake.fleet.orgs={prod}",
                  "--set", "secrets.intakeFleetTokens.prod.current=" + "p" * 32)
    env = env_of(pod_specs(docs)["intake"])
    ref = _secret_ref(env, "FORGD_INTAKE_FLEET_TOKEN_PROD")
    assert ref["key"] == "intake-fleet-token-prod" and "optional" not in ref
    prev = _secret_ref(env, "FORGD_INTAKE_FLEET_TOKEN_PROD_PREVIOUS")
    assert prev["key"] == "intake-fleet-token-prod-previous" and prev["optional"] is True
    assert "FORGD_INTAKE_FLEET_TOKEN" not in env


@requires_helm
def test_the_single_slot_fleet_token_is_required():
    env = env_of(pod_specs(render(*FLEET))["intake"])
    assert "optional" not in _secret_ref(env, "FORGD_INTAKE_FLEET_TOKEN")
    assert _secret_ref(env, "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS")["optional"] is True


@requires_helm
def test_a_fleet_with_no_token_is_refused_unless_the_secret_is_external():
    err = render_error("--set", "intake.enabled=true", "--set", "intake.fleet.enabled=true")
    assert "secrets.intakeFleetToken" in err
    err = render_error(*ORGS, "--set", "intake.enabled=true", "--set", "intake.fleet.orgs={prod}")
    assert "secrets.intakeFleetTokens.prod.current" in err
    render(*EXISTING, "--set", "intake.enabled=true", "--set", "intake.fleet.enabled=true")
    render(*ORGS, *EXISTING, "--set", "intake.enabled=true", "--set", "intake.fleet.orgs={prod}")


# -- refusals, per role -------------------------------------------------------

ROLES = {
    "verdict": ("verdict.signingOrgs", "secrets.webhookSecrets.{}.current"),
    "ingest": ("ingest.complianceOrgs", "secrets.complianceKeys.{}"),
    "intake": ("intake.fleet.orgs", "secrets.intakeFleetTokens.{}.current"),
}
ENABLE = {"verdict": (), "ingest": (), "intake": ("--set", "intake.enabled=true")}


def _with_names(role: str, *names: str, ids: dict[str, str] | None = None) -> tuple[str, ...]:
    key, value = ROLES[role]
    ids = ids if ids is not None else {n: PROD for n in names}
    out = [*ENABLE[role], "--set", f"{key}={{{','.join(names)}}}"]
    for n, uuid in ids.items():
        out += ["--set", f"orgIds.{n}={uuid}"]
    for n in names:
        out += ["--set", f"{value.format(n)}={'t' * 32}"]
    return tuple(out)


@requires_helm
@pytest.mark.parametrize("role", ROLES)
def test_an_org_name_that_is_not_an_org_id_is_refused(role):
    err = render_error(*_with_names(role, "prod", ids={}))
    assert f"{ROLES[role][0]} names prod, which has no entry in orgIds" in err


@requires_helm
@pytest.mark.parametrize("role", ROLES)
def test_an_inline_secret_for_an_unlisted_org_is_refused(role):
    key, value = ROLES[role]
    err = render_error(*ENABLE[role], *ORGS, "--set", f"{key}={{prod}}",
                       "--set", f"{value.format('prod')}={'t' * 32}",
                       "--set", f"{value.format('dev')}={'t' * 32}")
    assert f"{value.format('dev').split('.current')[0]} has no matching entry in {key}" in err


@requires_helm
@pytest.mark.parametrize("role", ["verdict", "intake"])
def test_an_org_named_previous_collides_with_the_single_slot(role):
    err = render_error(*_with_names(role, "previous"))
    assert "collides" in err and "PREVIOUS" in err


@requires_helm
@pytest.mark.parametrize("role", ["verdict", "intake"])
def test_an_org_and_its_previous_name_collide(role):
    err = render_error(*_with_names(role, "a", "a-previous"))
    assert "collides" in err and "A_PREVIOUS" in err


@requires_helm
@pytest.mark.parametrize("role", ROLES)
def test_two_names_for_one_variable_collide(role):
    err = render_error(*_with_names(role, "a-b", "a_b"))
    assert "collides" in err and "A_B" in err


@requires_helm
def test_extra_env_cannot_set_a_per_org_credential():
    for name in ("WEBHOOK_SECRET_PROD", "ANTHROPIC_COMPLIANCE_ACCESS_KEY_PROD",
                 "FORGD_INTAKE_FLEET_TOKEN_PROD"):
        assert "names a credential the chart wires from a Secret" in render_error(
            "--set", f"extraEnv.{name}=x")


# -- the policy's commented per-org examples ----------------------------------

def test_the_shipped_policy_shows_each_per_org_form():
    policy = (REPO / "policy.yaml").read_text(encoding="utf-8")
    for line in ("#   - $WEBHOOK_SECRET_PROD", "#   - $WEBHOOK_SECRET_PROD_PREVIOUS",
                 "#   api_key: $ANTHROPIC_COMPLIANCE_ACCESS_KEY_OTHER",
                 "#    tokens: [$FORGD_INTAKE_FLEET_TOKEN_PROD, $FORGD_INTAKE_FLEET_TOKEN_PROD_PREVIOUS]",
                 "#    org: $FORGD_ORG_ID_PROD"):
        assert line in policy, line


# -- the chart as it was at v0.46.0 -------------------------------------------

BEFORE = "a9a62907"
VALUE_SETS = {
    "inline single slots": (),
    "existingSecret, orgIds and the intake fleet": (
        *EXISTING, "--set", f"orgIds.primary={PROD}", "--set", "intake.enabled=true",
        "--set", "intake.fleet.enabled=true"),
    "otelTokens for two orgs": (
        "--set", f"orgIds.other={DEV}", "--set", "secrets.otelTokens.other=" + "o" * 32),
}
# The one change an empty org list makes. The single-slot fleet token is no
# longer optional: an unset intake-fleet-token used to start an intake that
# skips the fleet and refuses every laptop with 401.
FLEET_TOKEN_REQUIRED = "- optional: true  (FORGD_INTAKE_FLEET_TOKEN)"
# And one addition: the intake gets the metrics token the verdict server
# and the collector already read, for its /stats.
INTAKE_METRICS_TOKEN = "FORGD_METRICS_TOKEN"


def _chart_at(commit: str, into: Path) -> Path:
    archive = subprocess.run(["git", "archive", commit, "deploy/helm/forgd-verdict"], cwd=REPO,
                             capture_output=True, check=True).stdout
    tar = into / "chart.tar"
    tar.write_bytes(archive)
    with tarfile.open(tar) as t:
        t.extractall(into, filter="data")
    chart = into / "deploy" / "helm" / "forgd-verdict"
    # A release moves appVersion, which reaches every version label and the
    # default image tag. The old chart renders with the current one.
    current = re.search(r"^appVersion: .*$", (CHART / "Chart.yaml").read_text(), re.M).group(0)
    meta = chart / "Chart.yaml"
    meta.write_text(re.sub(r"^appVersion: .*$", current, meta.read_text(), count=1, flags=re.M))
    return chart


def _template(chart: Path, extra: tuple[str, ...]) -> str:
    out = subprocess.run([helm, "template", "rel", str(chart), *BASE, *extra],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return out.stdout


def _optional_dropped(old: str, new: str) -> list[str]:
    """Each env var whose secretKeyRef lost `optional: true` between the two
    renders, everything else equal."""
    def refs(text):
        out = {}
        for doc in yaml.safe_load_all(text):
            for spec in _pod_specs_of(doc):
                for c in spec.get("containers", []):
                    for e in c.get("env", []):
                        ref = (e.get("valueFrom") or {}).get("secretKeyRef")
                        if ref:
                            out[(doc["metadata"]["name"], c["name"], e["name"])] = ref
        return out
    a, b = refs(old), refs(new)
    return [f"- optional: true  ({k[2]})" for k in a
            if a[k].get("optional") and k in b and "optional" not in b[k]]


def _pod_specs_of(doc):
    if not doc:
        return []
    spec = doc.get("spec") or {}
    if doc.get("kind") == "CronJob":
        return [spec["jobTemplate"]["spec"]["template"]["spec"]]
    if "template" in spec:
        return [spec["template"]["spec"]]
    return []


def _intake_env(text: str) -> set[str]:
    return {e["name"] for doc in yaml.safe_load_all(text) for spec in _pod_specs_of(doc)
            for c in spec.get("containers", []) if c["name"] == "intake" for e in c.get("env", [])}


def _without_optional(text: str, names: set[str], drop: tuple[str, str] | None = None) -> str:
    """`text` with `optional` removed from each named secretKeyRef, and with
    `drop`, a (container, variable) pair, removed from its container."""
    docs = list(yaml.safe_load_all(text))
    for doc in docs:
        for spec in _pod_specs_of(doc):
            for c in spec.get("containers", []):
                if drop and c["name"] == drop[0]:
                    c["env"] = [e for e in c.get("env", []) if e["name"] != drop[1]]
                for e in c.get("env", []):
                    ref = (e.get("valueFrom") or {}).get("secretKeyRef")
                    if ref and e["name"] in names:
                        ref.pop("optional", None)
    return yaml.safe_dump_all(docs, sort_keys=True)


@requires_helm
@pytest.mark.parametrize("values", VALUE_SETS)
def test_the_chart_renders_as_it_did_at_v0_46_0_with_no_org_lists(tmp_path, values):
    if subprocess.run(["git", "cat-file", "-e", f"{BEFORE}^{{commit}}"], cwd=REPO).returncode:
        pytest.skip(f"{BEFORE} is not in this repository's history")
    old = _template(_chart_at(BEFORE, tmp_path), VALUE_SETS[values])
    new = _template(CHART, VALUE_SETS[values])
    dropped = _optional_dropped(old, new)
    assert set(dropped) <= {FLEET_TOKEN_REQUIRED}, dropped
    drop = ("intake", INTAKE_METRICS_TOKEN) if "intake" in values else None
    assert (_without_optional(old, {"FORGD_INTAKE_FLEET_TOKEN"})
            == _without_optional(new, {"FORGD_INTAKE_FLEET_TOKEN"}, drop))
    if "intake" in values:
        assert dropped == [FLEET_TOKEN_REQUIRED]
        assert INTAKE_METRICS_TOKEN not in _intake_env(old) and INTAKE_METRICS_TOKEN in _intake_env(new)
    else:
        assert old == new

