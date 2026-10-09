"""What `extraEnv` may not set, which workload each Secret key reaches, and
which renders route the dashboard from an Ingress.

`extraEnv` is emitted on every workload after the chart's own entries, and
Kubernetes keeps the last of two entries with one name. So a key naming a
variable the chart sets replaces the value the chart's refusals checked,
and a credential there reaches the dashboard and the connector in plaintext.
Sink bearers and the shared header have a Secret key each, on the one
workload that reads them. `dashboard.serveOpen` never renders a route to the
dashboard.
"""

from __future__ import annotations

import re

import pytest
import yaml
from test_helm_admins import ADMINS, CONNECTOR
from test_helm_chart import (
    INTAKE,
    REPO,
    base_without,
    by_kind,
    env_of,
    pod_specs,
    render,
    render_error,
    render_gke,
    requires_helm,
)

from forgd_verdict.policy import ENV_OVERRIDES, SECRET_LIST_PATHS, SECRET_MAP_PATHS, SECRET_PATHS

pytestmark = requires_helm

CANARY = "canary-5b0e72c4"
FULL = "rel-forgd-verdict"
UNROUTED = ("--set", "ingress.dashboard.enabled=false")
OIDC = (
    "--set", "dashboard.auth.mode=oidc_jwt",
    "--set", "dashboard.auth.jwksUrl=https://idp.example.test/keys",
    "--set", "dashboard.auth.issuer=https://idp.example.test/",
    "--set", "dashboard.auth.audience=an-app-id",
)
SINK_TOKEN = "synthetic-sink-bearer"
HEADER = "synthetic-shared-header"


def _policy(*, sinks=None, headers=None) -> str:
    policy = yaml.safe_load((REPO / "policy.yaml").read_text())
    if sinks is not None:
        policy["sinks"] = sinks
    if headers is not None:
        policy["server"]["required_headers"] = headers
    return yaml.safe_dump(policy)


SIEM = {"name": "siem", "type": "otlp", "endpoint": "https://otel.example.test:4318",
        "token": "$FORGD_SINK_TOKEN_SIEM"}
SINK_POLICY = _policy(sinks=[SIEM, {**SIEM, "name": "siem-eu", "token": "$FORGD_SINK_TOKEN_SIEM_EU"}],
                      headers={"x-forgd-shared": "$FORGD_SHARED_HEADER",
                               "x-forgd-edge": "$FORGD_SHARED_HEADER_EDGE"})
SINK_SECRETS = (
    "--set-string", f"secrets.sinkTokens.siem={SINK_TOKEN}",
    "--set-string", f"secrets.sinkTokens.siem-eu={SINK_TOKEN}",
    "--set-string", f"secrets.sharedHeader={HEADER}",
    "--set-string", f"secrets.sharedHeaders.edge={HEADER}",
)
# Every workload, every optional Secret key: the configuration whose env
# names the ownership tests check.
EVERYTHING = (
    *ADMINS, *CONNECTOR, *INTAKE,
    "--set", "intake.fleet.enabled=true",
    "--set-string", "secrets.intakeFleetToken=synthetic-fleet-token",
    "--set", "verdict.signingOrgs={primary}",
    "--set-string", "secrets.webhookSecrets.primary.current=whsec_synthetic",
    "--set", "ingest.complianceOrgs={primary}",
    "--set-string", "secrets.complianceKeys.primary=synthetic-compliance-key",
    "--set-string", "secrets.managedAgentsKeys.ws1=synthetic-workspace-key",
    "--set", "intake.fleet.orgs={primary}",
    "--set-string", "secrets.intakeFleetTokens.primary.current=synthetic-fleet-token",
    "--set", "otelFleets.laptops={primary}",
    "--set-string", "secrets.otelTokens.laptops=synthetic-otel-token",
    "--set", "dashboard.auth.groupsClaim=roles",
    "--set", "dashboard.auth.header=x-user",
    "--set", "dashboard.admins.gcsInheritedAuditedBy=someone",
    *SINK_SECRETS,
)


@pytest.fixture(scope="module")
def everything() -> list[dict]:
    return render(*EVERYTHING, policy=SINK_POLICY)


def _refused(key: str, *extra: str) -> str:
    err = render_error(*OIDC, *extra, "--set-string", f"extraEnv.{key}={CANARY}")
    assert CANARY not in err
    return err


# -- FV2-M10: extraEnv cannot replace what the chart checked -----------------

def test_extra_env_cannot_flip_the_dashboard_to_an_unchecked_trusted_header():
    err = render_error(
        *base_without("dashboard.trustedHeaderStrippedBy", "trustedHeaderWithoutPolicyAcknowledged"),
        *OIDC,
        "--set-string", "extraEnv.FORGD_DASHBOARD_AUTH_MODE=trusted_header",
        "--set-string", "extraEnv.FORGD_DASHBOARD_STRIPPED_BY=nobody",
    )
    assert "names a variable the chart sets or checks" in err, err


@pytest.mark.parametrize("key", sorted(ENV_OVERRIDES))
def test_extra_env_refuses_every_policy_override(key):
    """Each is a setting the chart sets from a value it validated, or one the
    policy file it mounts already decides."""
    assert "extraEnv." + key in _refused(key)


def test_every_variable_the_chart_sets_is_refused_in_extra_env(everything):
    names = set()
    for spec in pod_specs(everything).values():
        names |= set(env_of(spec))
    assert {"FORGD_SINK_TOKEN_SIEM", "FORGD_SHARED_HEADER_EDGE", "FORGD_OVERRIDES_VERIFY_KEY",
            "FORGD_CONNECTOR_RESOURCE", "AZURE_CLIENT_ID", "FORGD_ROLE"} <= names, sorted(names)
    accepted = [n for n in sorted(names) if "extraEnv." + n not in _refused(n)]
    assert not accepted, accepted


# The variables the app reads that no chart value sets and no check depends on.
UNOWNED = {"FORGD_BUILD_COMMIT", "FORGD_GITLEAKSD_WAIT_S"}


def test_every_variable_the_app_reads_is_refused_or_listed_as_unowned():
    sources = [*(REPO / "src" / "forgd_verdict").rglob("*.py"), REPO / "deploy" / "entrypoint.sh"]
    found = set()
    for path in sources:
        found |= set(re.findall(r"\bFORGD_[A-Z0-9_]*[A-Z0-9_]", path.read_text(encoding="utf-8")))
    assert "FORGD_DASHBOARD_STRIPPED_BY" in found and "FORGD_POLICY_INLINE_GZ" in found
    accepted = []
    for name in sorted(found - UNOWNED):
        key = name + "X" if name.endswith("_") else name
        if "extraEnv." + key not in _refused(key):
            accepted.append(name)
    assert not accepted, f"refuse these in extraEnv, or add them to UNOWNED: {accepted}"


# The `$NAME` references in policy.yaml that extraEnv exists to supply.
POLICY_PASSTHROUGH = {"FORGD_SINK_ENDPOINT_AZMON"}


@pytest.mark.parametrize("policy", sorted(str(p.relative_to(REPO)) for p in [REPO / "policy.yaml", *REPO.glob("*/policy.yaml")]))
def test_every_policy_reference_but_the_passthrough_is_refused(policy):
    found = set(re.findall(r"\$([A-Z][A-Z0-9_]+)", (REPO / policy).read_text(encoding="utf-8")))
    found -= {"VAR"}
    accepted = [n for n in sorted(found - POLICY_PASSTHROUGH) if "extraEnv." + n not in _refused(n)]
    assert not accepted, accepted
    for name in sorted(found & POLICY_PASSTHROUGH):
        env = env_of(pod_specs(render(*OIDC, "--set-string", f"extraEnv.{name}=https://x/s"))["collector"])
        assert env[name]["value"] == "https://x/s"


@pytest.mark.parametrize("key", [
    "AZURE_CLIENT_ID", "azure_tenant_id", "AZURE_FEDERATED_TOKEN_FILE",
    "AWS_ACCESS_KEY_ID", "aws_secret_access_key", "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "GOOGLE_APPLICATION_CREDENTIALS",
])
def test_extra_env_refuses_a_cloud_identity(key):
    err = _refused(key)
    assert f"extraEnv.{key} selects a cloud identity" in err, err


@pytest.mark.parametrize("key", ["FORGD_POLICY_INLINE", "forgd_policy_inline_gz", "FORGD_GITLEAKS_CONFIG",
                                 "FORGD_ORG_ID_PRIMARY", "FORGD_VERDICT_BUDGET_MS", "PORT", "Forgd_Role"])
def test_extra_env_refuses_chart_owned_settings_whatever_the_case(key):
    assert f"extraEnv.{key} names a variable the chart sets or checks" in _refused(key)


@pytest.mark.parametrize("key", ["FORGD_SINK_ENDPOINT_AZMON", "FORGD_GITLEAKSD_WAIT_S", "AWS_REGION"])
def test_unowned_extra_env_keys_still_render(key):
    for role, spec in pod_specs(render(*OIDC, "--set-string", f"extraEnv.{key}=1")).items():
        assert env_of(spec)[key]["value"] == "1", role


# -- FV2-M11: sink bearers and shared headers have a Secret path -------------

@pytest.mark.parametrize("key", ["FORGD_SINK_TOKEN_SIEM", "forgd_sink_token_siem", "FORGD_SHARED_HEADER",
                                 "FORGD_SHARED_HEADER_EDGE"])
def test_extra_env_refuses_a_sink_token_or_shared_header(key):
    err = _refused(key)
    assert f"extraEnv.{key} names a credential the chart wires from a Secret" in err, err


def test_a_sink_token_reaches_the_collector_alone_from_its_secret_key(everything):
    specs = pod_specs(everything)
    collector = env_of(specs["collector"])
    assert collector["FORGD_SINK_TOKEN_SIEM"]["valueFrom"]["secretKeyRef"] == {
        "name": f"{FULL}-secrets", "key": "sink-token-siem"}
    assert collector["FORGD_SINK_TOKEN_SIEM_EU"]["valueFrom"]["secretKeyRef"]["key"] == "sink-token-siem-eu"
    for role, spec in specs.items():
        if role != "collector":
            assert not [n for n in env_of(spec) if n.startswith("FORGD_SINK_TOKEN_")], role


def test_a_shared_header_reaches_the_verdict_server_alone(everything):
    specs = pod_specs(everything)
    verdict = env_of(specs["verdict"])
    assert verdict["FORGD_SHARED_HEADER"]["valueFrom"]["secretKeyRef"]["key"] == "shared-header"
    assert verdict["FORGD_SHARED_HEADER_EDGE"]["valueFrom"]["secretKeyRef"]["key"] == "shared-header-edge"
    for role, spec in specs.items():
        if role != "verdict":
            assert not [n for n in env_of(spec) if n.startswith("FORGD_SHARED_HEADER")], role


def test_the_chart_managed_secret_holds_the_sink_and_header_values(everything):
    [secret] = by_kind(everything, "Secret").values()
    data = secret["stringData"]
    assert data["sink-token-siem"] == SINK_TOKEN and data["sink-token-siem-eu"] == SINK_TOKEN
    assert data["shared-header"] == HEADER and data["shared-header-edge"] == HEADER


def test_no_value_reaches_a_pod_spec_or_the_policy_configmap(everything):
    for d in everything:
        if d.get("kind") != "Secret":
            text = yaml.safe_dump(d)
            assert SINK_TOKEN not in text and HEADER not in text, d["kind"]


def test_with_an_existing_secret_the_policy_alone_decides_the_keys():
    docs = render("--set", "secrets.existingSecret=from-vault", policy=SINK_POLICY)
    assert not by_kind(docs, "Secret")
    ref = env_of(pod_specs(docs)["collector"])["FORGD_SINK_TOKEN_SIEM"]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": "from-vault", "key": "sink-token-siem"}


@pytest.mark.parametrize("missing, message", [
    ("secrets.sinkTokens.siem", "secrets.sinkTokens.siem is required"),
    ("secrets.sharedHeader=", "secrets.sharedHeader is required"),
    ("secrets.sharedHeaders.edge", "secrets.sharedHeaders.edge is required"),
])
def test_a_chart_managed_secret_missing_a_referenced_value_is_refused(missing, message):
    kept = []
    for i in range(0, len(SINK_SECRETS), 2):
        if not SINK_SECRETS[i + 1].startswith(missing):
            kept += SINK_SECRETS[i:i + 2]
    assert message in render_error(*kept, policy=SINK_POLICY)


@pytest.mark.parametrize("policy, message", [
    pytest.param(_policy(sinks=[{**SIEM, "token": CANARY}]),
                 "sinks[0].token is not a $FORGD_SINK_TOKEN_<NAME> reference", id="literal-token"),
    pytest.param(_policy(sinks=[{**SIEM, "token": "$SIEM_TOKEN"}]),
                 "sinks[0].token is not a $FORGD_SINK_TOKEN_<NAME> reference", id="other-variable"),
    pytest.param(_policy(headers={"x-forgd-shared": CANARY}),
                 "required_headers.x-forgd-shared is not a $FORGD_SHARED_HEADER", id="literal-header"),
])
def test_a_literal_or_unwired_reference_in_the_policy_is_refused_without_its_value(policy, message):
    err = render_error("--set", "secrets.existingSecret=from-vault", policy=policy)
    assert message in err, err
    assert CANARY not in err


@pytest.mark.parametrize("extra, message", [
    (("--set-string", "secrets.sinkTokens.other=x"), "secrets.sinkTokens.other matches no sinks[].token"),
    (("--set-string", "secrets.sharedHeaders.other=x"), "secrets.sharedHeaders.other matches no"),
])
def test_a_secret_value_nothing_reads_is_refused(extra, message):
    assert message in render_error(*SINK_SECRETS, *extra, policy=SINK_POLICY)


# -- Secrets reach only the workloads that read them -------------------------

# Secret key, or key prefix ending in "-", -> the only workloads it may reach.
SECRET_SCOPE = {
    "hash-salt": {"verdict", "collector", "intake", "ingest"},
    "webhook-secret": {"verdict"},
    "webhook-secret-": {"verdict"},
    "shared-header": {"verdict"},
    "shared-header-": {"verdict"},
    "otel-token-": {"collector"},
    "sink-token-": {"collector"},
    "metrics-token": {"verdict", "collector", "intake"},
    "intake-fleet-token": {"intake"},
    "intake-fleet-token-": {"intake"},
    "intake-token-": {"intake"},
    "compliance-key": {"ingest"},
    "compliance-key-": {"ingest"},
    "managed-agents-key-": {"ingest"},
    "dashboard-form-key": {"dashboard"},
    "overrides-signing-key": {"dashboard"},
}


def _scope(key: str) -> set[str] | None:
    if key in SECRET_SCOPE:
        return SECRET_SCOPE[key]
    prefixes = [p for p in SECRET_SCOPE if p.endswith("-") and key.startswith(p)]
    return SECRET_SCOPE[max(prefixes, key=len)] if prefixes else None


def test_every_secret_key_reaches_only_the_workloads_that_read_it(everything):
    unlisted, spread = [], []
    for role, spec in pod_specs(everything).items():
        for entry in env_of(spec).values():
            ref = (entry.get("valueFrom") or {}).get("secretKeyRef")
            if not ref:
                continue
            allowed = _scope(ref["key"])
            if allowed is None:
                unlisted.append(ref["key"])
            elif role not in allowed:
                spread.append((ref["key"], role))
    assert not unlisted, f"give these a scope in SECRET_SCOPE: {unlisted}"
    assert not spread, spread


# Every credential path the policy redacts, and the chart Secret key that
# supplies it. A new path fails here until the chart has a Secret for it.
POLICY_SECRET_KEYS = {
    ("compliance", "api_key"): "compliance-key",
    ("server", "metrics_token"): "metrics-token",
    ("privacy", "hash_salt"): "hash-salt",
    ("hook", "ship_token"): None,
    ("hook", "scan_token"): None,
    ("dashboard", "admins", "form_key"): "dashboard-form-key",
    ("overrides", "signing_key"): "overrides-signing-key",
    ("otel", "orgs", "token"): "otel-token-",
    ("sinks", "token"): "sink-token-",
    ("intake", "clients", "token"): "intake-token-",
    ("intake", "fleet", "tokens"): "intake-fleet-token",
    ("compliance", "orgs", "api_key"): "compliance-key-",
    ("managed_agents", "workspaces", "api_key"): "managed-agents-key-",
    ("server", "required_headers"): "shared-header",
}


def test_every_policy_credential_has_a_chart_secret_key_or_is_laptop_only():
    """`hook.ship_token` and `hook.scan_token` are read by the hook on a
    laptop, never by a workload this chart runs."""
    paths = {*SECRET_PATHS, *((*p, k) for p, k in SECRET_LIST_PATHS), *SECRET_MAP_PATHS}
    assert paths == set(POLICY_SECRET_KEYS), sorted(paths ^ set(POLICY_SECRET_KEYS))
    for key in filter(None, POLICY_SECRET_KEYS.values()):
        assert _scope(key) or _scope(key + "x"), key


# -- FV2-M12: an open dashboard is never routed ------------------------------

def _dashboard_routes(docs: list[dict]) -> list[str]:
    out = []
    for name, ing in by_kind(docs, "Ingress").items():
        for rule in ing["spec"].get("rules", []):
            for path in rule["http"]["paths"]:
                if path["backend"]["service"]["name"] == f"{FULL}-dashboard":
                    out.append(f"{name} {rule.get('host')}{path['path']}")
    return out


@pytest.mark.parametrize("extra", [
    ("--set", "dashboard.auth.mode=none"),
    ("--set", "dashboard.auth.mode=none", "--set", "ingress.dashboard.host=dash.example.test"),
    ("--set", "dashboard.auth.mode=none",
     "--set-string", "ingress.dashboard.annotations.nginx\\.ingress\\.kubernetes\\.io/auth-url=https://a/"),
], ids=["shared-host", "own-host", "auth-annotation"])
def test_serve_open_with_a_routed_dashboard_is_refused(extra):
    err = render_error(*extra, "--set", "dashboard.serveOpen=true")
    assert "Set ingress.dashboard.enabled: false" in err, err


def test_serve_open_renders_no_route_to_the_dashboard():
    docs = render("--set", "dashboard.auth.mode=none", "--set", "dashboard.serveOpen=true", *UNROUTED)
    assert "dashboard" in pod_specs(docs)
    assert f"{FULL}-dashboard" in by_kind(docs, "Service")
    assert not _dashboard_routes(docs)
    assert by_kind(docs, "Ingress"), "the public Ingress still carries /hook and /v1"


def test_serve_open_without_an_ingress_renders():
    docs = render("--set", "dashboard.auth.mode=none", "--set", "dashboard.serveOpen=true",
                  "--set", "ingress.enabled=false")
    assert not by_kind(docs, "Ingress")


@pytest.mark.parametrize("extra", [(), ("--set", "ingress.dashboard.host=dash.example.test")],
                         ids=["shared-host", "own-host"])
def test_an_unrouted_signed_in_dashboard_has_no_ingress(extra):
    assert _dashboard_routes(render(*OIDC, *extra))
    assert not _dashboard_routes(render(*OIDC, *extra, *UNROUTED))


def test_gke_mode_drops_the_dashboard_path_when_unrouted():
    from test_helm_chart import GKE_DASHBOARD_ON
    assert _dashboard_routes(render_gke(*GKE_DASHBOARD_ON))
    assert not _dashboard_routes(render_gke(*GKE_DASHBOARD_ON, *UNROUTED))


@pytest.mark.parametrize("extra", [
    (),
    OIDC,
    ("--set", "dashboard.auth.mode=none", "--set", "dashboard.serveOpen=true", *UNROUTED),
    ("--set", "dashboard.auth.mode=none", "--set", "dashboard.serveOpen=true", "--set", "ingress.enabled=false"),
    (*OIDC, "--set", "ingress.dashboard.host=dash.example.test"),
], ids=["shipped", "oidc", "serve-open", "serve-open-no-ingress", "own-host"])
def test_no_render_routes_a_dashboard_that_serves_open(extra):
    docs = render(*extra)
    open_ = any(env_of(s).get("FORGD_DASHBOARD_SERVE_OPEN") for s in pod_specs(docs).values())
    assert not (open_ and _dashboard_routes(docs))


@pytest.mark.parametrize("module", ["app-aca", "app-cloudrun", "app-ecs"])
def test_no_terraform_app_module_serves_the_dashboard_open(module):
    """Each fronts the dashboard with a sign-in (Easy Auth, IAP, the ALB's
    authenticate-oidc), and the dashboard refuses to bind under mode none
    without FORGD_DASHBOARD_SERVE_OPEN."""
    text = "".join(p.read_text(encoding="utf-8")
                   for p in (REPO / "deploy" / "terraform" / "modules" / module).glob("*.tf"))
    assert "FORGD_DASHBOARD_SERVE_OPEN" not in text
    assert not re.search(r'FORGD_DASHBOARD_AUTH_MODE\s*=\s*"none"', text)


# -- podLabels and podAnnotations, merged after the chart's own ---------------

@pytest.mark.parametrize("key", ["app\\.kubernetes\\.io/component", "helm\\.sh/chart",
                                 "azure\\.workload\\.identity/use", "App\\.Kubernetes\\.io/name"])
def test_pod_labels_cannot_replace_a_label_the_chart_sets(key):
    err = render_error(*OIDC, "--set-string", f"podLabels.{key}=dashboard")
    assert "is a label the chart sets on every pod" in err, err


@pytest.mark.parametrize("key", ["container\\.apparmor\\.security\\.beta\\.kubernetes\\.io/collector",
                                 "seccomp\\.security\\.alpha\\.kubernetes\\.io/pod"])
def test_pod_annotations_cannot_loosen_the_security_profile(key):
    err = render_error(*OIDC, "--set-string", f"podAnnotations.{key}=unconfined")
    assert "sets a pod's AppArmor or seccomp profile" in err, err


def test_other_pod_labels_and_annotations_render():
    docs = render(*OIDC, "--set-string", "podLabels.team=sec",
                  "--set-string", "podAnnotations.prometheus\\.io/scrape=true")
    for d in by_kind(docs, "Deployment").values():
        meta = d["spec"]["template"]["metadata"]
        assert meta["labels"]["team"] == "sec"
        assert meta["annotations"]["prometheus.io/scrape"] == "true"
