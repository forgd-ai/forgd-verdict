"""The chart's connector role: off by default, public like /hook, on the reader identity."""

from __future__ import annotations

import json

import pytest
import test_helm_gke as gke_mode
from test_helm_chart import (
    GKE_READER,
    READER_ID,
    WRITER_ID,
    by_kind,
    render,
    render_eks,
    render_error,
    render_gke,
    requires_helm,
)

pytestmark = requires_helm

FULL = "rel-forgd-verdict"
HOST = "verdict.example.test"
ISSUER = "https://login.example.com/tenant/v2.0"
AUTH = (
    "--set", "connector.enabled=true",
    "--set", f"connector.auth.issuer={ISSUER}",
    "--set", "connector.auth.jwksUrl=https://login.example.com/tenant/discovery/v2.0/keys",
    "--set", f"connector.auth.audience={{https://{HOST}/mcp,api-client-id}}",
    "--set", f"connector.scopes={{https://{HOST}/mcp/findings.read}}",
    "--set", "connector.requiredScope=findings.read",
)
PRM = "/.well-known/oauth-protected-resource/mcp"


def _named(docs, suffix="connector"):
    return [d for d in docs if d["metadata"]["name"].endswith(f"-{suffix}")
            or d["metadata"]["name"] == f"{FULL}-{suffix}"]


def _env(deployment) -> dict[str, str]:
    [container] = deployment["spec"]["template"]["spec"]["containers"]
    return {e["name"]: e.get("value") for e in container["env"]}


def _paths(ingress) -> list[tuple[str, str, str, str]]:
    return [(r["host"], p["path"], p["pathType"], p["backend"]["service"]["name"])
            for r in ingress["spec"]["rules"] for p in r["http"]["paths"]]


# --- off -------------------------------------------------------------------

@pytest.mark.parametrize("renderer", [render, render_eks, render_gke])
def test_off_by_default_nothing_is_rendered(renderer):
    docs = renderer()
    assert not [d["metadata"]["name"] for d in docs if "connector" in d["metadata"]["name"]]
    text = json.dumps(docs)
    assert "FORGD_CONNECTOR" not in text and "/mcp" not in text


def test_off_in_gke_mode_nothing_is_rendered():
    docs = gke_mode.render(*gke_mode.ALL_ON)
    assert "connector" not in json.dumps(docs)


# --- on ----------------------------------------------------------------------

@pytest.fixture(scope="module")
def on():
    return render(*AUTH)


def test_its_own_deployment_service_and_service_account(on):
    assert {d["kind"] for d in _named(on)} >= {"Deployment", "Service", "ServiceAccount", "Ingress"}
    dep = by_kind(on, "Deployment")[f"{FULL}-connector"]
    spec = dep["spec"]["template"]["spec"]
    assert spec["serviceAccountName"] == f"{FULL}-connector"
    svc = by_kind(on, "Service")[f"{FULL}-connector"]
    assert svc["spec"]["selector"]["app.kubernetes.io/component"] == "connector"
    assert svc["spec"]["ports"][0]["port"] == 8090


def test_the_service_account_carries_the_reader_identity(on):
    sa = by_kind(on, "ServiceAccount")[f"{FULL}-connector"]
    assert sa["metadata"]["labels"]["forgd.ai/store-access"] == "reader"
    assert sa["metadata"]["annotations"]["azure.workload.identity/client-id"] == READER_ID
    assert WRITER_ID not in json.dumps(sa)
    env = _env(by_kind(on, "Deployment")[f"{FULL}-connector"])
    assert env["AZURE_CLIENT_ID"] == READER_ID


def test_no_hash_salt_and_no_secret_reaches_the_connector(on):
    [container] = by_kind(on, "Deployment")[f"{FULL}-connector"]["spec"]["template"]["spec"]["containers"]
    assert "FORGD_HASH_SALT" not in {e["name"] for e in container["env"]}
    assert not [e for e in container["env"] if "valueFrom" in e]
    assert "envFrom" not in container


def test_the_environment_is_what_the_app_reads(on):
    from forgd_verdict.policy import ENV_OVERRIDES

    env = _env(by_kind(on, "Deployment")[f"{FULL}-connector"])
    assert env["FORGD_ROLE"] == "connector"
    assert env["FORGD_CONNECTOR_ENABLED"] == "true"
    assert env["FORGD_CONNECTOR_AUTH_MODE"] == "oidc_jwt"
    assert env["FORGD_CONNECTOR_RESOURCE"] == f"https://{HOST}/mcp"
    assert json.loads(env["FORGD_CONNECTOR_AUDIENCE"]) == [f"https://{HOST}/mcp", "api-client-id"]
    assert json.loads(env["FORGD_CONNECTOR_SCOPES"]) == [f"https://{HOST}/mcp/findings.read"]
    assert env["FORGD_CONNECTOR_REQUIRED_SCOPE"] == "findings.read"
    for name in env:
        if name.startswith("FORGD_CONNECTOR_"):
            assert name in ENV_OVERRIDES, name


def test_the_rendered_environment_starts_the_app(on, monkeypatch, tmp_path):
    """The chart's env through the real policy loader and config check."""
    from pathlib import Path

    from forgd_verdict.connector import config
    from forgd_verdict.policy import load_policy

    for name, value in _env(by_kind(on, "Deployment")[f"{FULL}-connector"]).items():
        if value is not None and name.startswith("FORGD_CONNECTOR_"):
            monkeypatch.setenv(name, value)
    cfg = config.load(load_policy(Path(__file__).resolve().parent.parent / "policy.yaml"))
    assert cfg.resource == f"https://{HOST}/mcp" and cfg.auth.header == "authorization"


def test_the_ingress_is_public_like_hook(on):
    ing = by_kind(on, "Ingress")[f"{FULL}-connector"]
    ann = ing["metadata"]["annotations"]
    assert ann["nginx.ingress.kubernetes.io/enable-global-auth"] == "false"
    assert ann["nginx.ingress.kubernetes.io/enable-modsecurity"] == "false"
    assert not [k for k in ann if "auth-" in k.split("/")[-1]]
    assert _paths(ing) == [(HOST, "/mcp", "Exact", f"{FULL}-connector"),
                           (HOST, PRM, "Exact", f"{FULL}-connector")]


def test_no_other_ingress_routes_the_connector(on):
    for name, ing in by_kind(on, "Ingress").items():
        if name != f"{FULL}-connector":
            assert f"{FULL}-connector" not in json.dumps(ing), name


def test_the_other_objects_are_as_they_were_with_it_off(on):
    off = {(d["kind"], d["metadata"]["name"]): d for d in render()}
    now = {(d["kind"], d["metadata"]["name"]): d for d in on}
    added = set(now) - set(off)
    assert added == {("Deployment", f"{FULL}-connector"), ("Service", f"{FULL}-connector"),
                     ("ServiceAccount", f"{FULL}-connector"), ("Ingress", f"{FULL}-connector")}
    for key, doc in off.items():
        assert now[key] == doc, key


def test_its_own_hostname_gets_its_own_certificate():
    docs = render(*AUTH, "--set", "ingress.connector.host=mcp.example.test",
                  "--set", "connector.auth.audience=x")
    ing = by_kind(docs, "Ingress")[f"{FULL}-connector"]
    assert ing["spec"]["tls"] == [{"hosts": ["mcp.example.test"],
                                   "secretName": f"{FULL}-connector-tls"}]
    assert ing["metadata"]["annotations"]["cert-manager.io/cluster-issuer"] == "letsencrypt"
    assert {h for h, *_ in _paths(ing)} == {"mcp.example.test"}
    env = _env(by_kind(docs, "Deployment")[f"{FULL}-connector"])
    assert env["FORGD_CONNECTOR_RESOURCE"] == "https://mcp.example.test/mcp"


def test_the_source_allowlist_is_optional():
    docs = render(*AUTH, "--set", "ingress.connector.sourceRanges={160.79.104.0/21}")
    ann = by_kind(docs, "Ingress")[f"{FULL}-connector"]["metadata"]["annotations"]
    assert ann["nginx.ingress.kubernetes.io/whitelist-source-range"] == "160.79.104.0/21"
    ann = by_kind(render(*AUTH), "Ingress")[f"{FULL}-connector"]["metadata"]["annotations"]
    assert "nginx.ingress.kubernetes.io/whitelist-source-range" not in ann


def test_on_eks_the_service_account_is_the_readers():
    docs = render_eks(*AUTH)
    sa = by_kind(docs, "ServiceAccount")[f"{FULL}-connector"]
    assert sa["metadata"]["labels"]["forgd.ai/store-access"] == "reader"


def test_on_gke_the_account_is_the_readers():
    docs = render_gke(*AUTH)
    sa = by_kind(docs, "ServiceAccount")[f"{FULL}-connector"]
    assert sa["metadata"]["annotations"]["iam.gke.io/gcp-service-account"] == GKE_READER


# --- GKE mode ------------------------------------------------------------------

def test_gke_mode_routes_the_connector_without_iap():
    docs = gke_mode.render(*gke_mode.ALL_ON, *AUTH)
    [ing] = by_kind(docs, "Ingress").values()
    paths = [(p, t, s) for _h, p, t, s in _paths(ing)]
    assert ("/mcp", "Exact", f"{FULL}-connector") in paths
    assert (PRM, "Exact", f"{FULL}-connector") in paths
    assert paths.index(("/mcp", "Exact", f"{FULL}-connector")) < \
        [p for p, *_ in paths].index("/")
    bc = by_kind(docs, "BackendConfig")[f"{FULL}-connector"]
    assert bc["spec"]["iap"] == {"enabled": False}
    assert bc["spec"]["healthCheck"] == {"type": "HTTP", "requestPath": "/healthz", "port": 8090}
    svc = by_kind(docs, "Service")[f"{FULL}-connector"]
    assert "backend-config" in json.dumps(svc["metadata"]["annotations"])


def test_gke_mode_certificate_covers_its_own_host():
    docs = gke_mode.render(*gke_mode.GKE_MODE, *AUTH, "--set", "ingress.connector.host=mcp.example.com",
                           "--set", "connector.auth.audience=x")
    [cert] = by_kind(docs, "ManagedCertificate").values()
    assert "mcp.example.com" in cert["spec"]["domains"]
    [ing] = by_kind(docs, "Ingress").values()
    assert ("mcp.example.com", "/mcp", "Exact", f"{FULL}-connector") in _paths(ing)


# --- refusals ------------------------------------------------------------------

@pytest.mark.parametrize("args,message", [
    (("--set", "connector.enabled=true", "--set", "connector.requiredScope=findings.read"),
     "connector.auth.issuer is empty"),
    (("--set", "connector.enabled=true", "--set", "connector.requiredScope=findings.read",
      "--set", f"connector.auth.issuer={ISSUER}",
      "--set", "connector.auth.jwksUrl=https://k"), "connector.auth.audience is empty"),
    (("--set", "connector.enabled=true", "--set", "connector.requiredScope=findings.read",
      "--set", f"connector.auth.issuers[0].issuer={ISSUER}",
      "--set", "connector.auth.issuers[0].jwksUrl=https://k"), "issuers[0].audience is empty"),
    ((*AUTH, "--set", "connector.requiredScope="), "connector.requiredScope is empty"),
    ((*AUTH, "--set", "connector.resource=http://verdict.example.test/mcp"), "https URL"),
    ((*AUTH, "--set", "connector.resource=https://Verdict.example.test/mcp"), "lowercase"),
    ((*AUTH, "--set", "connector.resource=https://verdict.example.test/findings"), "end in /mcp"),
    ((*AUTH, "--set", "connector.resource=https://other.example.test/mcp"), "must match"),
    ((*AUTH, "--set", "ingress.connector.annotations.nginx\\.ingress\\.kubernetes\\.io/auth-url=https://x"),
     "ingress.connector.annotations.nginx.ingress.kubernetes.io/auth-url fronts or rewrites /mcp"),
    ((*AUTH, "--set", "ingress.connector.annotations.nginx\\.ingress\\.kubernetes\\.io/enable-global-auth=true"),
     "fronts or rewrites /mcp"),
    ((*AUTH, "--set", "ingress.connector.annotations.nginx\\.ingress\\.kubernetes\\.io/server-snippet=x"),
     "fronts or rewrites /mcp"),
    ((*AUTH, "--set", "ingress.connector.annotations.alb\\.ingress\\.kubernetes\\.io/auth-type=oidc"),
     "fronts or rewrites /mcp"),
    ((*AUTH, "--set", "ingress.extraHosts={mcp.example.test}",
      "--set", "ingress.connector.host=mcp.example.test"), "also in ingress.extraHosts"),
    ((*AUTH, "--set", "ingress.dashboard.host=same.example.test",
      "--set", "ingress.connector.host=same.example.test"), "both same.example.test"),
    ((*AUTH, "--set", "dashboard.enabled=false",
      "--set", f"serviceAccounts.reader.clientId={WRITER_ID}"), "the connector must hold a reader identity"),
])
def test_a_misconfigured_connector_does_not_render(args, message):
    assert message in render_error(*args)


def test_without_a_reader_client_id_the_connector_does_not_render():
    err = render_error(*AUTH, "--set", "dashboard.enabled=false",
                       "--set", "serviceAccounts.reader.clientId=")
    assert "connector is on" in err


@pytest.mark.parametrize("extra", [
    ("--set", "ingress.connector.annotations.a=b"),
    ("--set", "ingress.connector.sourceRanges={160.79.104.0/21}"),
])
def test_gke_mode_refuses_connector_ingress_settings(extra):
    assert "do not apply with ingress.className gce" in gke_mode.render_error(
        *gke_mode.GKE_MODE, *AUTH, *extra)
