"""The Helm chart in GKE mode: ingress.className gce.

One Ingress carries every path, each routed Service gets a BackendConfig,
and IAP sits on the dashboard's backend alone. Rendered on top of the
shipped GKE example, with the dashboard on a generic OIDC issuer unless a
test says otherwise, so IAP's attachment is seen not to depend on it.
"""

from __future__ import annotations

import json
import subprocess

import pytest
import yaml
from test_helm_chart import (
    BASE,
    CHART,
    EKS_VALUES,
    GKE_DASHBOARD_ON,
    GKE_INTAKE_ON,
    GKE_VALUES,
    REPO,
    by_kind,
    helm,
    requires_helm,
)

HOST = "verdict.example.com"
PLACEHOLDER_AUDIENCE = "/projects/0/global/backendServices/0"
GKE_MODE = (
    "--set", "ingress.enabled=true",
    "--set", "ingress.className=gce",
    "--set", f"ingress.host={HOST}",
    "--set", "ingress.gke.managedCertificate=true",
)
ALL_ON = (*GKE_MODE, *GKE_DASHBOARD_ON, *GKE_INTAKE_ON)
PUBLIC_ROLES = ("verdict", "collector", "intake")

# Every value under ingress.gke, set away from its default.
GKE_VALUES_SET = (
    "--set", "ingress.gke.managedCertificate=true",
    "--set", "ingress.gke.staticIpName=forgd-ip",
    "--set", "ingress.gke.collectorTimeoutSec=300",
    "--set", "ingress.gke.iap.oauthclientCredentials.secretName=iap-client",
)


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([helm, "template", "rel", str(CHART), *argv],
                          capture_output=True, text=True, timeout=120)


def _gke_argv(extra: tuple[str, ...]) -> list[str]:
    return ["-f", str(GKE_VALUES), "--set-file", f"policy.inline={REPO / 'policy.yaml'}", *extra]


def render(*extra: str) -> list[dict]:
    out = _run(_gke_argv(extra))
    if out.returncode != 0:
        raise AssertionError(out.stderr.strip())
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def render_error(*extra: str) -> str:
    out = _run(_gke_argv(extra))
    assert out.returncode != 0, "expected the render to be refused, and it was not"
    return " ".join(out.stderr.split())


@pytest.fixture(scope="module")
def docs() -> list[dict]:
    return render(*ALL_ON)


def _services(docs: list[dict]) -> dict[str, dict]:
    """component -> Service."""
    return {d["metadata"]["labels"]["app.kubernetes.io/component"]: d
            for d in by_kind(docs, "Service").values()}


def _backend_config_of(docs: list[dict], service: dict) -> dict:
    """The BackendConfig a Service's annotation names, which must exist."""
    ref = json.loads(service["metadata"]["annotations"]["cloud.google.com/backend-config"])
    assert list(ref) == ["default"], ref
    configs = by_kind(docs, "BackendConfig")
    assert ref["default"] in configs, (ref, sorted(configs))
    return configs[ref["default"]]


def _ingress(docs: list[dict]) -> dict:
    ingresses = list(by_kind(docs, "Ingress").values())
    assert len(ingresses) == 1, [i["metadata"]["name"] for i in ingresses]
    return ingresses[0]


def _routes(ingress: dict) -> dict[str, dict[tuple[str, str], str]]:
    """host -> (path, pathType) -> backend Service name."""
    return {r["host"]: {(p["path"], p["pathType"]): p["backend"]["service"]["name"]
                        for p in r["http"]["paths"]}
            for r in ingress["spec"]["rules"]}


# --- IAP placement -------------------------------------------------------

@requires_helm
def test_the_public_backends_never_carry_iap(docs):
    """Anthropic authenticates to verdict with a signature and to the
    collector with an OTLP header, and intake with a bearer token. A
    sign-in redirect on any of them is a delivery failure, not a deny."""
    services = _services(docs)
    for role in PUBLIC_ROLES:
        config = _backend_config_of(docs, services[role])
        assert config["spec"]["iap"] == {"enabled": False}, (role, config["spec"])
    # The only BackendConfig with IAP on is the dashboard's.
    with_iap = [n for n, c in by_kind(docs, "BackendConfig").items() if c["spec"].get("iap", {}).get("enabled")]
    assert with_iap == ["rel-forgd-verdict-dashboard"], with_iap


@requires_helm
def test_the_dashboard_backend_has_iap(docs):
    config = _backend_config_of(docs, _services(docs)["dashboard"])
    assert config["spec"]["iap"] == {"enabled": True}, config["spec"]


@requires_helm
@pytest.mark.parametrize("auth", [
    GKE_DASHBOARD_ON,
    ("--set", "dashboard.auth.audience=/projects/123456789012/global/backendServices/9876543210"),
])
def test_iap_is_attached_to_the_dashboard_with_platform_iap(auth):
    docs = render(*GKE_MODE, *auth)
    assert _backend_config_of(docs, _services(docs)["dashboard"])["spec"]["iap"]["enabled"] is True


@requires_helm
@pytest.mark.parametrize("platform", ["", "cloud_run"])
def test_a_gke_dashboard_that_does_not_sign_in_through_iap_is_refused(platform):
    """IAP answers every request first, so any other sign-in is unreachable."""
    err = render_error(*GKE_MODE,
                       "--set", "dashboard.enabled=true",
                       "--set", "dashboard.auth.mode=oidc_jwt",
                       "--set", f"dashboard.auth.platform={platform}",
                       "--set", "dashboard.auth.issuer=https://idp.example.com/",
                       "--set", "dashboard.auth.jwksUrl=https://idp.example.com/keys",
                       "--set", "dashboard.auth.audience=forgd-dashboard")
    assert "ingress.className gce puts the dashboard behind IAP" in err, err


@requires_helm
def test_a_custom_iap_oauth_client_is_optional():
    docs = render(*ALL_ON, "--set", "ingress.gke.iap.oauthclientCredentials.secretName=iap-client")
    assert _backend_config_of(docs, _services(docs)["dashboard"])["spec"]["iap"] == {
        "enabled": True, "oauthclientCredentials": {"secretName": "iap-client"}}


# --- one Ingress ---------------------------------------------------------

@requires_helm
def test_exactly_one_ingress_carries_every_path(docs):
    """GCE builds one load balancer, with its own address, per Ingress."""
    ingress = _ingress(docs)
    assert "ingressClassName" not in ingress["spec"]
    annotations = ingress["metadata"]["annotations"]
    assert annotations["kubernetes.io/ingress.class"] == "gce"
    assert annotations["kubernetes.io/ingress.allow-http"] == "false"

    full = "rel-forgd-verdict"
    assert _routes(ingress) == {HOST: {
        ("/hook", "Prefix"): f"{full}-verdict",
        ("/v1", "Prefix"): f"{full}-collector",
        ("/intake", "Prefix"): f"{full}-intake",
        ("/scan", "Prefix"): f"{full}-intake",
        ("/healthz", "Exact"): f"{full}-verdict",
        ("/metrics", "Exact"): f"{full}-verdict",
        ("/health", "Exact"): f"{full}-collector",
        ("/stats", "Exact"): f"{full}-collector",
        ("/", "Prefix"): f"{full}-dashboard",
    }}


@requires_helm
def test_a_separate_dashboard_host_is_a_second_rule_on_the_same_ingress():
    docs = render(*ALL_ON, "--set", "ingress.dashboard.host=dash.example.com")
    routes = _routes(_ingress(docs))
    assert set(routes) == {HOST, "dash.example.com"}, routes
    assert routes["dash.example.com"] == {("/", "Prefix"): "rel-forgd-verdict-dashboard"}
    assert ("/", "Prefix") not in routes[HOST]
    [cert] = by_kind(docs, "ManagedCertificate").values()
    assert cert["spec"]["domains"] == [HOST, "dash.example.com"]


@requires_helm
def test_every_routed_service_has_a_backend_config_and_a_neg(docs):
    services = {s["metadata"]["name"]: s for s in by_kind(docs, "Service").values()}
    routed = {name for paths in _routes(_ingress(docs)).values() for name in paths.values()}
    assert routed == set(services), (routed, sorted(services))
    for name in routed:
        annotations = services[name]["metadata"]["annotations"]
        assert json.loads(annotations["cloud.google.com/neg"]) == {"ingress": True}, name
        _backend_config_of(docs, services[name])


# --- health checks and timeouts ------------------------------------------

@requires_helm
def test_every_backend_config_health_checks_healthz_on_the_serving_port(docs):
    configs = by_kind(docs, "BackendConfig")
    assert len(configs) == 4, sorted(configs)
    deployments = by_kind(docs, "Deployment")
    for service in by_kind(docs, "Service").values():
        check = _backend_config_of(docs, service)["spec"]["healthCheck"]
        [deployment] = [d for d in deployments.values()
                        if d["spec"]["selector"]["matchLabels"] == service["spec"]["selector"]]
        container_port = deployment["spec"]["template"]["spec"]["containers"][0]["ports"][0]["containerPort"]
        assert check == {"type": "HTTP", "requestPath": "/healthz",
                         "port": container_port}, (service["metadata"]["name"], check)


@requires_helm
def test_the_collector_backend_outlasts_the_30_second_default(docs):
    """A batch is scanned group by group, each up to otel.scan.budget_ms."""
    configs = {c["metadata"]["labels"]["app.kubernetes.io/component"]: c["spec"]
               for c in by_kind(docs, "BackendConfig").values()}
    assert configs["collector"]["timeoutSec"] > 30
    assert [r for r, c in configs.items() if "timeoutSec" in c] == ["collector"]


# --- TLS -----------------------------------------------------------------

@requires_helm
def test_a_managed_certificate_covers_every_host(docs):
    [cert] = by_kind(docs, "ManagedCertificate").values()
    assert cert["spec"]["domains"] == [HOST]
    assert _ingress(docs)["metadata"]["annotations"]["networking.gke.io/managed-certificates"] == cert["metadata"]["name"]
    assert "tls" not in _ingress(docs)["spec"]


@requires_helm
def test_a_tls_secret_is_the_alternative():
    docs = render(*ALL_ON, "--set", "ingress.gke.managedCertificate=false",
                  "--set", "ingress.tls.secretName=verdict-tls",
                  "--set", "ingress.extraHosts={b.example.com}")
    assert not by_kind(docs, "ManagedCertificate")
    ingress = _ingress(docs)
    assert ingress["spec"]["tls"] == [{"hosts": [HOST, "b.example.com"], "secretName": "verdict-tls"}]
    assert "networking.gke.io/managed-certificates" not in ingress["metadata"]["annotations"]


@requires_helm
@pytest.mark.parametrize("extra,message", [
    (("--set", "ingress.gke.managedCertificate=false"), "no certificate to serve"),
    (("--set", "ingress.tls.enabled=false"), "serves nothing"),
    (("--set", "ingress.tls.clusterIssuer=letsencrypt"), "clusterIssuer does not apply"),
])
def test_a_gke_ingress_without_a_certificate_is_refused(extra, message):
    assert message in render_error(*ALL_ON, *extra)


@requires_helm
def test_a_static_address_is_named_when_given():
    docs = render(*ALL_ON, "--set", "ingress.gke.staticIpName=forgd-ip")
    assert _ingress(docs)["metadata"]["annotations"]["kubernetes.io/ingress.global-static-ip-name"] == "forgd-ip"
    unset = render(*ALL_ON, "--set", "ingress.gke.staticIpName=")
    assert "kubernetes.io/ingress.global-static-ip-name" not in _ingress(unset)["metadata"]["annotations"]


# --- annotation guards ---------------------------------------------------

@requires_helm
@pytest.mark.parametrize("key", [
    "cloud.google.com/backend-config",
    "beta.cloud.google.com/backend-config",
    "Cloud.Google.com/Backend-Config",
    "example.com/iap-enabled",
    "kubernetes.io/ingress.allow-http",
    "kubernetes.io/ingress.class",
    "nginx.ingress.kubernetes.io/auth-url",
])
def test_an_annotation_that_could_front_the_public_paths_is_refused(key):
    escaped = key.replace(".", "\\.")
    err = render_error(*ALL_ON, "--set", f"ingress.annotations.{escaped}=x")
    assert f"ingress.annotations.{key}" in err, err


@requires_helm
@pytest.mark.parametrize("map_", ["ingress.diagnostics.annotations", "ingress.dashboard.annotations"])
def test_the_per_object_annotation_maps_are_refused(map_):
    err = render_error(*ALL_ON, "--set", f"{map_}.example\\.com/x=y")
    assert "do not apply with ingress.className gce" in err, err


@requires_helm
def test_a_frontend_config_annotation_is_allowed():
    """A FrontendConfig applies to the load balancer's frontend: redirects
    and SSL policy, not a backend."""
    docs = render(*ALL_ON, "--set", "ingress.annotations.networking\\.gke\\.io/v1beta1\\.FrontendConfig=fc")
    assert _ingress(docs)["metadata"]["annotations"]["networking.gke.io/v1beta1.FrontendConfig"] == "fc"


# --- the shipped example -------------------------------------------------

@requires_helm
def test_the_example_as_shipped_is_gke_mode_with_iap_on_the_dashboard_only():
    """The install in step 2 of its header, with nothing layered on."""
    docs = render("--set-string", "orgIds.primary=00000000-0000-0000-0000-000000000000")
    ingress = _ingress(docs)
    assert ingress["metadata"]["annotations"]["kubernetes.io/ingress.class"] == "gce"
    assert ingress["metadata"]["annotations"]["kubernetes.io/ingress.global-static-ip-name"] == "forgd-verdict-ip"
    services = _services(docs)
    iap = {role: _backend_config_of(docs, s)["spec"]["iap"]["enabled"] for role, s in services.items()}
    assert iap == {"verdict": False, "collector": False, "dashboard": True}, iap
    assert by_kind(docs, "ManagedCertificate")

    [dashboard] = [d for d in by_kind(docs, "Deployment").values() if d["metadata"]["name"].endswith("-dashboard")]
    env = {e["name"]: e.get("value") for e in dashboard["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["FORGD_DASHBOARD_PLATFORM"] == "iap"
    assert env["FORGD_DASHBOARD_AUDIENCE"] == PLACEHOLDER_AUDIENCE


def test_the_example_audience_is_the_placeholder():
    values = yaml.safe_load(GKE_VALUES.read_text(encoding="utf-8"))
    assert values["dashboard"]["auth"]["audience"] == PLACEHOLDER_AUDIENCE


# --- other renders are untouched -----------------------------------------

@requires_helm
@pytest.mark.parametrize("argv", [
    [*BASE],
    [*BASE, "--set", "dashboard.enabled=true", "--set", "intake.enabled=true",
     "--set", "intake.clients={alice}", "--set", "ingress.dashboard.host=dash.example.test"],
    ["-f", str(EKS_VALUES), "--set-file", f"policy.inline={REPO / 'policy.yaml'}"],
], ids=["default", "dashboard-intake-host", "eks"])
def test_gke_values_change_nothing_outside_gke_mode(argv):
    """Every GKE setting is gated on className gce, so setting all of them on
    a non-GKE render leaves it byte-identical."""
    plain, with_gke = _run(argv), _run([*argv, *GKE_VALUES_SET])
    assert plain.returncode == 0, plain.stderr
    assert with_gke.returncode == 0, with_gke.stderr
    assert with_gke.stdout == plain.stdout
    for d in yaml.safe_load_all(plain.stdout):
        if d and d["kind"] in ("BackendConfig", "ManagedCertificate"):
            raise AssertionError(d["metadata"]["name"])
        if d and d["kind"] == "Service":
            assert "annotations" not in d["metadata"], d["metadata"]["name"]
