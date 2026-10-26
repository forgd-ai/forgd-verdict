"""The Helm chart in AGC mode: ingress.mode agc (docs/design/agc.md).

A Gateway on Application Gateway for Containers and HTTPRoutes in place of
the Ingress objects, each route under the WAF policy its paths need, and
the dashboard reached only through oauth2-proxy.
"""

from __future__ import annotations

import pytest
from test_helm_chart import render, render_error, requires_helm
from test_helm_connector import AUTH as CONNECTOR

pytestmark = requires_helm

FULL = "rel-forgd-verdict"
HOST = "verdict.example.test"
WAF = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/"
POLICIES = {name: f"{WAF}{name}" for name in ("protected", "connector", "hook", "api")}
AGC = (
    "--set", "ingress.mode=agc",
    "--set", "ingress.agc.albId=/subscriptions/0/resourceGroups/rg/providers/"
             "Microsoft.ServiceNetworking/trafficControllers/agc",
    "--set", "ingress.agc.frontend=fe",
    *[x for name, policy in POLICIES.items() for x in ("--set", f"ingress.agc.wafPolicies.{name}={policy}")],
    "--set", "ingress.agc.dashboardBackend.name=oauth2-proxy",
    "--set", "networkPolicy.enabled=true",
    "--set", "networkPolicy.agc.subnetCidr=10.240.8.0/24",
    "--set", "networkPolicy.agc.dashboardProxy.podSelector.matchLabels.app\\.kubernetes\\.io/name=oauth2-proxy",
)
INTAKE = ("--set", "intake.enabled=true", "--set", "intake.clients={dev-laptop}")
ALL_ON = (*AGC, *INTAKE, *CONNECTOR)


def _kind(docs: list[dict], kind: str) -> dict[str, dict]:
    return {d["metadata"]["name"]: d for d in docs if d["kind"] == kind}


def _routes(docs: list[dict]) -> dict[str, dict]:
    return {n.removeprefix(f"{FULL}-"): d for n, d in _kind(docs, "HTTPRoute").items()}


def _paths(route: dict) -> list[tuple[str, str, str]]:
    return [(m["path"]["type"], m["path"]["value"], r["backendRefs"][0]["name"])
            for r in route["spec"]["rules"] for m in r["matches"] if "backendRefs" in r]


def _listeners(docs: list[dict]) -> dict[str, dict]:
    [gateway] = _kind(docs, "Gateway").values()
    return {listener["name"]: listener for listener in gateway["spec"]["listeners"]}


def _sections(route: dict) -> set[str]:
    return {p["sectionName"] for p in route["spec"]["parentRefs"]}


def test_agc_renders_a_gateway_and_routes_and_no_ingress():
    docs = render(*ALL_ON)
    assert _kind(docs, "Ingress") == {}
    assert sorted(_routes(docs)) == ["connector", "dashboard", "diagnostics", "hook", "public", "redirect"]
    [gateway] = _kind(docs, "Gateway").values()
    assert gateway["spec"]["gatewayClassName"] == "azure-alb-external"
    assert gateway["metadata"]["annotations"]["alb.networking.azure.io/alb-id"].endswith("/trafficControllers/agc")
    assert gateway["spec"]["addresses"] == [{"type": "alb.networking.azure.io/alb-frontend", "value": "fe"}]


def test_the_routes_carry_todays_paths():
    routes = _routes(render(*ALL_ON))
    assert _paths(routes["hook"]) == [("PathPrefix", "/hook", f"{FULL}-verdict")]
    assert _paths(routes["public"]) == [("PathPrefix", "/v1", f"{FULL}-collector"),
                                        ("PathPrefix", "/intake", f"{FULL}-intake"),
                                        ("PathPrefix", "/scan", f"{FULL}-intake")]
    assert _paths(routes["diagnostics"]) == [("Exact", "/healthz", f"{FULL}-verdict"),
                                             ("Exact", "/metrics", f"{FULL}-verdict"),
                                             ("Exact", "/health", f"{FULL}-collector"),
                                             ("Exact", "/stats", f"{FULL}-collector")]
    assert _paths(routes["connector"]) == [("Exact", "/mcp", f"{FULL}-connector"),
                                           ("Exact", "/.well-known/oauth-protected-resource/mcp", f"{FULL}-connector")]
    assert _paths(routes["dashboard"]) == [("PathPrefix", "/", "oauth2-proxy")]


def test_only_the_dashboard_route_goes_through_oauth2_proxy():
    for name, route in _routes(render(*ALL_ON)).items():
        backends = {b for _, _, b in _paths(route)}
        assert ("oauth2-proxy" in backends) == (name == "dashboard"), name


def test_disabled_roles_have_no_route():
    routes = _routes(render(*AGC, "--set", "collector.enabled=false", "--set", "ingress.diagnostics.enabled=false",
                            "--set", "ingress.dashboard.enabled=false"))
    assert sorted(routes) == ["hook", "redirect"]


def test_each_route_is_under_the_policy_its_paths_need():
    docs = render(*ALL_ON)
    wafs = {d["spec"]["targetRef"]["name"].removeprefix(f"{FULL}-"): d["spec"]["webApplicationFirewall"]["id"]
            for d in _kind(docs, "WebApplicationFirewallPolicy").values()}
    assert wafs == {"hook": POLICIES["hook"], "public": POLICIES["api"], "diagnostics": POLICIES["api"],
                    "dashboard": POLICIES["protected"], "connector": POLICIES["connector"]}
    for d in _kind(docs, "WebApplicationFirewallPolicy").values():
        assert d["spec"]["targetRef"]["kind"] == "HTTPRoute"


def test_every_route_but_the_redirect_binds_to_https_listeners_only():
    docs = render(*ALL_ON, "--set", "ingress.extraHosts={alt.example.test}")
    listeners = _listeners(docs)
    https = {n for n, listener in listeners.items() if listener["protocol"] == "HTTPS"}
    for name, route in _routes(docs).items():
        if name == "redirect":
            assert _sections(route) == {"http"}
        else:
            assert _sections(route) <= https, name


def test_public_routes_repeat_across_extra_hosts_with_a_listener_each():
    docs = render(*ALL_ON, "--set", "ingress.extraHosts={alt.example.test}")
    listeners = _listeners(docs)
    by_host = {listener.get("hostname"): n for n, listener in listeners.items()}
    for name in ("hook", "public", "diagnostics", "dashboard", "connector"):
        route = _routes(docs)[name]
        assert route["spec"]["hostnames"] == [HOST, "alt.example.test"], name
        assert _sections(route) == {by_host[HOST], by_host["alt.example.test"]}, name


def test_separate_dashboard_and_connector_hosts_get_routes_and_listeners_of_their_own():
    docs = render(*ALL_ON, "--set", "ingress.dashboard.host=dash.example.test",
                  "--set", "ingress.connector.host=mcp.example.test")
    routes = _routes(docs)
    by_host = {listener.get("hostname"): n for n, listener in _listeners(docs).items()}
    assert routes["dashboard"]["spec"]["hostnames"] == ["dash.example.test"]
    assert _sections(routes["dashboard"]) == {by_host["dash.example.test"]}
    assert routes["connector"]["spec"]["hostnames"] == ["mcp.example.test"]
    assert _sections(routes["connector"]) == {by_host["mcp.example.test"]}
    assert _paths(routes["connector"])[0][:2] == ("Exact", "/mcp")
    assert routes["hook"]["spec"]["hostnames"] == [HOST]


def test_the_redirect_sends_port_80_to_https():
    [rule] = _routes(render(*AGC))["redirect"]["spec"]["rules"]
    assert rule["matches"] == [{"path": {"type": "PathPrefix", "value": "/"}}]
    assert rule["filters"] == [{"type": "RequestRedirect",
                                "requestRedirect": {"scheme": "https", "statusCode": 301}}]
    assert "backendRefs" not in rule


def test_cert_manager_issues_one_certificate_per_listener():
    docs = render(*ALL_ON, "--set", "ingress.extraHosts={alt.example.test}")
    [gateway] = _kind(docs, "Gateway").values()
    assert gateway["metadata"]["annotations"]["cert-manager.io/cluster-issuer"] == "letsencrypt"
    https = [listener for listener in _listeners(docs).values() if listener["protocol"] == "HTTPS"]
    secrets = [listener["tls"]["certificateRefs"][0]["name"] for listener in https]
    assert [listener["hostname"] for listener in https] == [HOST, "alt.example.test"]
    assert secrets == [f"{FULL}-tls-0", f"{FULL}-tls-1"]


def test_a_named_secret_with_the_issuer_names_that_secret_on_every_listener():
    docs = render(*AGC, "--set", "ingress.tls.secretName=shared", "--set", "ingress.extraHosts={alt.example.test}")
    [gateway] = _kind(docs, "Gateway").values()
    assert gateway["metadata"]["annotations"]["cert-manager.io/cluster-issuer"] == "letsencrypt"
    https = [listener for listener in _listeners(docs).values() if listener["protocol"] == "HTTPS"]
    assert [listener["tls"]["certificateRefs"][0]["name"] for listener in https] == ["shared", "shared"]


def test_a_named_secret_goes_on_every_listener():
    docs = render(*AGC, "--set", "ingress.tls.clusterIssuer=", "--set", "ingress.tls.secretName=wildcard")
    [gateway] = _kind(docs, "Gateway").values()
    assert "cert-manager.io/cluster-issuer" not in gateway["metadata"]["annotations"]
    https = [listener for listener in _listeners(docs).values() if listener["protocol"] == "HTTPS"]
    assert {listener["tls"]["certificateRefs"][0]["name"] for listener in https} == {"wildcard"}


@pytest.mark.parametrize("name", ["hook", "public"])
def test_the_public_routes_lift_the_60_second_timeout(name):
    route = _routes(render(*ALL_ON))[name]
    assert {r["timeouts"]["request"] for r in route["spec"]["rules"]} == {"300s"}


def test_health_checks_probe_the_ready_path_and_oauth2_proxys_own():
    checks = {d["spec"]["targetRef"]["name"]: d["spec"]["default"]
              for d in _kind(render(*ALL_ON), "HealthCheckPolicy").values()}
    assert sorted(checks) == sorted([f"{FULL}-verdict", f"{FULL}-collector", f"{FULL}-intake",
                                     f"{FULL}-connector", "oauth2-proxy"])
    for name, check in checks.items():
        assert check["http"]["path"] == ("/ping" if name == "oauth2-proxy" else "/healthz"), name


def test_the_defaults_for_other_modes_do_not_refuse_agc():
    """className nginx and the GKE defaults are untouched values, and render nothing here."""
    assert render(*AGC)


# --- refusals ------------------------------------------------------------------

@pytest.mark.parametrize(("extra", "message"), [
    (("--set", "ingress.tls.enabled=false"), "ingress.tls.enabled false"),
    (("--set", "ingress.agc.frontend="), "needs ingress.agc.albId and ingress.agc.frontend"),
    (("--set", "ingress.hook.sourceRanges={203.0.113.0/24}"), "hook_source_ranges"),
    (("--set", "ingress.connector.sourceRanges={203.0.113.0/24}"), "connector_source_ranges"),
    (("--set", "ingress.className=webapprouting.kubernetes.azure.com"), "no Ingress and no class"),
    (("--set", "ingress.annotations.foo=bar"), "are Ingress annotations"),
    (("--set", "ingress.dashboard.annotations.foo=bar"), "are Ingress annotations"),
    (("--set", "ingress.gke.staticIpName=ip"), "ingress.gke values do not apply"),
    (("--set", "ingress.gke.collectorTimeoutSec=30"), "ingress.gke values do not apply"),
    (("--set", "networkPolicy.enabled=false"), "with the dashboard routed needs networkPolicy.enabled"),
    (("--set", "networkPolicy.enabled=false", "--set", "networkPolicy.agcWithoutPolicyAcknowledged=true"),
     "with the dashboard routed needs networkPolicy.enabled"),
    (("--set", "ingress.agc.dashboardBackend.name=rel-forgd-verdict-dashboard"), "is the dashboard's own Service"),
    (("--set", "networkPolicy.dashboardExtraFrom[0].ipBlock.cidr=10.0.0.0/8"), "dashboardExtraFrom does not apply"),
    (("--set", "ingress.agc.dashboardBackend.name="), "needs ingress.agc.dashboardBackend.name"),
    (("--set", "ingress.agc.wafPolicies.hook="), "ingress.agc.wafPolicies.hook is empty"),
    (("--set", "ingress.agc.wafPolicies.api="), "ingress.agc.wafPolicies.api is empty"),
    (("--set", "ingress.agc.wafPolicies.protected="), "ingress.agc.wafPolicies.protected is empty"),
])
def test_agc_refuses(extra, message):
    assert message in render_error(*AGC, *extra)


def test_agc_refuses_no_certificate_source():
    assert "neither ingress.tls.clusterIssuer nor ingress.tls.secretName" in \
        render_error(*AGC, "--set", "ingress.tls.clusterIssuer=")


def test_agc_refuses_an_unrouted_connector_policy():
    assert "ingress.agc.wafPolicies.connector is empty" in \
        render_error(*ALL_ON, "--set", "ingress.agc.wafPolicies.connector=")


def test_a_policy_for_an_unrouted_role_is_not_required():
    render(*AGC, "--set", "ingress.dashboard.enabled=false", "--set", "ingress.agc.wafPolicies.protected=",
           "--set", "ingress.agc.dashboardBackend.name=")


def test_without_a_routed_dashboard_the_policy_can_be_acknowledged_away():
    render(*AGC, "--set", "ingress.dashboard.enabled=false", "--set", "networkPolicy.enabled=false",
           "--set", "networkPolicy.agcWithoutPolicyAcknowledged=true")
    assert "needs networkPolicy.enabled" in render_error(
        *AGC, "--set", "ingress.dashboard.enabled=false", "--set", "networkPolicy.enabled=false")


def test_the_proxy_health_check_is_named_for_the_release():
    checks = _kind(render(*AGC), "HealthCheckPolicy")
    proxy = checks[f"{FULL}-dashboard-proxy"]
    assert proxy["spec"]["targetRef"]["name"] == "oauth2-proxy"
    assert "oauth2-proxy" not in checks


def test_trusted_header_in_agc_mode_takes_the_proxy_as_its_peer():
    """The shipped policy's trusted_header mode needs the policy to admit the
    stripping proxy alone; in agc mode that is dashboardProxy."""
    assert render(*AGC, "--set", "networkPolicy.trustedHeaderWithoutPolicyAcknowledged=false")


def test_the_open_dashboard_refusal_holds_in_agc_mode():
    assert "dashboard.serveOpen serves every finding" in render_error(*AGC, "--set", "dashboard.serveOpen=true")


def test_the_host_collision_checks_hold_in_agc_mode():
    assert "repeats ingress.host" in render_error(*AGC, "--set", f"ingress.extraHosts={{{HOST}}}")


def test_an_unknown_mode_is_refused():
    assert "nginx, gke or agc" in render_error("--set", "ingress.mode=traefik")


def test_agc_with_classname_gce_is_refused():
    assert "selects GKE mode" in render_error(*AGC, "--set", "ingress.className=gce")


def test_classname_gce_alone_still_selects_gke():
    assert "ingress.gke.managedCertificate" in render_error("--set", "ingress.className=gce")


# --- network policy ------------------------------------------------------------

def _policies(docs: list[dict]) -> dict[str, list]:
    return {d["metadata"]["name"].removeprefix(f"{FULL}-"): d["spec"]["ingress"]
            for d in docs if d["kind"] == "NetworkPolicy"}


def test_the_agc_subnet_reaches_every_role_but_the_dashboard():
    policies = _policies(render(*ALL_ON))
    for role, ingress in policies.items():
        peers = ingress[0]["from"] if ingress else []
        cidrs = [p["ipBlock"]["cidr"] for p in peers if "ipBlock" in p]
        if role == "dashboard":
            assert cidrs == [], role
            [proxy] = peers
            assert proxy["podSelector"] == {"matchLabels": {"app.kubernetes.io/name": "oauth2-proxy"}}
            # The release's own namespace: an HTTPRoute's backend Service is in the route's.
            assert proxy["namespaceSelector"] == {"matchLabels": {"kubernetes.io/metadata.name": "default"}}
        else:
            assert cidrs == ["10.240.8.0/24"], role
            assert all("podSelector" not in p for p in peers), role


def test_agc_refuses_the_ingress_controller_selectors():
    assert "networkPolicy.ingressController does not apply in ingress.mode agc" in render_error(
        *AGC,
        "--set", "networkPolicy.ingressController.namespaceSelector.matchLabels.a=b",
        "--set", "networkPolicy.ingressController.podSelector.matchLabels.a=b")


def test_agc_policy_needs_the_subnet():
    assert "needs networkPolicy.agc.subnetCidr" in render_error(
        *AGC, "--set", "networkPolicy.agc.subnetCidr=")


def test_agc_policy_needs_the_proxy_when_the_dashboard_is_routed():
    assert "needs networkPolicy.agc.dashboardProxy.podSelector" in render_error(*AGC_NO_PROXY)


PROXY = "networkPolicy.agc.dashboardProxy.podSelector"
# AGC without its oauth2-proxy selector, for tests that set their own.
AGC_NO_PROXY = tuple(x for pair in zip(AGC[::2], AGC[1::2], strict=True) if not pair[1].startswith(PROXY) for x in pair)


@pytest.mark.parametrize("labels", [
    {"app\\.kubernetes\\.io/name": "forgd-verdict"},
    {"app\\.kubernetes\\.io/instance": "rel"},
    {"app\\.kubernetes\\.io/component": "verdict"},
    {"app\\.kubernetes\\.io/managed-by": "Helm"},
    {"app\\.kubernetes\\.io/name": "forgd-verdict", "app\\.kubernetes\\.io/component": "collector"},
])
def test_a_proxy_selector_that_matches_the_releases_own_pods_is_refused(labels):
    flags = [x for k, v in labels.items() for x in ("--set", f"{PROXY}.matchLabels.{k}={v}")]
    assert "selects this release's own pods" in render_error(*AGC_NO_PROXY, *flags)


def test_a_proxy_selector_built_from_pod_labels_is_refused():
    """podLabels go on every chart pod, so a selector made of them and the
    chart's labels matches the chart's pods."""
    assert "selects this release's own pods" in render_error(
        *AGC_NO_PROXY, "--set", "podLabels.proxy-peer=true",
        "--set", f"{PROXY}.matchLabels.app\\.kubernetes\\.io/name=forgd-verdict",
        "--set", f"{PROXY}.matchLabels.proxy-peer=true")


def test_a_proxy_selector_on_the_workload_identity_label_is_refused():
    assert "selects this release's own pods" in render_error(
        *AGC_NO_PROXY, "--set", f"{PROXY}.matchLabels.azure\\.workload\\.identity/use=true")


def test_a_proxy_selector_with_a_label_of_its_own_is_accepted():
    """Labels are ANDed, so one label the chart's pods lack is enough."""
    render(*AGC_NO_PROXY,
           "--set", f"{PROXY}.matchLabels.app\\.kubernetes\\.io/managed-by=Helm",
           "--set", f"{PROXY}.matchLabels.app\\.kubernetes\\.io/name=oauth2-proxy")


def test_a_proxy_selector_with_match_expressions_is_refused():
    assert "matchLabels only" in render_error(
        *AGC_NO_PROXY, "--set", f"{PROXY}.matchExpressions[0].key=app",
        "--set", f"{PROXY}.matchExpressions[0].operator=Exists")
