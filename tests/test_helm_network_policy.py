"""The chart's NetworkPolicy, and the trusted_header guard that needs it.

Under trusted_header the dashboard believes a header the proxy in front
sets. A pod in the cluster can skip the proxy and send that header straight
to the dashboard Service, so the chart refuses trusted_header unless a
NetworkPolicy admits only the ingress controller, or the deployment
acknowledges that something else does.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from test_helm_admins import CONNECTOR, OIDC
from test_helm_chart import (
    INTAKE,
    by_kind,
    render,
    render_error,
    render_error_without,
    requires_helm,
)

pytestmark = requires_helm

CHART = Path(__file__).resolve().parent.parent / "deploy" / "helm"
README = CHART / "README.md"
VALUES = CHART / "forgd-verdict" / "values.yaml"
FULL = "rel-forgd-verdict"
ACK = "networkPolicy.trustedHeaderWithoutPolicyAcknowledged"
WITHOUT_ACK = ("--set", f"{ACK}=false")
NAMESPACE = {"matchLabels": {"kubernetes.io/metadata.name": "app-routing-system"}}
PODS = {"matchLabels": {"app": "nginx"}}
ENABLED = (
    "--set", "networkPolicy.enabled=true",
    "--set", "networkPolicy.ingressController.namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name=app-routing-system",
    "--set", "networkPolicy.ingressController.podSelector.matchLabels.app=nginx",
)
STRIPPED = "dashboard.trustedHeaderStrippedBy"


def _policies(docs) -> dict[str, dict]:
    return by_kind(docs, "NetworkPolicy")


def test_trusted_header_without_a_policy_or_the_acknowledgement_is_refused():
    err = render_error_without(ACK)
    assert "trusted_header" in err and "networkPolicy.enabled" in err and ACK in err, err


def test_the_refusal_says_the_cni_must_enforce_the_policy():
    """On EKS the default VPC CNI accepts a NetworkPolicy and enforces none
    of it, so networkPolicy.enabled alone would satisfy the guard."""
    err = render_error_without(ACK)
    assert "enforce" in err and "enableNetworkPolicy" in err and "cluster-eks" in err, err


@pytest.mark.parametrize("path", [README, VALUES], ids=["README", "values.yaml"])
def test_the_chart_docs_say_eks_enforces_only_with_enable_network_policy(path):
    text = " ".join(path.read_text(encoding="utf-8").split())
    assert "enableNetworkPolicy" in text and "cluster-eks" in text, path


def test_trusted_header_renders_with_the_acknowledgement_and_no_policy():
    docs = render()
    assert _policies(docs) == {}


def test_trusted_header_renders_with_the_policy_enabled():
    docs = render(*WITHOUT_ACK, *ENABLED)
    assert f"{FULL}-dashboard" in _policies(docs)


def test_oidc_jwt_needs_neither():
    docs = render(*WITHOUT_ACK, "--set", f"{STRIPPED}=", *OIDC)
    assert _policies(docs) == {}


@pytest.mark.parametrize("extra,roles", [
    ((), {"verdict", "collector", "dashboard"}),
    ((*INTAKE, *CONNECTOR), {"verdict", "collector", "dashboard", "intake", "connector"}),
    (("--set", "collector.enabled=false", "--set", "dashboard.enabled=false"), {"verdict"}),
], ids=["default", "intake-connector", "verdict-only"])
def test_each_served_role_admits_only_the_ingress_controller_on_its_port(extra, roles):
    docs = render(*ENABLED, *extra)
    policies = _policies(docs)
    assert set(policies) == {f"{FULL}-{r}" for r in roles}
    services = by_kind(docs, "Service")
    for role in roles:
        spec = policies[f"{FULL}-{role}"]["spec"]
        assert spec["podSelector"] == {"matchLabels": services[f"{FULL}-{role}"]["spec"]["selector"]}
        assert spec["policyTypes"] == ["Ingress"]
        [rule] = spec["ingress"]
        assert rule["from"] == [{"namespaceSelector": NAMESPACE, "podSelector": PODS}]
        assert rule["ports"] == [{"port": "http", "protocol": "TCP"}]


EXTRA = ("--set", "networkPolicy.extraFrom[0].ipBlock.cidr=10.20.0.0/16")
DASHBOARD_EXTRA = ("--set", "networkPolicy.dashboardExtraFrom[0].ipBlock.cidr=10.30.0.0/16")
EXTRA_ACK = "networkPolicy.dashboardExtraFromTrustedAcknowledged"
CONTROLLER = {"namespaceSelector": NAMESPACE, "podSelector": PODS}
ALL_ROLES = {"verdict", "collector", "dashboard", "intake", "connector"}


def test_extra_peers_are_admitted_alongside_the_controller():
    docs = render(*ENABLED, *EXTRA)
    [rule] = _policies(docs)[f"{FULL}-verdict"]["spec"]["ingress"]
    assert rule["from"] == [CONTROLLER, {"ipBlock": {"cidr": "10.20.0.0/16"}}]


def test_extra_peers_alone_are_enough():
    docs = render(*WITHOUT_ACK, "--set", f"{STRIPPED}=", *OIDC,
                  "--set", "networkPolicy.enabled=true", *EXTRA)
    [rule] = _policies(docs)[f"{FULL}-verdict"]["spec"]["ingress"]
    assert rule["from"] == [{"ipBlock": {"cidr": "10.20.0.0/16"}}]


def test_extra_peers_reach_every_role_but_the_dashboard():
    policies = _policies(render(*ENABLED, *INTAKE, *CONNECTOR, *EXTRA))
    assert set(policies) == {f"{FULL}-{r}" for r in ALL_ROLES}
    for role in ALL_ROLES - {"dashboard"}:
        [rule] = policies[f"{FULL}-{role}"]["spec"]["ingress"]
        assert rule["from"] == [CONTROLLER, {"ipBlock": {"cidr": "10.20.0.0/16"}}], role
    [rule] = policies[f"{FULL}-dashboard"]["spec"]["ingress"]
    assert rule["from"] == [CONTROLLER]


def test_dashboard_extra_peers_reach_only_the_dashboard():
    policies = _policies(render(*WITHOUT_ACK, "--set", f"{STRIPPED}=", *OIDC,
                                *ENABLED, *INTAKE, *CONNECTOR, *DASHBOARD_EXTRA))
    [rule] = policies[f"{FULL}-dashboard"]["spec"]["ingress"]
    assert rule["from"] == [CONTROLLER, {"ipBlock": {"cidr": "10.30.0.0/16"}}]
    for role in ALL_ROLES - {"dashboard"}:
        [rule] = policies[f"{FULL}-{role}"]["spec"]["ingress"]
        assert rule["from"] == [CONTROLLER], role


def test_a_dashboard_with_no_peers_admits_nothing():
    """A rule with no `from` admits every source, so the dashboard gets no
    rule at all."""
    docs = render(*WITHOUT_ACK, "--set", f"{STRIPPED}=", *OIDC,
                  "--set", "networkPolicy.enabled=true", *EXTRA)
    spec = _policies(docs)[f"{FULL}-dashboard"]["spec"]
    assert spec["policyTypes"] == ["Ingress"]
    assert spec["ingress"] == []


@pytest.mark.parametrize("ack", ["false", "true"], ids=["unacknowledged", "acknowledged"])
def test_trusted_header_with_only_extra_peers_is_refused(ack):
    err = render_error("--set", f"{ACK}={ack}", "--set", "networkPolicy.enabled=true",
                       "--set", "networkPolicy.extraFrom[0].ipBlock.cidr=10.0.0.0/8")
    assert "trusted_header" in err and "ingressController" in err, err
    assert "dashboardExtraFrom" in err, err


def test_trusted_header_refuses_dashboard_extra_peers_without_the_acknowledgement():
    """A peer in dashboardExtraFrom reaches the dashboard without passing
    the proxy that strips the header, so it can set it as any user."""
    err = render_error(*WITHOUT_ACK, *ENABLED, *DASHBOARD_EXTRA)
    assert "trusted_header" in err and "networkPolicy.dashboardExtraFrom" in err, err
    assert EXTRA_ACK in err and "any user" in err, err


@pytest.mark.parametrize("ack", ["false", "true"], ids=["policy-ack-off", "policy-ack-on"])
def test_the_policy_acknowledgement_does_not_stand_in_for_the_peers_one(ack):
    err = render_error("--set", f"{ACK}={ack}", *ENABLED, *DASHBOARD_EXTRA)
    assert EXTRA_ACK in err, err


def test_trusted_header_admits_acknowledged_dashboard_extra_peers_beside_the_controller():
    docs = render(*WITHOUT_ACK, *ENABLED, *DASHBOARD_EXTRA, "--set", f"{EXTRA_ACK}=true")
    [rule] = _policies(docs)[f"{FULL}-dashboard"]["spec"]["ingress"]
    assert rule["from"] == [CONTROLLER, {"ipBlock": {"cidr": "10.30.0.0/16"}}]


def test_oidc_jwt_admits_dashboard_extra_peers_without_the_acknowledgement():
    docs = render(*WITHOUT_ACK, "--set", f"{STRIPPED}=", *OIDC, *ENABLED, *DASHBOARD_EXTRA)
    [rule] = _policies(docs)[f"{FULL}-dashboard"]["spec"]["ingress"]
    assert rule["from"] == [CONTROLLER, {"ipBlock": {"cidr": "10.30.0.0/16"}}]


def test_trusted_header_without_a_policy_ignores_dashboard_extra_peers():
    """With networkPolicy off nothing renders the peers, and
    trustedHeaderWithoutPolicyAcknowledged already covers the dashboard."""
    assert _policies(render(*DASHBOARD_EXTRA)) == {}


@pytest.mark.parametrize("extra", [
    ("--set", "networkPolicy.enabled=true"),
    ("--set", "networkPolicy.enabled=true",
     "--set", "networkPolicy.ingressController.podSelector.matchLabels.app=nginx"),
    ("--set", "networkPolicy.enabled=true",
     "--set", "networkPolicy.ingressController.namespaceSelector.matchLabels.team=ingress"),
], ids=["nothing", "pods-only", "namespace-only"])
def test_an_enabled_policy_must_name_whom_it_admits(extra):
    err = render_error(*extra)
    assert "networkPolicy" in err and "ingressController" in err, err


ADMIN_CLAIM = re.compile(r"an admin included|including an admin", re.I)


@pytest.mark.parametrize("extra", [(), (*ENABLED, *DASHBOARD_EXTRA)],
                         ids=["no-policy", "dashboard-extra-from"])
def test_a_trusted_header_refusal_claims_no_admin(extra):
    """The chart refuses dashboard.admins.enabled unless the mode is
    oidc_jwt, so no admin exists under trusted_header."""
    err = render_error(*extra) if extra else render_error_without(ACK)
    assert "trusted_header" in err, err
    assert not ADMIN_CLAIM.search(err), err


def test_the_readme_claims_no_admin_under_trusted_header():
    assert not ADMIN_CLAIM.findall(README.read_text(encoding="utf-8"))
