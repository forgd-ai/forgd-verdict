"""cluster-aks with ingress = "agc": Application Gateway for Containers,
the ALB Controller's identity and grants, and the three WAF policies
(docs/design/agc.md).

Rendered with a mocked azurerm provider; nothing reaches a cloud.
"""

from __future__ import annotations

import shutil

import pytest
from terraform_render import RG, _azure, module, plugin_dir, render_once

terraform = shutil.which("terraform")
pytestmark = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

AKS = module("cluster-aks")
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
NODES = f"{SUB}/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet-nodes"
AGC_SUBNET = f"{SUB}/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet-agc"
NODE_GROUP = f"{SUB}/resourceGroups/rg-aks-nodes"
REQUIRED = {
    "resource_group_name": "rg", "location": "centralus", "cluster_name": "aks",
    "writer_identity_id": f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/writer",
    "reader_identity_id": f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/reader",
    "writer_service_account": "forgd-verdict-writer",
    "reader_service_account": "forgd-verdict-reader",
    "allow_unrestricted_public_api_server": True,
}
AGC = {"ingress": "agc", "vnet_subnet_id": NODES, "agc_subnet_id": AGC_SUBNET}
ALB_CONTROLLER = "66666666-0000-0000-0000-000000000000"


def _overrides(block: str, kind: str, name: str) -> dict:
    if kind == "azurerm_kubernetes_cluster":
        return {"oidc_issuer_url": "https://issuer.example/", "node_resource_group_id": NODE_GROUP,
                "kubelet_identity": [{"object_id": "00000000-0000-0000-0000-000000000009",
                                      "client_id": "", "user_assigned_identity_id": ""}]}
    if kind == "azurerm_user_assigned_identity" and name == "alb_controller":
        return {"id": f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/alb",
                "principal_id": ALB_CONTROLLER, "client_id": "66666666-1111-1111-1111-111111111111",
                "tenant_id": "00000000-0000-0000-0000-000000000000"}
    if kind == "azurerm_application_load_balancer":
        return {"id": f"{RG}/providers/Microsoft.ServiceNetworking/trafficControllers/aks-agc"}
    if kind == "azurerm_web_application_firewall_policy":
        return {"id": f"{RG}/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/{name}"}
    return _azure(block, kind, name)


def _render(tmp_path, **variables) -> dict:
    return render_once(tmp_path / "cluster-aks", AKS, {**REQUIRED, **variables},
                       providers=["azurerm"], mock_data={}, overrides=_overrides,
                       plugins=plugin_dir(AKS))


def _refused(tmp_path, match: str, **variables) -> None:
    with pytest.raises(AssertionError, match=match):
        _render(tmp_path, **variables)


def _one(rendered: dict, address: str) -> dict:
    """The single instance of a counted resource."""
    [instance] = rendered[address]
    return instance


def _present(rendered: dict, address: str) -> bool:
    return bool(rendered.get(address))


def _custom_rules(policy: dict) -> list[dict]:
    return sorted(policy.get("custom_rules") or [], key=lambda r: r["priority"])


def _rule_sets(policy: dict) -> list[tuple[str, str]]:
    [managed] = policy["managed_rules"]
    return [(s["type"], s["version"]) for s in managed["managed_rule_set"]]


def test_the_default_is_still_the_app_routing_add_on_and_no_agc(tmp_path):
    rendered = _render(tmp_path)
    assert rendered["azurerm_kubernetes_cluster.this"]["web_app_routing"]
    agc = [k for k in rendered if k.startswith(("azurerm_application_load_balancer", "azurerm_web_application_firewall_policy"))]
    assert agc and not any(_present(rendered, k) for k in agc), agc


def test_app_routing_enabled_false_still_means_no_add_on(tmp_path):
    rendered = _render(tmp_path, app_routing_enabled=False)
    assert not rendered["azurerm_kubernetes_cluster.this"].get("web_app_routing")


def test_agc_replaces_the_add_on_with_agc_on_the_given_subnet(tmp_path):
    rendered = _render(tmp_path, **AGC)
    assert not rendered["azurerm_kubernetes_cluster.this"].get("web_app_routing")
    assert _one(rendered, "azurerm_application_load_balancer.this")
    assert _one(rendered, "azurerm_application_load_balancer_frontend.this")
    assert _one(rendered, "azurerm_application_load_balancer_subnet_association.this")["subnet_id"] == AGC_SUBNET


def test_the_controller_federates_to_its_service_account(tmp_path):
    rendered = _render(tmp_path, **AGC)
    credential = _one(rendered, "azurerm_federated_identity_credential.alb_controller")
    assert credential["subject"] == "system:serviceaccount:azure-alb-system:alb-controller-sa"
    assert credential["issuer"] == "https://issuer.example/"


def test_the_controller_gets_exactly_the_three_documented_grants(tmp_path):
    rendered = _render(tmp_path, **AGC)
    grants = {(r["role_definition_name"], r["scope"]) for k, v in rendered.items()
              if k.startswith("azurerm_role_assignment.") for r in (v if isinstance(v, list) else [v])
              if r["principal_id"] == ALB_CONTROLLER}
    assert grants == {
        ("AppGw for Containers Configuration Manager", RG),
        ("Network Contributor", AGC_SUBNET),
        ("Reader", NODE_GROUP),
    }


def test_the_node_reader_grant_can_be_left_to_someone_else(tmp_path):
    rendered = _render(tmp_path, **AGC, grant_alb_controller_node_reader=False)
    assert not _present(rendered, "azurerm_role_assignment.alb_controller_reads_nodes")
    assert _present(rendered, "azurerm_role_assignment.alb_controller_configures_agc")


def test_the_protected_policy_runs_drs_and_bot_manager_on_bodies(tmp_path):
    policy = _one(_render(tmp_path, **AGC), "azurerm_web_application_firewall_policy.protected")
    [settings] = policy["policy_settings"]
    assert settings["mode"] == "Prevention" and settings["request_body_check"] is True
    assert _rule_sets(policy) == [("Microsoft_DefaultRuleSet", "2.1"), ("Microsoft_BotManagerRuleSet", "1.1")]
    assert _custom_rules(policy) == []


@pytest.mark.parametrize("name", ["api", "connector", "hook"])
def test_api_connector_and_hook_end_in_an_allow_so_managed_rules_never_run(tmp_path, name):
    """The provider requires a managed rule set; a request a custom rule
    allows is not evaluated by it. Without the final Allow, DRS would read
    prompt text and telemetry, or answer the connector before its 401."""
    variables = {**AGC, "hook_source_ranges": ["203.0.113.0/24"], "api_rate_limit_per_minute": 6000,
                 "connector_source_ranges": ["198.51.100.0/24"]}
    policy = _one(_render(tmp_path, **variables), f"azurerm_web_application_firewall_policy.{name}")
    [settings] = policy["policy_settings"]
    assert settings["mode"] == "Prevention"
    assert settings["request_body_check"] is False and settings["request_body_enforcement"] is False
    rules = _custom_rules(policy)
    last = rules[-1]
    assert (last["action"], last["rule_type"]) == ("Allow", "MatchRule")
    [condition] = last["match_conditions"]
    assert condition["operator"] == "Any"
    assert all(r["action"] != "Allow" for r in rules[:-1])


def test_with_no_ranges_or_limit_api_connector_and_hook_allow_everything(tmp_path):
    rendered = _render(tmp_path, **AGC)
    for name in ("api", "connector", "hook"):
        rules = _custom_rules(_one(rendered, f"azurerm_web_application_firewall_policy.{name}"))
        assert [r["name"] for r in rules] == ["AllowRest"], name


def test_hook_source_ranges_cover_the_whole_hook_policy_and_nothing_else(tmp_path):
    """The hook route has a policy of its own, so the rule matches no path:
    whatever the Gateway routes to /hook is what the ranges apply to."""
    ranges = ["203.0.113.0/24"]
    rendered = _render(tmp_path, **AGC, hook_source_ranges=ranges)
    block = _custom_rules(_one(rendered, "azurerm_web_application_firewall_policy.hook"))[0]
    assert (block["name"], block["action"]) == ("HookSourceRanges", "Block")
    [condition] = block["match_conditions"]
    assert condition["match_variables"][0]["variable_name"] == "RemoteAddr"
    assert condition["operator"] == "IPMatch"
    assert condition["negation_condition"] is True
    assert condition["match_values"] == ranges
    for name in ("api", "connector", "protected"):
        rules = _custom_rules(_one(rendered, f"azurerm_web_application_firewall_policy.{name}"))
        assert "HookSourceRanges" not in [r["name"] for r in rules], name


def test_every_rule_on_keeps_blocks_before_the_allow(tmp_path):
    rendered = _render(tmp_path, **AGC, hook_source_ranges=["203.0.113.0/24"], api_rate_limit_per_minute=6000)
    hook = _custom_rules(_one(rendered, "azurerm_web_application_firewall_policy.hook"))
    assert [(r["name"], r["priority"], r["action"]) for r in hook] == [
        ("HookSourceRanges", 10, "Block"), ("RateLimit", 20, "Block"), ("AllowRest", 100, "Allow")]
    api = _custom_rules(_one(rendered, "azurerm_web_application_firewall_policy.api"))
    assert [(r["name"], r["priority"], r["action"]) for r in api] == [
        ("RateLimit", 20, "Block"), ("AllowRest", 100, "Allow")]


def test_connector_source_ranges_block_other_addresses(tmp_path):
    ranges = ["198.51.100.0/24"]
    policy = _one(_render(tmp_path, **AGC, connector_source_ranges=ranges),
                  "azurerm_web_application_firewall_policy.connector")
    block = _custom_rules(policy)[0]
    assert (block["name"], block["action"]) == ("ConnectorSourceRanges", "Block")
    [condition] = block["match_conditions"]
    assert condition["negation_condition"] is True and condition["match_values"] == ranges


@pytest.mark.parametrize("name", ["api", "hook"])
def test_the_rate_limit_is_off_unless_set(tmp_path, name):
    names = [r["name"] for r in _custom_rules(
        _one(_render(tmp_path, **AGC), f"azurerm_web_application_firewall_policy.{name}"))]
    assert "RateLimit" not in names
    rules = _custom_rules(_one(_render(tmp_path, **AGC, api_rate_limit_per_minute=6000),
                               f"azurerm_web_application_firewall_policy.{name}"))
    [limit] = [r for r in rules if r["name"] == "RateLimit"]
    assert (limit["rule_type"], limit["rate_limit_threshold"], limit["group_rate_limit_by"]) == \
        ("RateLimitRule", 6000, "ClientAddr")


def test_each_waf_policy_has_a_security_policy_on_the_agc(tmp_path):
    rendered = _render(tmp_path, **AGC)
    policies = rendered["azurerm_application_load_balancer_security_policy.waf"]
    assert sorted(policies) == ["api", "connector", "hook", "protected"]
    for name, policy in policies.items():
        assert policy["web_application_firewall_policy_id"].endswith(f"/{name}"), name


def test_agc_needs_both_subnets(tmp_path):
    _refused(tmp_path, "needs vnet_subnet_id and agc_subnet_id", ingress="agc", vnet_subnet_id=NODES)


def test_an_agc_subnet_without_agc_is_refused(tmp_path):
    _refused(tmp_path, "agc_subnet_id is only for", agc_subnet_id=AGC_SUBNET)


def test_ingress_and_app_routing_enabled_together_are_refused(tmp_path):
    _refused(tmp_path, "not app_routing_enabled as well", ingress="app_routing", app_routing_enabled=True)


@pytest.mark.parametrize("version", ["1.31", "1.31.4"])
def test_agc_refuses_kubernetes_older_than_1_32(tmp_path, version):
    _refused(tmp_path, "1.32 or later", **AGC, kubernetes_version=version)


@pytest.mark.parametrize("version", ["1.x", "1.32.foo", "2.0", "v1.35"])
def test_a_malformed_kubernetes_version_is_refused(tmp_path, version):
    _refused(tmp_path, "kubernetes_version is MAJOR.MINOR", kubernetes_version=version)


def test_the_nodes_subnet_as_the_agc_subnet_is_refused(tmp_path):
    _refused(tmp_path, "agc_subnet_id is the nodes' subnet", ingress="agc", vnet_subnet_id=NODES,
             agc_subnet_id=NODES)


def test_an_agc_subnet_that_is_not_a_subnet_id_is_refused(tmp_path):
    _refused(tmp_path, "agc_subnet_id must be a subnet's resource id", **{**AGC, "agc_subnet_id": "snet-agc"})


@pytest.mark.parametrize("version", ["1.32", "1.35.7"])
def test_agc_accepts_kubernetes_1_32_and_later(tmp_path, version):
    assert _render(tmp_path, **AGC, kubernetes_version=version)["azurerm_kubernetes_cluster.this"]


def test_the_node_resource_group_name_reaches_the_cluster(tmp_path):
    cluster = _render(tmp_path, **AGC, node_resource_group="rg-aks-nodes")["azurerm_kubernetes_cluster.this"]
    assert cluster["node_resource_group"] == "rg-aks-nodes"
