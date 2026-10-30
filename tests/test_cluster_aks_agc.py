"""cluster-aks with ingress = "agc": Application Gateway for Containers,
the ALB Controller's identity and grants, and the four WAF policies
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


def _exclusions(policy: dict) -> list[tuple[str, str, str]]:
    [managed] = policy["managed_rules"]
    return sorted((e["match_variable"], e["selector_match_operator"], e["selector"])
                  for e in managed.get("exclusion", []))


def test_the_protected_policy_skips_the_session_cookie_and_the_oidc_callback(tmp_path):
    """DRS 2.1 blocked a signed-in browser on oauth2-proxy's encrypted
    cookie: random bytes trip it on some sessions and not others."""
    policy = _one(_render(tmp_path, **AGC), "azurerm_web_application_firewall_policy.protected")
    assert _exclusions(policy) == [
        ("RequestArgNames", "Equals", "code"),
        ("RequestArgNames", "Equals", "state"),
        ("RequestCookieNames", "StartsWith", "_oauth2_proxy"),
    ]


def test_the_protected_policy_exclusions_follow_the_variables(tmp_path):
    policy = _one(_render(tmp_path, **AGC, protected_waf_excluded_cookies=["_sess"],
                          protected_waf_excluded_args=[]),
                  "azurerm_web_application_firewall_policy.protected")
    assert _exclusions(policy) == [("RequestCookieNames", "StartsWith", "_sess")]


def test_a_cookie_exclusion_must_be_a_cookie_name(tmp_path):
    _refused(tmp_path, "protected_waf_excluded_cookies holds cookie names",
             **AGC, protected_waf_excluded_cookies=["a b"])


@pytest.mark.parametrize("name", ["api", "connector", "hook"])
def test_api_connector_and_hook_end_in_an_allow_so_managed_rules_never_run(tmp_path, name):
    """With endpoint_waf_managed_rules off. The provider requires a managed
    rule set; a request a custom rule allows is not evaluated by it."""
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
    assert condition["match_variables"][0]["variable_name"] == "RequestUri"
    assert (condition["operator"], condition["match_values"]) == ("BeginsWith", ["/"])
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


ENDPOINTS = ("api", "connector", "hook")
WORKSPACE = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law"


@pytest.mark.parametrize("mode", ["Detection", "Prevention"])
def test_endpoint_managed_rules_drop_the_allow_and_inspect_bodies(tmp_path, mode):
    """With the final Allow gone, DRS evaluates every request the custom
    rules do not block, bodies included."""
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules=mode)
    for name in ENDPOINTS:
        policy = _one(rendered, f"azurerm_web_application_firewall_policy.{name}")
        [settings] = policy["policy_settings"]
        assert settings["mode"] == mode, name
        assert settings["request_body_check"] is True, name
        assert settings["request_body_enforcement"] is False, name
        assert settings["request_body_inspect_limit_in_kb"] == 2000, name
        [scrub] = settings["log_scrubbing"]
        assert scrub["enabled"] is True, name
        assert sorted(r["match_variable"] for r in scrub["rule"]) == sorted(
            ["RequestArgNames", "RequestPostArgNames", "RequestJSONArgNames",
             "RequestHeaderNames", "RequestCookieNames"]), name
        assert {r["selector_match_operator"] for r in scrub["rule"]} == {"EqualsAny"}, name
        assert "AllowRest" not in [r["name"] for r in _custom_rules(policy)], name
        assert _rule_sets(policy) == [("Microsoft_DefaultRuleSet", "2.1")], name
    protected = _one(rendered, "azurerm_web_application_firewall_policy.protected")
    assert protected["policy_settings"][0]["mode"] == "Prevention"


def test_endpoint_managed_rules_default_off_leaves_the_policies_as_they_were(tmp_path):
    rendered = _render(tmp_path, **AGC)
    for name in ENDPOINTS:
        policy = _one(rendered, f"azurerm_web_application_firewall_policy.{name}")
        [settings] = policy["policy_settings"]
        assert (settings["mode"], settings["request_body_check"],
                settings["request_body_inspect_limit_in_kb"]) == ("Prevention", False, 128), name
        assert not settings.get("log_scrubbing"), name
        assert not policy["managed_rules"][0].get("rule_group_override"), name
        assert _exclusions(policy) == [], name


def test_prevention_keeps_the_source_ranges_and_rate_limit_blocking(tmp_path):
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules="Prevention",
                       hook_source_ranges=["160.79.104.0/21"], api_rate_limit_per_minute=6000,
                       connector_source_ranges=["198.51.100.0/24"])
    hook = _custom_rules(_one(rendered, "azurerm_web_application_firewall_policy.hook"))
    assert [(r["name"], r["action"]) for r in hook] == [("HookSourceRanges", "Block"), ("RateLimit", "Block")]
    connector = _custom_rules(_one(rendered, "azurerm_web_application_firewall_policy.connector"))
    assert [(r["name"], r["action"]) for r in connector] == [("ConnectorSourceRanges", "Block")]


@pytest.mark.parametrize("extra", [{"hook_source_ranges": ["160.79.104.0/21"]},
                                   {"connector_source_ranges": ["198.51.100.0/24"]},
                                   {"api_rate_limit_per_minute": 6000}])
def test_detection_with_blocking_custom_rules_is_refused(tmp_path, extra):
    """Detection is policy-wide: the custom rules would only log."""
    _refused(tmp_path, "only log", **AGC, endpoint_waf_managed_rules="Detection", **extra)


def _modes(rendered) -> dict:
    return {name: _one(rendered, f"azurerm_web_application_firewall_policy.{name}")["policy_settings"][0]["mode"]
            for name in ENDPOINTS}


def test_endpoint_waf_modes_moves_one_policy_out_of_the_shared_mode(tmp_path):
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules="Detection",
                       endpoint_waf_modes={"hook": "Prevention"})
    assert _modes(rendered) == {"api": "Detection", "connector": "Detection", "hook": "Prevention"}
    for name in ENDPOINTS:
        policy = _one(rendered, f"azurerm_web_application_firewall_policy.{name}")
        assert policy["policy_settings"][0]["request_body_check"] is True, name
        assert "AllowRest" not in [r["name"] for r in _custom_rules(policy)], name


def test_endpoint_waf_modes_can_hold_one_policy_in_detection(tmp_path):
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules="Prevention",
                       endpoint_waf_modes={"connector": "Detection"})
    assert _modes(rendered) == {"api": "Prevention", "connector": "Detection", "hook": "Prevention"}


def test_a_policy_in_prevention_may_block_while_the_others_soak(tmp_path):
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules="Detection",
                       endpoint_waf_modes={"hook": "Prevention"}, hook_source_ranges=["160.79.104.0/21"])
    hook = _custom_rules(_one(rendered, "azurerm_web_application_firewall_policy.hook"))
    assert [(r["name"], r["action"]) for r in hook] == [("HookSourceRanges", "Block")]


@pytest.mark.parametrize("modes,extra", [
    ({"hook": "Prevention"}, {"connector_source_ranges": ["198.51.100.0/24"]}),
    ({"connector": "Prevention"}, {"hook_source_ranges": ["160.79.104.0/21"]}),
    ({"hook": "Prevention"}, {"api_rate_limit_per_minute": 6000}),
    ({"api": "Prevention"}, {"api_rate_limit_per_minute": 6000}),
])
def test_a_blocking_rule_on_a_policy_left_in_detection_is_refused(tmp_path, modes, extra):
    """The rate limit is on both the hook and api policies."""
    _refused(tmp_path, "only log", **AGC, endpoint_waf_managed_rules="Detection",
             endpoint_waf_modes=modes, **extra)


def test_the_rate_limit_blocks_with_hook_and_api_in_prevention(tmp_path):
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules="Detection",
                       endpoint_waf_modes={"hook": "Prevention", "api": "Prevention"},
                       api_rate_limit_per_minute=6000)
    for name in ("hook", "api"):
        rules = _custom_rules(_one(rendered, f"azurerm_web_application_firewall_policy.{name}"))
        assert ("RateLimit", "Block") in [(r["name"], r["action"]) for r in rules], name


@pytest.mark.parametrize("variables,match", [
    ({"endpoint_waf_managed_rules": "Detection", "endpoint_waf_modes": {"protected": "Prevention"}},
     "keyed hook, api or connector"),
    ({"endpoint_waf_managed_rules": "Detection", "endpoint_waf_modes": {"hook": "off"}},
     "values are"),
    ({"endpoint_waf_modes": {"hook": "Prevention"}}, "needs endpoint_waf_managed_rules on"),
])
def test_bad_endpoint_waf_modes_are_refused(tmp_path, variables, match):
    _refused(tmp_path, match, **AGC, **variables)


def test_an_unknown_endpoint_mode_is_refused(tmp_path):
    _refused(tmp_path, "endpoint_waf_managed_rules is", **AGC, endpoint_waf_managed_rules="on")


HOOK_ARGUMENTS = [("RequestArgKeys", "EqualsAny", "*"), ("RequestArgValues", "EqualsAny", "*")]


@pytest.mark.parametrize("mode", ["Detection", "Prevention"])
def test_with_managed_rules_the_hook_policy_skips_every_body_argument(tmp_path, mode):
    """Prompt text and the session_id key score over the threshold."""
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules=mode)
    assert _exclusions(_one(rendered, "azurerm_web_application_firewall_policy.hook")) == HOOK_ARGUMENTS
    for name in ("api", "connector"):
        assert _exclusions(_one(rendered, f"azurerm_web_application_firewall_policy.{name}")) == [], name


def test_a_hook_exclusion_the_module_already_makes_is_not_repeated(tmp_path):
    keys = {"match_variable": "RequestArgKeys", "selector": "*", "selector_match_operator": "EqualsAny"}
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules="Detection",
                       endpoint_waf_exclusions={"hook": [keys]})
    assert _exclusions(_one(rendered, "azurerm_web_application_firewall_policy.hook")) == HOOK_ARGUMENTS


def test_endpoint_exclusions_reach_only_their_policy(tmp_path):
    field = {"match_variable": "RequestHeaderNames", "selector": "x-trace", "selector_match_operator": "Equals"}
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules="Detection",
                       endpoint_waf_exclusions={"hook": [field]})
    hook = _one(rendered, "azurerm_web_application_firewall_policy.hook")
    assert _exclusions(hook) == [*HOOK_ARGUMENTS, ("RequestHeaderNames", "Equals", "x-trace")]
    for name in ("api", "connector"):
        assert _exclusions(_one(rendered, f"azurerm_web_application_firewall_policy.{name}")) == [], name


@pytest.mark.parametrize("exclusions,match", [
    ({"protected": []}, "keyed hook, api or connector"),
    ({"hook": [{"match_variable": "RequestBody", "selector": "x", "selector_match_operator": "Equals"}]},
     "match_variable"),
    ({"hook": [{"match_variable": "RequestArgNames", "selector": "x", "selector_match_operator": "Regex"}]},
     "selector_match_operator"),
    ({"hook": [{"match_variable": "RequestArgNames", "selector": "", "selector_match_operator": "Equals"}]},
     "a selector"),
    ({"hook": [{"match_variable": "RequestArgNames", "selector": "prompt", "selector_match_operator": "EqualsAny"}]},
     "EqualsAny"),
    ({"hook": [{"match_variable": "RequestArgNames", "selector": "*", "selector_match_operator": "Equals"}]},
     "EqualsAny"),
])
def test_a_malformed_endpoint_exclusion_is_refused(tmp_path, exclusions, match):
    _refused(tmp_path, match, **AGC, endpoint_waf_exclusions=exclusions)


def test_rule_overrides_reach_only_their_policy_grouped_by_rule_group(tmp_path):
    """920420 judges the content type, which no exclusion can skip."""
    overrides = {"api": [
        {"rule_group_name": "PROTOCOL-ENFORCEMENT", "rule_id": "920420", "action": "Log"},
        {"rule_group_name": "PROTOCOL-ENFORCEMENT", "rule_id": "920320", "action": "Disabled"},
        {"rule_group_name": "General", "rule_id": "200002", "action": "Log"},
    ]}
    rendered = _render(tmp_path, **AGC, endpoint_waf_managed_rules="Detection",
                       endpoint_waf_rule_overrides=overrides)
    [managed] = _one(rendered, "azurerm_web_application_firewall_policy.api")["managed_rules"]
    groups = {g["rule_group_name"]: sorted((r["id"], r["enabled"], r.get("action")) for r in g["rule"])
              for g in managed["managed_rule_set"][0]["rule_group_override"]}
    assert groups == {
        "PROTOCOL-ENFORCEMENT": [("920320", False, None), ("920420", True, "Log")],
        "General": [("200002", True, "Log")],
    }
    for name in ("hook", "connector"):
        [m] = _one(rendered, f"azurerm_web_application_firewall_policy.{name}")["managed_rules"]
        assert not m["managed_rule_set"][0].get("rule_group_override"), name


@pytest.mark.parametrize("overrides,match", [
    ({"protected": []}, "keyed hook, api or connector"),
    ({"api": [{"rule_group_name": "G", "rule_id": "920420", "action": "Allow"}]}, "an action of"),
    ({"api": [{"rule_group_name": "G", "rule_id": "abc", "action": "Log"}]}, "numeric rule_id"),
])
def test_a_malformed_rule_override_is_refused(tmp_path, overrides, match):
    _refused(tmp_path, match, **AGC, endpoint_waf_rule_overrides=overrides)


def test_agc_logs_go_to_the_workspace_when_one_is_given(tmp_path):
    assert not _present(_render(tmp_path, **AGC), "azurerm_monitor_diagnostic_setting.agc")
    setting = _one(_render(tmp_path, **AGC, agc_log_analytics_workspace_id=WORKSPACE),
                   "azurerm_monitor_diagnostic_setting.agc")
    assert setting["log_analytics_workspace_id"] == WORKSPACE
    assert setting["target_resource_id"].endswith("/trafficControllers/aks-agc")
    assert [log["category_group"] for log in setting["enabled_log"]] == ["allLogs"]


def test_no_agc_logs_without_agc(tmp_path):
    assert not _present(_render(tmp_path, agc_log_analytics_workspace_id=WORKSPACE),
                        "azurerm_monitor_diagnostic_setting.agc")


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


def test_no_custom_rule_pairs_remote_addr_with_the_any_operator(tmp_path):
    """Application Gateway refuses it ("does not support match variable
    'RemoteAddr'"): Any is for variables that take a selector. The lab's
    first apply failed on it in every policy that had one."""
    rendered = _render(tmp_path, **AGC, hook_source_ranges=["203.0.113.0/24"],
                       connector_source_ranges=["198.51.100.0/24"], api_rate_limit_per_minute=6000)
    for name in ("protected", "connector", "hook", "api"):
        for rule in _custom_rules(_one(rendered, f"azurerm_web_application_firewall_policy.{name}")):
            for condition in rule["match_conditions"]:
                variables = {v["variable_name"] for v in condition["match_variables"]}
                if condition["operator"] == "Any":
                    assert variables.isdisjoint({"RemoteAddr", "RequestMethod", "RequestUri"}), (name, rule["name"])
                if condition["operator"] == "IPMatch":
                    assert variables == {"RemoteAddr"}, (name, rule["name"])


def test_without_a_registry_there_is_no_pull_grant(tmp_path):
    """With grant_registry_pull = true and a registry made in the same apply,
    test_cluster_aks_plan_time.py plans the grant with the id unknown."""
    assert not _present(_render(tmp_path, **AGC), "azurerm_role_assignment.kubelet_pulls_images")
