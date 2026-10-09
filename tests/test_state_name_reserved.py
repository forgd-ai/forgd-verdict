"""A state key derived from configuration may not be a name the store
reserves for its own objects: the runtime overrides object, the org
registries, the lockout reports, or a Managed Agents cursor."""

from __future__ import annotations

import pytest

from forgd_verdict.lockout import report_name
from forgd_verdict.models import CONTROL_STATE, config_state_name, safe_state_name
from forgd_verdict.orgregistry import REGISTRY_STATE_NAMES
from forgd_verdict.policy import Policy, PolicyInvalid

RESERVED = [CONTROL_STATE, *REGISTRY_STATE_NAMES.values(),
            *(report_name(r) for r in ("verdict", "collector", "intake", "ingest", "dashboard")),
            "managed-support.json"]


@pytest.mark.parametrize("name", RESERVED)
def test_a_reserved_name_is_refused(name):
    with pytest.raises(ValueError):
        config_state_name(name)


@pytest.mark.parametrize("name", ["compliance-state.json", "compliance-state-0123456789.json",
                                  "prod-cursor.json"])
def test_an_ordinary_name_is_accepted(name):
    assert config_state_name(name) == name


@pytest.mark.parametrize("name", ["RUNTIME-OVERRIDES.JSON", "runtime-overrides.json ",
                                  "Org-Registry-Verdict.json"])
def test_case_and_padding_do_not_get_round_the_check(name):
    with pytest.raises(ValueError):
        config_state_name(name)


def test_the_flat_key_rules_still_apply():
    for name in ("../x.json", "a/b.json", ".hidden"):
        with pytest.raises(ValueError):
            config_state_name(name)
    assert safe_state_name(CONTROL_STATE) == CONTROL_STATE  # system writers still use it


@pytest.mark.parametrize("state_path", [
    "./runtime-overrides.json", "runtime-overrides.json", "/tmp/x/runtime-overrides.json",
    "./org-registry-intake.json", "./overrides-lockout-ingest.json", "./managed-ws1.json",
])
def test_a_compliance_state_path_naming_a_reserved_object_refuses_to_load(state_path):
    multi = Policy(raw={"privacy": {"allow_unsalted": True}, "compliance": {"orgs": [
        {"id": "org-synthetic", "api_key": "sk-ant-api01-" + "x" * 40,
         "state_path": state_path}]}})
    with pytest.raises(PolicyInvalid, match="state_path"):
        multi.compliance_orgs()
    with pytest.raises(PolicyInvalid, match="state_path"):
        multi.compliance_state_keys()
    single = Policy(raw={"privacy": {"allow_unsalted": True}, "compliance": {
        "api_key": "sk-ant-api01-" + "x" * 40, "state_path": state_path}})
    with pytest.raises(PolicyInvalid, match="state_path"):
        single.compliance_orgs()
