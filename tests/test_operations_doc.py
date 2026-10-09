"""docs/OPERATIONS.md says how a policy change reaches each target."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEXT = " ".join((REPO / "docs" / "OPERATIONS.md").read_text(encoding="utf-8").split())
SECTION = TEXT[TEXT.find("## Change the policy"):]


def test_there_is_a_section_on_changing_the_policy():
    assert "## Change the policy" in TEXT


def test_the_helm_path_names_the_flag_the_deploy_scripts_leave_out():
    for script in ("deploy_aws.sh", "deploy_gcp.sh"):
        text = (REPO / "scripts" / script).read_text(encoding="utf-8")
        assert "--reset-then-reuse-values" in text and "policy.inline" not in text, script
    assert "--set-file policy.inline" in SECTION


def test_the_terraform_path_names_the_module_variable():
    for module in ("app-aca", "app-cloudrun", "app-ecs"):
        variables = (REPO / "deploy" / "terraform" / "modules" / module / "variables.tf").read_text()
        assert 'variable "policy_yaml"' in variables, module
        assert f"`{module}`" in SECTION, module
    assert "`policy_yaml`" in SECTION and "terraform apply" in SECTION
