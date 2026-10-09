"""cluster-aks's API server: private by default, never open to every address
without saying so, and reached through Entra rather than local accounts.

The renders are of examples/aks, so they also check that the example passes
each setting through to the module.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import terraform_render as tr
import test_cluster_connector as conn

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

STACK_REQUIRED = {
    "subscription_id": "00000000-0000-0000-0000-000000000000",
    "resource_group_name": "rg-aks",
    "storage_account_name": "forgdfindingsaks",
}
PUBLIC_UNRESTRICTED = "admits every address"
PRIVATE_WITH_RANGES = "applies only to a public API server"
WORLD_OPEN = "may not contain a /0"


def _cluster(tmp_path: Path, **variables) -> dict:
    rendered = tr.render_aks_stack_once(tmp_path, {**STACK_REQUIRED, **variables})
    return rendered["module.cluster"]["render"]["azurerm_kubernetes_cluster.this"]


def _refusal(tmp_path: Path, **variables) -> str:
    with pytest.raises(tr.StackRefused) as refused:
        _cluster(tmp_path, **variables)
    return " ".join(str(refused.value).split())


def _module_variables(tmp_path: Path, **variables) -> subprocess.CompletedProcess:
    """`terraform apply` of cluster-aks's variables.tf alone, which runs its
    validations and nothing else."""
    shutil.copy(conn.AKS / "variables.tf", tmp_path / "variables.tf")
    (tmp_path / "terraform.tfvars.json").write_text(
        json.dumps({**conn.AKS_REQUIRED, **variables}), encoding="utf-8")
    out = subprocess.run([terraform, f"-chdir={tmp_path}", "init", "-input=false", "-no-color"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return subprocess.run([terraform, f"-chdir={tmp_path}", "apply", "-auto-approve", "-input=false", "-no-color"],
                          capture_output=True, text=True, timeout=120)


@requires_terraform
def test_the_defaults_render_the_standard_tier(tmp_path):
    """Free has no financially backed uptime SLA on the API server, and the
    API server is what every governed prompt's hook call depends on."""
    assert _cluster(tmp_path)["sku_tier"] == "Standard"


def test_the_example_and_the_module_default_to_the_same_tier():
    pattern = r'variable "sku_tier" \{[^}]*?default\s*=\s*"(\w+)"'
    module = re.findall(pattern, (conn.AKS / "variables.tf").read_text(encoding="utf-8"))
    example = re.findall(pattern, (tr.TERRAFORM / "examples" / "aks" / "variables.tf").read_text(encoding="utf-8"))
    assert module == example == ["Standard"], (module, example)


@requires_terraform
def test_the_example_passes_the_tier_through(tmp_path):
    assert _cluster(tmp_path, sku_tier="Free")["sku_tier"] == "Free"


@requires_terraform
def test_the_defaults_render_a_private_cluster_with_no_local_accounts(tmp_path):
    cluster = _cluster(tmp_path)
    assert cluster["private_cluster_enabled"] is True
    assert cluster["api_server_access_profile"] == []
    assert cluster["local_account_disabled"] is True
    [entra] = cluster["azure_active_directory_role_based_access_control"]
    assert entra["azure_rbac_enabled"] is True
    assert entra["admin_group_object_ids"] == []


@requires_terraform
def test_listed_entra_admin_groups_reach_the_cluster(tmp_path):
    group = "00000000-0000-0000-0000-00000000000a"
    cluster = _cluster(tmp_path, entra_admin_group_object_ids=[group])
    [entra] = cluster["azure_active_directory_role_based_access_control"]
    assert entra["admin_group_object_ids"] == [group]


@requires_terraform
def test_local_accounts_left_on_render_no_entra_block(tmp_path):
    cluster = _cluster(tmp_path, local_account_disabled=False)
    assert cluster["local_account_disabled"] is False
    assert cluster["azure_active_directory_role_based_access_control"] == []


@requires_terraform
def test_a_public_api_server_with_no_ranges_is_refused_at_plan_time(tmp_path):
    assert PUBLIC_UNRESTRICTED in _refusal(tmp_path, private_cluster_enabled=False)


@requires_terraform
def test_a_public_api_server_with_no_ranges_renders_once_acknowledged(tmp_path):
    cluster = _cluster(tmp_path, private_cluster_enabled=False, allow_unrestricted_public_api_server=True)
    assert cluster["private_cluster_enabled"] is False
    assert cluster["api_server_access_profile"] == []


@requires_terraform
def test_a_public_api_server_admits_only_the_listed_ranges(tmp_path):
    ranges = ["203.0.113.0/24", "198.51.100.7/32"]
    cluster = _cluster(tmp_path, private_cluster_enabled=False, api_server_authorized_ip_ranges=ranges)
    assert cluster["private_cluster_enabled"] is False
    [profile] = cluster["api_server_access_profile"]
    assert sorted(profile["authorized_ip_ranges"]) == sorted(ranges)


@requires_terraform
def test_a_private_cluster_takes_no_authorized_ranges(tmp_path):
    assert PRIVATE_WITH_RANGES in _refusal(tmp_path, api_server_authorized_ip_ranges=["203.0.113.0/24"])


@requires_terraform
@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0", "10.0.0.0/0", "0::0/0"])
def test_an_authorized_range_cannot_be_every_address(tmp_path, cidr):
    out = _module_variables(tmp_path, api_server_authorized_ip_ranges=["203.0.113.0/24", cidr])
    assert out.returncode != 0
    assert WORLD_OPEN in " ".join(out.stderr.split()), out.stderr


@requires_terraform
def test_an_authorized_range_must_be_a_cidr(tmp_path):
    out = _module_variables(tmp_path, api_server_authorized_ip_ranges=["203.0.113.7"])
    assert out.returncode != 0
    assert "must be a CIDR block" in " ".join(out.stderr.split()), out.stderr


@requires_terraform
def test_listed_ranges_pass_the_variable_checks(tmp_path):
    """The /0 check refuses only a /0."""
    out = _module_variables(tmp_path, api_server_authorized_ip_ranges=["203.0.113.0/24", "198.51.100.7/32"])
    assert out.returncode == 0, out.stderr


# --- reaching a private cluster ------------------------------------------

TF_README = Path(__file__).resolve().parent.parent / "deploy" / "terraform" / "README.md"
AKS_MAIN = Path(__file__).resolve().parent.parent / "deploy" / "terraform" / "modules" / "cluster-aks" / "main.tf"


def _reaching_the_aks_api() -> str:
    text = TF_README.read_text(encoding="utf-8")
    return text.split("\n### Reaching the AKS API\n", 1)[1].split("\n## ", 1)[0]


def test_the_module_takes_no_subnet():
    assert "vnet_subnet_id" not in AKS_MAIN.read_text(encoding="utf-8")


def test_the_private_cluster_text_names_the_managed_vnet_and_command_invoke_with_files():
    section = _reaching_the_aks_api()
    flat = " ".join(section.split())
    assert "node resource group" in flat, flat
    assert "az aks command invoke" in flat and "--file ." in flat, flat
    assert "orgIds.primary" in flat and "policy.inline=policy.yaml" in flat, flat
    for claim in ("vnet_subnet_id", "subnet_id", "the cluster's virtual network or a peered one"):
        assert claim not in flat, claim


AKS_OUTPUTS = Path(__file__).resolve().parent.parent / "deploy" / "terraform" / "examples" / "aks" / "outputs.tf"
SET_KEY = re.compile(r"--set(?:-string|-file)?[ =]([^=\s]+)=")

# outputs.tf's org key, where it differs from the README's.
OUTPUTS_TO_README: dict[str, str] = {}


def _command_invoke_keys() -> set[str]:
    block = re.search(r"```sh\n(.*?)\n```", _reaching_the_aks_api(), re.DOTALL).group(1)
    command = re.search(r'--command "(.*?)"\s*$', block, re.DOTALL).group(1)
    return set(SET_KEY.findall(command))


def _helm_install_command_keys() -> set[str]:
    src = AKS_OUTPUTS.read_text(encoding="utf-8")
    body = re.search(r'output "helm_install_command" \{(.*?)\n\}', src, re.DOTALL).group(1)
    command = " ".join(re.findall(r'^\s*"([^"]*)",?\s*$', body, re.MULTILINE))
    return {OUTPUTS_TO_README.get(k, k) for k in SET_KEY.findall(command)}


def test_the_command_invoke_install_sets_what_helm_install_command_sets():
    readme, outputs = _command_invoke_keys(), _helm_install_command_keys()
    assert len(readme) > 15, readme
    assert readme == outputs, {"only in README": sorted(readme - outputs),
                               "only in helm_install_command": sorted(outputs - readme)}
