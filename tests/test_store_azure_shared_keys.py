"""store-azure refuses shared key access by default, and examples/aks then
keeps Terraform off the findings account's data plane.

A shared key bypasses every role assignment and condition on the account,
and Contributor can list the keys. lockout_evidence/azure.py counts
listKeys as a grant for the same reason.
"""

from __future__ import annotations

import re
import shutil

import pytest
import terraform_render as tr
from test_cluster_aks import STACK_REQUIRED
from test_cluster_eks import _text

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")
STORE = tr.TERRAFORM / "modules" / "store-azure"
EXAMPLE = tr.TERRAFORM / "examples" / "aks"


def _account(tmp_path, **variables) -> dict:
    rendered = tr.render_aks_stack_once(tmp_path, {**STACK_REQUIRED, **variables})
    return rendered["module.store"]["render"]["azurerm_storage_account.findings"]


@requires_terraform
def test_the_findings_account_refuses_shared_keys_by_default(tmp_path):
    assert _account(tmp_path)["shared_access_key_enabled"] is False


@requires_terraform
def test_shared_keys_can_be_turned_back_on(tmp_path):
    assert _account(tmp_path, shared_access_key_enabled=True)["shared_access_key_enabled"] is True


def test_the_module_default_is_false():
    variables = _text(STORE / "variables.tf")
    block = re.search(r'variable "shared_access_key_enabled" \{(.*?)\n\}', variables, re.S)
    assert block and re.search(r"^\s*default\s*=\s*false\s*$", block.group(1), re.M)
    assert re.search(r"^\s*shared_access_key_enabled\s*=\s*var\.shared_access_key_enabled\s*$",
                     _text(STORE / "main.tf"), re.M)


def test_the_example_keeps_terraform_off_the_data_plane_when_keys_are_off():
    """With keys off, a data-plane call authenticated by key fails, and the
    infra identity holds no data role to make one with Entra ID either."""
    provider = re.search(r'^provider "azurerm" \{\n(.*?)^\}', _text(EXAMPLE / "main.tf"), re.S | re.M).group(1)
    assert re.search(r"^\s*storage_use_azuread\s*=\s*!var\.shared_access_key_enabled\s*$", provider, re.M)
    assert re.search(r"^\s*data_plane_available\s*=\s*var\.shared_access_key_enabled\s*$", provider, re.M)
