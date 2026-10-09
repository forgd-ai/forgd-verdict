"""store-azure keeps a deleted container recoverable for a retention window.

Without control_enabled the writer holds Storage Blob Data Contributor,
which includes containers/delete, and no lock covers the account.
"""

from __future__ import annotations

import re
import shutil

import pytest
import terraform_render as tr
from test_cluster_eks import _text

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")
STORE = tr.TERRAFORM / "modules" / "store-azure"
AZURE = {"resource_group_name": "rg", "location": "westeurope", "storage_account_name": "forgdfindings"}


def _blob_properties(tmp_path, **variables) -> dict:
    rendered = tr.render_module(tmp_path, "store-azure", {**AZURE, **variables})
    [properties] = rendered["azurerm_storage_account.findings"]["blob_properties"]
    return properties


def _default_days() -> int:
    block = re.search(r'variable "container_delete_retention_days" \{(.*?)\n\}', _text(STORE / "variables.tf"), re.S)
    assert block, "store-azure declares no container_delete_retention_days"
    return int(re.search(r"^\s*default\s*=\s*(\d+)\s*$", block.group(1), re.M).group(1))


@requires_terraform
def test_module_defaults_keep_deleted_containers_recoverable(tmp_path):
    policy = _blob_properties(tmp_path)["container_delete_retention_policy"]
    assert policy, "a deleted container is gone for good"
    assert policy == [{"days": _default_days()}] and policy[0]["days"] >= 1


@requires_terraform
@pytest.mark.parametrize("off", [0, None], ids=["zero", "null"])
def test_zero_or_null_omits_the_policy(tmp_path, off):
    assert _blob_properties(tmp_path, container_delete_retention_days=off)["container_delete_retention_policy"] == []


@requires_terraform
def test_the_days_are_passed_through(tmp_path):
    assert _blob_properties(tmp_path, container_delete_retention_days=90)["container_delete_retention_policy"] == [
        {"days": 90}]


@requires_terraform
@pytest.mark.parametrize("days", [-1, 1.5, 366], ids=["negative", "fraction", "over-365"])
def test_days_outside_what_azure_accepts_are_refused(tmp_path, days):
    with pytest.raises(AssertionError, match="A whole number of days from 1 to 365"):
        _blob_properties(tmp_path, container_delete_retention_days=days)


@pytest.mark.parametrize("path", [tr.TERRAFORM / "README.md", STORE / "variables.tf"], ids=["README", "variables"])
def test_the_rescan_claim_is_limited_to_the_pulling_adapters(path):
    """Adapters 3 and 6 pull from Anthropic again; 1, 2 and 4 record what
    arrived once."""
    text = " ".join(path.read_text(encoding="utf-8").split())
    assert "derived data and a rescan reproduces them" not in text
    assert "derived data, and a rescan reproduces them" not in text
    assert "adapters 3 and 6" in text
