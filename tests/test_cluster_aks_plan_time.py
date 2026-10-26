"""cluster-aks plans in the same run as the network-azure that makes its
subnets and the registry it pulls from.

A subnet's id is not known until the subnet exists. A count that reads
vnet_subnet_id then fails the plan with "Invalid count argument", which
mocked renders cannot show, since a mock gives every attribute a value.
This plans the two modules together with `command = plan`, where the
subnet ids are still unknown.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
from terraform_render import STACK_EDITS, module, plugin_dir

terraform = shutil.which("terraform")
pytestmark = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

ROOT = '''
terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = "00000000-0000-0000-0000-000000000000"
}

resource "azurerm_container_registry" "lab" {
  name                = "acrlab"
  resource_group_name = "rg"
  location            = "centralus"
  sku                 = "Basic"
}

module "network" {
  source              = "./network-azure"
  resource_group_name = "rg"
  location            = "centralus"
}

module "cluster" {
  source                               = "./cluster-aks"
  resource_group_name                  = "rg"
  location                             = "centralus"
  cluster_name                         = "aks"
  writer_identity_id                   = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/writer"
  reader_identity_id                   = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/reader"
  writer_service_account               = "forgd-verdict-writer"
  reader_service_account               = "forgd-verdict-reader"
  allow_unrestricted_public_api_server = true
  ingress                              = "agc"
  vnet_subnet_id                       = module.network.node_subnet_id
  agc_subnet_id                        = module.network.agc_subnet_id
  registry_id                          = azurerm_container_registry.lab.id
  grant_registry_pull                  = true
}
'''

TEST = '''
mock_provider "azurerm" {}

run "plan" {
  command = plan
}
'''


def test_cluster_aks_plans_with_subnets_and_a_registry_not_made_yet(tmp_path):
    for name in ("network-azure", "cluster-aks"):
        shutil.copytree(module(name), tmp_path / name, ignore=shutil.ignore_patterns(".terraform*"))
    # A mocked plan gives the cluster an empty kubelet_identity list where
    # the provider would give an unknown; the render harness's edit for it.
    for (name, file), edits in STACK_EDITS.items():
        path = tmp_path / name / file
        text = path.read_text(encoding="utf-8")
        for now, then in edits:
            assert now in text, now
            text = text.replace(now, then, 1)
        path.write_text(text, encoding="utf-8")
    (tmp_path / "main.tf").write_text(ROOT, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "plan.tftest.hcl").write_text(TEST, encoding="utf-8")
    init = subprocess.run([terraform, f"-chdir={tmp_path}", "init", "-input=false", "-no-color",
                           f"-plugin-dir={plugin_dir(module('cluster-aks'))}"],
                          capture_output=True, text=True, timeout=300)
    assert init.returncode == 0, init.stderr
    run = subprocess.run([terraform, f"-chdir={tmp_path}", "test", "-no-color"],
                         capture_output=True, text=True, timeout=300)
    assert run.returncode == 0, run.stdout[-3000:] + run.stderr[-3000:]
