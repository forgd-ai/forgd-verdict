"""The network-azure module: a VNet with a node subnet and a /24 delegated
to Application Gateway for Containers (docs/design/agc.md).

Rendered with a mocked azurerm provider; nothing reaches a cloud.
"""

from __future__ import annotations

import shutil

import pytest
from terraform_render import _azure, module, plugin_dir, render_once

terraform = shutil.which("terraform")
pytestmark = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

NETWORK = module("network-azure")
VARIABLES = {"resource_group_name": "rg", "location": "centralus"}


def _render(tmp_path, **over) -> dict:
    return render_once(tmp_path / "network-azure", NETWORK, {**VARIABLES, **over},
                       providers=["azurerm"], mock_data={}, overrides=_azure,
                       plugins=plugin_dir(NETWORK))


def test_the_agc_subnet_is_a_delegated_slash_24_beside_the_nodes(tmp_path):
    rendered = _render(tmp_path)
    vnet = rendered["azurerm_virtual_network.this"]
    nodes = rendered["azurerm_subnet.nodes"]
    agc = rendered["azurerm_subnet.agc"]
    assert vnet["address_space"] == ["10.240.0.0/16"]
    assert nodes["address_prefixes"] == ["10.240.0.0/22"]
    assert agc["address_prefixes"] == ["10.240.8.0/24"]
    assert nodes["virtual_network_name"] == agc["virtual_network_name"] == vnet["name"]
    assert nodes.get("delegation") in (None, [])
    [delegation] = agc["delegation"]
    [service] = delegation["service_delegation"]
    assert service["name"] == "Microsoft.ServiceNetworking/trafficControllers"


def test_the_default_space_avoids_aks_service_and_pod_defaults(tmp_path):
    rendered = _render(tmp_path)
    for prefix in rendered["azurerm_virtual_network.this"]["address_space"]:
        assert not prefix.startswith(("10.0.", "10.244.")), prefix


@pytest.mark.parametrize("prefix", ["10.240.8.0/23", "10.240.8.0/25", "not-a-cidr"])
def test_an_agc_subnet_other_than_a_slash_24_is_refused(tmp_path, prefix):
    with pytest.raises(AssertionError, match="agc_subnet_prefix must be a /24"):
        _render(tmp_path, agc_subnet_prefix=prefix)
