"""app-aca's Key Vault secret ids: each secret the module writes into a
Container Apps secret store, and so into the Terraform state, can instead be
named by a Key Vault secret id. The app then reads it through a Key Vault
reference, and the module never holds the value.

The plain variables keep working. A slot given both a value and an id is
refused, as is a name given in both a plain map and its id map, and neither
refusal prints the value.
"""

from __future__ import annotations

import json

import pytest
import terraform_render
from test_app_aca import requires_terraform
from test_app_aca_admins import RENDER, RENDER_ON

PROD = "00000000-0000-0000-0000-00000000000c"
EU = "00000000-0000-0000-0000-00000000000d"
SENTINEL = "SENTINEL-plain-value-0123456789abcdef"  # gitleaks:allow (made up)


def _kv(name: str) -> str:
    return f"https://kv-example.vault.azure.net/secrets/{name}"


SCALARS = {
    "webhook_secret_id": _kv("webhook"),
    "webhook_secret_previous_id": _kv("webhook-previous"),
    "hash_salt_secret_id": _kv("hash-salt"),
    "metrics_token_secret_id": _kv("metrics"),
    "compliance_key_secret_id": _kv("compliance"),
    "intake_fleet_token_secret_id": _kv("fleet"),
    "intake_fleet_token_previous_secret_id": _kv("fleet-previous"),
    "dashboard_auth_client_secret_secret_id": _kv("entra"),
    "dashboard_form_key_secret_id": _kv("form-key"),
}
MAPS = {
    "webhook_secret_ids": {"prod": {"current": _kv("webhook-prod"), "previous": _kv("webhook-prod-previous")}},
    "otel_token_secret_ids": {"prod": _kv("otel-prod")},
    "compliance_key_secret_ids": {"prod": _kv("compliance-prod")},
    "intake_fleet_token_secret_ids": {"prod": {"current": _kv("fleet-prod"), "previous": _kv("fleet-prod-previous")}},
    "intake_token_secret_ids": {"agent": _kv("intake-agent")},
}
# Every id, no plain value: the placeholders and the hash salt left at their
# defaults, otel_tokens emptied, form key unset.
ALL_IDS = {**RENDER, **RENDER_ON, **SCALARS, **MAPS,
           "hash_salt": "", "otel_tokens": {}, "dashboard_form_key": "",
           "org_ids": {"prod": PROD}, "enable_intake": True,
           "dashboard_auth_client_id": "entra-client", "dashboard_auth_tenant_id": "tenant"}

# app address -> secret name -> (env name, Key Vault id, identity variable)
EXPECTED = {
    "azurerm_container_app.verdict": {
        "webhook-secret": ("WEBHOOK_SECRET", _kv("webhook"), "identity_id"),
        "webhook-secret-previous": ("WEBHOOK_SECRET_PREVIOUS", _kv("webhook-previous"), "identity_id"),
        "webhook-secret-prod": ("WEBHOOK_SECRET_PROD", _kv("webhook-prod"), "identity_id"),
        "webhook-secret-prod-previous": ("WEBHOOK_SECRET_PROD_PREVIOUS", _kv("webhook-prod-previous"), "identity_id"),
        "hash-salt": ("FORGD_HASH_SALT", _kv("hash-salt"), "identity_id"),
        "metrics-token": ("FORGD_METRICS_TOKEN", _kv("metrics"), "identity_id"),
    },
    "azurerm_container_app.collector": {
        "otel-token-prod": ("FORGD_OTEL_TOKEN_PROD", _kv("otel-prod"), "identity_id"),
        "hash-salt": ("FORGD_HASH_SALT", _kv("hash-salt"), "identity_id"),
        "metrics-token": ("FORGD_METRICS_TOKEN", _kv("metrics"), "identity_id"),
    },
    "azurerm_container_app.intake": {
        "intake-fleet-token": ("FORGD_INTAKE_FLEET_TOKEN", _kv("fleet"), "identity_id"),
        "intake-fleet-token-previous": ("FORGD_INTAKE_FLEET_TOKEN_PREVIOUS", _kv("fleet-previous"), "identity_id"),
        "intake-fleet-token-prod": ("FORGD_INTAKE_FLEET_TOKEN_PROD", _kv("fleet-prod"), "identity_id"),
        "intake-fleet-token-prod-previous": ("FORGD_INTAKE_FLEET_TOKEN_PROD_PREVIOUS",
                                             _kv("fleet-prod-previous"), "identity_id"),
        "intake-token-agent": ("FORGD_INTAKE_TOKEN_AGENT", _kv("intake-agent"), "identity_id"),
        "hash-salt": ("FORGD_HASH_SALT", _kv("hash-salt"), "identity_id"),
        "metrics-token": ("FORGD_METRICS_TOKEN", _kv("metrics"), "identity_id"),
    },
    "azurerm_container_app.dashboard": {
        "entra-client-secret": (None, _kv("entra"), "reader_identity_id"),
        "dashboard-form-key": ("FORGD_DASHBOARD_FORM_KEY", _kv("form-key"), "control_identity_id"),
    },
    "azurerm_container_app_job.ingest": {
        "compliance-key": ("ANTHROPIC_COMPLIANCE_ACCESS_KEY", _kv("compliance"), "identity_id"),
        "compliance-key-prod": ("ANTHROPIC_COMPLIANCE_ACCESS_KEY_PROD", _kv("compliance-prod"), "identity_id"),
        "hash-salt": ("FORGD_HASH_SALT", _kv("hash-salt"), "identity_id"),
    },
}


def _render(tmp_path, **variables) -> dict:
    return terraform_render.render_module(tmp_path, "app-aca", variables)


def _one(value):
    return value[0] if isinstance(value, list) else value


def _app(rendered: dict, address: str) -> tuple[dict, dict]:
    app = _one(rendered[address])
    [template] = app["template"]
    env = {e["name"]: e for c in template["container"] for e in c["env"]}
    return {s["name"]: s for s in app["secret"]}, env


@pytest.fixture(scope="module")
def all_ids(tmp_path_factory):
    if terraform_render.terraform is None:
        pytest.skip("terraform is not installed")
    return _render(tmp_path_factory.mktemp("kv"), **ALL_IDS)


@requires_terraform
@pytest.mark.parametrize("address", sorted(EXPECTED))
def test_each_secret_id_becomes_a_key_vault_reference(all_ids, address):
    secrets, env = _app(all_ids, address)
    for name, (env_name, kv, identity) in EXPECTED[address].items():
        secret = secrets[name]
        assert secret.get("value") is None, name
        assert secret["key_vault_secret_id"] == kv, name
        assert secret["identity"] == ALL_IDS[identity], name
        if env_name:
            assert env[env_name]["secret_name"] == name and env[env_name]["value"] is None


@requires_terraform
def test_with_every_id_no_secret_in_the_state_holds_a_value(all_ids):
    """The defaults stay: webhook_secret and compliance_api_key are still
    the placeholder, and none of it reaches a secret store."""
    held = [(address, s["name"]) for address in all_ids if address.startswith("azurerm_container_app")
            for app in ([all_ids[address]] if isinstance(all_ids[address], dict) else all_ids[address])
            for s in app.get("secret") or [] if s.get("value") is not None]
    assert held == []
    assert "placeholder-not-yet-issued" not in json.dumps(all_ids)


@requires_terraform
def test_the_plain_variables_still_write_values(tmp_path):
    rendered = _render(tmp_path, **{**RENDER, "metrics_token": "m" * 32, "org_ids": {"prod": PROD},
                                    "webhook_secrets": {"prod": {"current": "w" * 32}},
                                    "otel_tokens": {"prod": "o" * 32}})
    secrets, _ = _app(rendered, "azurerm_container_app.verdict")
    for name, value in (("webhook-secret", "placeholder-not-yet-issued"), ("webhook-secret-prod", "w" * 32),
                        ("hash-salt", RENDER["hash_salt"]), ("metrics-token", "m" * 32)):
        assert secrets[name]["value"] == value and secrets[name].get("key_vault_secret_id") is None, name
    secrets, _ = _app(rendered, "azurerm_container_app.collector")
    assert secrets["otel-token-prod"]["value"] == "o" * 32


@requires_terraform
def test_one_org_plain_and_another_by_id_render_side_by_side(tmp_path):
    rendered = _render(tmp_path, **{**RENDER, "org_ids": {"prod": PROD, "eu": EU},
                                    "otel_tokens": {"prod": "o" * 32},
                                    "otel_token_secret_ids": {"eu": _kv("otel-eu")}})
    secrets, env = _app(rendered, "azurerm_container_app.collector")
    assert secrets["otel-token-prod"]["value"] == "o" * 32
    assert secrets["otel-token-eu"]["value"] is None
    assert secrets["otel-token-eu"]["key_vault_secret_id"] == _kv("otel-eu")
    assert {"FORGD_OTEL_TOKEN_PROD", "FORGD_OTEL_TOKEN_EU"} <= set(env)


@requires_terraform
@pytest.mark.parametrize("variable,id_variable", [
    ("webhook_secret", "webhook_secret_id"), ("webhook_secret_previous", "webhook_secret_previous_id"),
    ("hash_salt", "hash_salt_secret_id"), ("metrics_token", "metrics_token_secret_id"),
    ("compliance_api_key", "compliance_key_secret_id"),
    ("intake_fleet_token", "intake_fleet_token_secret_id"),
    ("dashboard_auth_client_secret", "dashboard_auth_client_secret_secret_id")])
def test_a_value_and_an_id_for_one_secret_are_refused_without_the_value(tmp_path, variable, id_variable):
    extra = {"dashboard_auth_client_id": "entra-client"} if variable.startswith("dashboard") else {}
    extra |= {"enable_intake": True} if variable.startswith("intake") else {}
    with pytest.raises(AssertionError, match=rf"set {variable} or {id_variable}, not both") as raised:
        _render(tmp_path, **{**RENDER, **extra, variable: SENTINEL, id_variable: _kv("x")})
    assert SENTINEL not in str(raised.value)


@requires_terraform
@pytest.mark.parametrize("plain,ids,value", [
    ("otel_tokens", "otel_token_secret_ids", "o" * 32),
    ("compliance_api_keys", "compliance_key_secret_ids", SENTINEL),
    ("intake_fleet_tokens", "intake_fleet_token_secret_ids", {"current": SENTINEL}),
    ("webhook_secrets", "webhook_secret_ids", {"current": SENTINEL}),
])
def test_a_name_in_a_plain_map_and_its_id_map_is_refused(tmp_path, plain, ids, value):
    kv = {"current": _kv("x")} if isinstance(value, dict) else _kv("x")
    with pytest.raises(AssertionError, match=rf"{plain}\.prod and {ids}\.prod") as raised:
        _render(tmp_path, **{**RENDER, "org_ids": {"prod": PROD}, plain: {"prod": value}, ids: {"prod": kv}})
    assert SENTINEL not in str(raised.value)


@requires_terraform
def test_an_empty_hash_salt_is_still_refused_without_its_id(tmp_path):
    with pytest.raises(AssertionError, match="Set TF_VAR_hash_salt to at least 16 characters"):
        _render(tmp_path, **{**RENDER, "hash_salt": ""})


@requires_terraform
def test_no_otel_token_by_either_route_is_refused(tmp_path):
    with pytest.raises(AssertionError, match="otel_tokens or otel_token_secret_ids needs at least one entry"):
        _render(tmp_path, **{**RENDER, "otel_tokens": {}})


@requires_terraform
@pytest.mark.parametrize("variable,value", [
    ("hash_salt_secret_id", "http://kv-example.vault.azure.net/secrets/x"),
    ("hash_salt_secret_id", "https://kv-example.vault.azure.net/secrets/x?value=y"),
    ("hash_salt_secret_id", "https://kv-example.vault.azure.net.attacker.example/secrets/x"),
    ("hash_salt_secret_id", "not-an-id"),
    ("otel_token_secret_ids", {"primary": "not-an-id"}),
    ("webhook_secret_ids", {"prod": {"current": "not-an-id"}}),
    ("intake_token_secret_ids", {"a b": _kv("x")}),
])
def test_a_secret_id_that_is_not_a_key_vault_id_is_refused(tmp_path, variable, value):
    with pytest.raises(AssertionError, match=r"Key Vault secret id|letters, digits"):
        _render(tmp_path, **{**RENDER, "org_ids": {"prod": PROD}, variable: value})
