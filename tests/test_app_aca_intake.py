"""app-aca's intake, adapter 2's receiving end, as app-ecs and app-cloudrun
have it: off by default, its own container app on 8200 with external
ingress and no sign-in in front, the fleet token pair, per-org fleet
tokens keyed to org_ids, and per-client tokens."""

from __future__ import annotations

import json

import pytest
import terraform_render
from test_app_aca import requires_terraform
from test_app_aca_admins import RENDER

PROD = "00000000-0000-0000-0000-00000000000c"
FLEET = "f" * 32
INTAKE = {"enable_intake": True, "intake_fleet_token": FLEET}


def _render(tmp_path, **variables) -> dict:
    return terraform_render.render_module(tmp_path, "app-aca", {**RENDER, **variables})


def _intake(rendered: dict) -> tuple[dict, dict, dict]:
    app = rendered["azurerm_container_app.intake"]
    app = app[0] if isinstance(app, list) else app
    [template] = app["template"]
    [container] = template["container"]
    env = {e["name"]: e for e in container["env"]}
    secrets = {s["name"]: s.get("value") for s in app["secret"]}
    return app, env, secrets


def _secret_of(env: dict, secrets: dict, name: str) -> str:
    return secrets[env[name]["secret_name"]]


@requires_terraform
def test_the_intake_is_off_by_default(tmp_path):
    rendered = _render(tmp_path)
    assert not [k for k in rendered if k.startswith("azurerm_container_app.intake")
                and rendered[k] not in ([], None, {})]


@requires_terraform
def test_the_intake_serves_8200_externally_with_no_sign_in(tmp_path):
    rendered = _render(tmp_path, **INTAKE)
    app, env, _ = _intake(rendered)
    [ingress] = app["ingress"]
    assert ingress["external_enabled"] is True and ingress["target_port"] == 8200
    assert env["FORGD_ROLE"]["value"] == "intake"
    assert env["FORGD_GITLEAKS_SOCKET"]["value"] == "/run/forgd/gitleaksd.sock"
    assert "FORGD_HASH_SALT" in env and "AZURE_CLIENT_ID" in env
    [container] = app["template"][0]["container"]
    [live] = container["liveness_probe"]
    assert live["path"] == "/livez" and live["port"] == 8200
    auth = [k for k, v in rendered.items() if "auth" in k.lower() and "intake" in json.dumps(v)]
    assert not auth, auth


@requires_terraform
def test_the_fleet_token_and_its_previous_reach_the_intake(tmp_path):
    _, env, secrets = _intake(_render(tmp_path, **INTAKE, intake_fleet_token_previous=FLEET + "old"))
    assert _secret_of(env, secrets, "FORGD_INTAKE_FLEET_TOKEN") == FLEET
    assert _secret_of(env, secrets, "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS") == FLEET + "old"


@requires_terraform
def test_an_unset_previous_fleet_token_sets_no_variable(tmp_path):
    _, env, _ = _intake(_render(tmp_path, **INTAKE))
    assert "FORGD_INTAKE_FLEET_TOKEN_PREVIOUS" not in env


@requires_terraform
def test_each_org_fleet_gets_its_token_and_its_previous_one(tmp_path):
    _, env, secrets = _intake(_render(tmp_path, enable_intake=True,
                                      org_ids={"primary": PROD, "prod": PROD},
                                      intake_fleet_tokens={"prod": {"current": "p" * 32, "previous": "o" * 32}}))
    assert _secret_of(env, secrets, "FORGD_INTAKE_FLEET_TOKEN_PROD") == "p" * 32
    assert _secret_of(env, secrets, "FORGD_INTAKE_FLEET_TOKEN_PROD_PREVIOUS") == "o" * 32
    assert "FORGD_INTAKE_FLEET_TOKEN" not in env


@requires_terraform
def test_each_client_gets_its_token(tmp_path):
    _, env, secrets = _intake(_render(tmp_path, enable_intake=True,
                                      intake_tokens={"invoice-bot": "b" * 32}))
    assert _secret_of(env, secrets, "FORGD_INTAKE_TOKEN_INVOICE_BOT") == "b" * 32


@requires_terraform
def test_an_intake_with_no_token_is_refused(tmp_path):
    with pytest.raises(AssertionError, match="enable_intake with no intake_fleet_token"):
        _render(tmp_path, enable_intake=True)


def _fleet_map(*names: str, ids: dict | None = None) -> dict:
    ids = ids if ids is not None else {n: PROD for n in names}
    return {"enable_intake": True, "org_ids": {"primary": PROD, **ids},
            "intake_fleet_tokens": {n: {"current": "t" * 32} for n in names}}


@requires_terraform
@pytest.mark.parametrize(("names", "ids", "match"), [
    (("eu",), {}, r"intake_fleet_tokens\.eu has no org_ids entry"),
    (("previous",), None, r"collides.*_PREVIOUS"),
    (("a", "a-previous"), None, r"collides.*_A_PREVIOUS"),
    (("a-b", "a_b"), {"a-b": PROD}, r"Two .* keys map to the same|collides.*_A_B"),
], ids=["not-an-org", "previous", "a-previous", "a-b-a_b"])
def test_a_per_org_fleet_token_that_would_not_wire_up_is_refused(tmp_path, names, ids, match):
    with pytest.raises(AssertionError, match=match):
        _render(tmp_path, **_fleet_map(*names, ids=ids))


@requires_terraform
def test_the_intake_url_is_an_output(tmp_path):
    outputs = (terraform_render.module("app-aca") / "outputs.tf").read_text(encoding="utf-8")
    assert 'output "intake_url"' in outputs and "var.enable_intake ?" in outputs


@requires_terraform
def test_the_module_plans_as_it_did_at_v0_46_0_with_the_intake_off(tmp_path):
    assert terraform_render.versus_commit(tmp_path, "app-aca", RENDER, "a9a62907") == []
