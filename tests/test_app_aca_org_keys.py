"""app-aca's org ids and per-org OTel tokens, named as app-ecs and the chart
name them: upper case, hyphens as underscores.

A token whose org has no id is refused, as the chart refuses it: the
collector cross-checks a batch's organization.id against the org's id, and
an empty id cannot make that check fire.
"""

from __future__ import annotations

import pytest
import terraform_render
from test_app_aca import requires_terraform
from test_app_aca_admins import RENDER

PROD = "00000000-0000-0000-0000-00000000000c"
EU = "00000000-0000-0000-0000-00000000000d"


def _render(tmp_path, **variables) -> dict:
    return terraform_render.render_module(tmp_path, "app-aca", {**RENDER, **variables})


def _collector(rendered: dict) -> tuple[dict, list[dict]]:
    app = rendered["azurerm_container_app.collector"]
    [template] = app["template"]
    [container] = template["container"]
    return {e["name"]: e for e in container["env"]}, app["secret"]


@requires_terraform
def test_a_hyphenated_key_is_named_with_an_underscore(tmp_path):
    env, secrets = _collector(_render(tmp_path, org_ids={"eu-west": EU},
                                      otel_tokens={"eu-west": "t" * 32}))
    assert env["FORGD_ORG_ID_EU_WEST"]["value"] == EU
    token = env["FORGD_OTEL_TOKEN_EU_WEST"]
    assert token["value"] is None and token["secret_name"] in {s["name"] for s in secrets}


@requires_terraform
def test_two_tokens_render_two_env_entries_and_two_secrets(tmp_path):
    env, secrets = _collector(_render(tmp_path, org_ids={"prod": PROD, "eu-west": EU},
                                      otel_tokens={"prod": "p" * 32, "eu-west": "e" * 32}))
    tokens = {n: e for n, e in env.items() if n.startswith("FORGD_OTEL_TOKEN_")}
    assert set(tokens) == {"FORGD_OTEL_TOKEN_PROD", "FORGD_OTEL_TOKEN_EU_WEST"}
    names = {e["secret_name"] for e in tokens.values()}
    assert len(names) == 2
    by_name = {s["name"]: s for s in secrets}
    assert names <= set(by_name)
    assert sorted(by_name[n]["value"] for n in names) == ["e" * 32, "p" * 32]


@requires_terraform
def test_nothing_set_renders_the_placeholder_token(tmp_path):
    env, secrets = _collector(_render(tmp_path))
    [name] = [n for n in env if n.startswith("FORGD_OTEL_TOKEN_")]
    assert name == "FORGD_OTEL_TOKEN_PRIMARY"
    [secret] = [s for s in secrets if s["name"] == env[name]["secret_name"]]
    assert secret["value"] == "placeholder-not-yet-issued"


@requires_terraform
@pytest.mark.parametrize("variable", ["org_ids", "otel_tokens"])
@pytest.mark.parametrize("key", ["eu west", "eu.west", ""], ids=["space", "dot", "empty"])
def test_a_bad_key_is_refused(tmp_path, variable, key):
    values = {"org_ids": {"prod": PROD}, "otel_tokens": {"prod": "p" * 32}}
    values[variable] = {key: EU if variable == "org_ids" else "e" * 32}
    with pytest.raises(AssertionError, match=rf"Each {variable} key must be"):
        _render(tmp_path, **values)


@requires_terraform
@pytest.mark.parametrize("variable", ["org_ids", "otel_tokens"])
def test_two_keys_that_collide_are_refused(tmp_path, variable):
    values = {"org_ids": {"eu-west": EU}, "otel_tokens": {"eu-west": "e" * 32}}
    values[variable] = {"eu-west": EU, "EU_WEST": EU} if variable == "org_ids" \
        else {"eu-west": "e" * 32, "EU_WEST": "f" * 32}
    with pytest.raises(AssertionError, match=rf"Two {variable} keys map to the same"):
        _render(tmp_path, **values)


@requires_terraform
@pytest.mark.parametrize(("org_ids", "message"), [
    ({}, r"otel_tokens\.eu-west has no non-empty org_ids entry"),
    ({"prod": PROD}, r"otel_tokens\.eu-west has no non-empty org_ids entry"),
    ({"eu-west": ""}, r"org_ids\.eu-west is not an organization UUID"),
], ids=["no-orgs", "another-org", "empty-id"])
def test_a_token_without_an_org_is_refused(tmp_path, org_ids, message):
    with pytest.raises(AssertionError, match=message):
        _render(tmp_path, org_ids=org_ids, otel_tokens={"eu-west": "e" * 32})


@requires_terraform
def test_a_token_matched_through_the_env_name_is_accepted(tmp_path):
    env, _ = _collector(_render(tmp_path, org_ids={"EU_WEST": EU}, otel_tokens={"eu-west": "e" * 32}))
    assert {"FORGD_ORG_ID_EU_WEST", "FORGD_OTEL_TOKEN_EU_WEST"} <= set(env)


@requires_terraform
def test_no_token_is_refused(tmp_path):
    with pytest.raises(AssertionError, match="otel_tokens or otel_token_secret_ids needs at least one entry"):
        _render(tmp_path, otel_tokens={})


@requires_terraform
@pytest.mark.parametrize("value", ["", "not-a-uuid-SENTINEL", "00000000-0000-0000-0000-00000000000"],
                         ids=["empty", "word", "short"])
def test_an_org_id_that_is_not_a_uuid_is_refused(tmp_path, value):
    with pytest.raises(AssertionError, match=r"org_ids\.eu-west is not an organization UUID") as raised:
        _render(tmp_path, org_ids={"prod": PROD, "eu-west": value})
    assert "SENTINEL" not in str(raised.value)


@requires_terraform
def test_a_mixed_case_org_id_is_accepted(tmp_path):
    mixed = "00000000-0000-4000-8000-00000000C0de"
    env, _ = _collector(_render(tmp_path, org_ids={"eu-west": mixed}, otel_tokens={"eu-west": "e" * 32}))
    assert env["FORGD_ORG_ID_EU_WEST"]["value"] == mixed


# -- per-org signing secrets and Compliance Access Keys ---------------------

WH = "whsec_" + "A" * 32


def _app(rendered: dict, kind: str, name: str) -> tuple[dict, dict]:
    app = rendered[f"azurerm_{kind}.{name}"]
    [template] = app["template"]
    [container] = template["container"]
    secrets = {s["name"]: s.get("value") for s in app["secret"]}
    return {e["name"]: e.get("secret_name") for e in container["env"]}, secrets


@requires_terraform
def test_each_org_gets_its_signing_secret_and_its_previous_one(tmp_path):
    rendered = _render(tmp_path, org_ids={"primary": PROD, "eu-west": EU}, otel_tokens={"primary": "p" * 32},
                       webhook_secrets={"eu-west": {"current": WH, "previous": WH + "old"}})
    env, secrets = _app(rendered, "container_app", "verdict")
    assert secrets[env["WEBHOOK_SECRET_EU_WEST"]] == WH
    assert secrets[env["WEBHOOK_SECRET_EU_WEST_PREVIOUS"]] == WH + "old"
    assert env["WEBHOOK_SECRET"] == "webhook-secret"


@requires_terraform
def test_an_org_without_a_previous_secret_gets_no_previous_variable(tmp_path):
    rendered = _render(tmp_path, org_ids={"primary": PROD, "eu-west": EU}, otel_tokens={"primary": "p" * 32},
                       webhook_secrets={"eu-west": {"current": WH}})
    env, _ = _app(rendered, "container_app", "verdict")
    assert "WEBHOOK_SECRET_EU_WEST" in env and "WEBHOOK_SECRET_EU_WEST_PREVIOUS" not in env


@requires_terraform
def test_the_single_signing_secret_has_a_previous_slot(tmp_path):
    env, secrets = _app(_render(tmp_path, webhook_secret_previous=WH + "old"), "container_app", "verdict")
    assert secrets[env["WEBHOOK_SECRET_PREVIOUS"]] == WH + "old"
    env, _ = _app(_render(tmp_path / "unset"), "container_app", "verdict")
    assert "WEBHOOK_SECRET_PREVIOUS" not in env


@requires_terraform
def test_each_org_gets_its_compliance_key_and_no_previous(tmp_path):
    rendered = _render(tmp_path, org_ids={"primary": PROD, "eu-west": EU}, otel_tokens={"primary": "p" * 32},
                       compliance_api_keys={"eu-west": "sk-ant-api01-eu"})
    env, secrets = _app(rendered, "container_app_job", "ingest")
    assert secrets[env["ANTHROPIC_COMPLIANCE_ACCESS_KEY_EU_WEST"]] == "sk-ant-api01-eu"
    assert not any(n.endswith("_PREVIOUS") for n in env if n.startswith("ANTHROPIC_"))


ORG_MAPS = {
    "webhook_secrets": lambda n: {"current": WH},
    "compliance_api_keys": lambda n: "sk-ant-api01-" + n,
}


def _with_org_map(variable: str, *names: str, ids: dict | None = None) -> dict:
    ids = ids if ids is not None else {n: PROD for n in names}
    return {"org_ids": {"primary": PROD, **ids}, "otel_tokens": {"primary": "p" * 32},
            variable: {n: ORG_MAPS[variable](n) for n in names}}


@requires_terraform
@pytest.mark.parametrize("variable", ORG_MAPS)
def test_a_per_org_secret_for_a_name_not_in_org_ids_is_refused(tmp_path, variable):
    with pytest.raises(AssertionError, match=rf"{variable}\.eu has no org_ids entry"):
        _render(tmp_path, **_with_org_map(variable, "eu", ids={}))


@requires_terraform
def test_an_org_named_previous_collides_with_the_single_slot(tmp_path):
    with pytest.raises(AssertionError, match=r"collides.*_PREVIOUS"):
        _render(tmp_path, **_with_org_map("webhook_secrets", "previous"))


@requires_terraform
def test_an_org_and_its_previous_name_collide(tmp_path):
    with pytest.raises(AssertionError, match=r"collides.*_A_PREVIOUS"):
        _render(tmp_path, **_with_org_map("webhook_secrets", "a", "a-previous"))


@requires_terraform
@pytest.mark.parametrize("variable", ORG_MAPS)
def test_two_names_for_one_variable_collide(tmp_path, variable):
    with pytest.raises(AssertionError, match=r"Two .* keys map to the same|collides.*_A_B"):
        _render(tmp_path, **_with_org_map(variable, "a-b", "a_b", ids={"a-b": PROD}))


@requires_terraform
def test_the_module_plans_as_it_did_at_v0_46_0_with_no_per_org_maps(tmp_path):
    assert terraform_render.versus_commit(tmp_path, "app-aca", RENDER, "a9a62907") == []
