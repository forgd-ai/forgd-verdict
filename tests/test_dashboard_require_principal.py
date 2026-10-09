"""`require_principal` refuses to start on every path that sets it.

It meant trusted_header on `x-ms-client-principal-name` with no
`stripped_by`, so any caller who could reach the container named
themselves. `dashboard.auth` is the only way to turn authentication on.
"""

from __future__ import annotations

import json

import pytest
from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard, create_app
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.entitlements import MODE_NONE
from forgd_verdict.store import LocalFileStore

FORGED = {"x-ms-client-principal-name": "attacker"}
REFUSAL = r"dashboard\.auth.*trusted_header.*header.*stripped_by"


@pytest.fixture
def no_policy(monkeypatch, tmp_path):
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    monkeypatch.delenv("FORGD_DASHBOARD_REQUIRE_PRINCIPAL", raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_the_kwarg_refuses(tmp_path):
    with pytest.raises(ValueError, match=REFUSAL):
        Dashboard(LocalFileStore(tmp_path / "s", instance="t"), require_principal=True)


def test_the_create_app_arg_refuses(no_policy):
    with pytest.raises(ValueError, match=REFUSAL):
        create_app(str(no_policy / "s"), True)


@pytest.mark.parametrize("value", ["1", "true", "on"])
def test_the_env_var_refuses(no_policy, monkeypatch, value):
    monkeypatch.setenv("FORGD_DASHBOARD_REQUIRE_PRINCIPAL", value)
    with pytest.raises(ValueError, match=REFUSAL):
        create_app(str(no_policy / "s"))


def test_the_policy_key_refuses(no_policy, monkeypatch):
    policy = no_policy / "policy.yaml"
    policy.write_text(json.dumps({"dashboard": {"require_principal": True}}))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))
    with pytest.raises(ValueError, match=REFUSAL):
        create_app(str(no_policy / "s"))


def test_the_policy_key_refuses_even_beside_dashboard_auth(no_policy, monkeypatch):
    policy = no_policy / "policy.yaml"
    policy.write_text(json.dumps({"dashboard": {
        "require_principal": True,
        "auth": {"mode": "trusted_header", "header": "x-auth-user",
                 "stripped_by": "a proxy checked in this test"}}}))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))
    with pytest.raises(ValueError, match=REFUSAL):
        create_app(str(no_policy / "s"))


def test_the_cli_flag_refuses(no_policy):
    from forgd_verdict.dashboard.__main__ import main

    with pytest.raises(ValueError, match=REFUSAL):
        main(["--store", str(no_policy / "s"), "--require-principal",
              "--render", str(no_policy / "out.html")])
    assert not (no_policy / "out.html").exists()


@pytest.mark.parametrize("value", ["", "0", "false"])
def test_false_or_unset_still_starts_in_mode_none(no_policy, monkeypatch, value):
    monkeypatch.setenv("FORGD_DASHBOARD_REQUIRE_PRINCIPAL", value)
    assert create_app(str(no_policy / "s")).auth.mode == MODE_NONE
    assert create_app(str(no_policy / "s"), False).auth.mode == MODE_NONE


async def test_a_forged_principal_header_is_never_served_as_that_name(no_policy):
    """The reviewer's case: `x-ms-client-principal-name: attacker`."""
    store = LocalFileStore(no_policy / "s", instance="t")

    with pytest.raises(ValueError):
        Dashboard(store, require_principal=True)

    # Mode none names nobody, whatever header arrives.
    status, body = await ASGIClient(Dashboard(store)).get("/", FORGED)
    assert status == 200 and "attacker" not in body

    # An attested trusted_header on another header ignores the forged one.
    auth = AuthConfig.parse({"mode": "trusted_header", "header": "x-auth-user",
                             "stripped_by": "a proxy checked in this test"})
    status, body = await ASGIClient(Dashboard(store, auth=auth)).get("/", FORGED)
    assert status == 401 and "attacker" not in json.dumps(body)
