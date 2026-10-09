"""Every credential path the policy redacts, and what its reference does when
it resolves to nothing: refuse to start, or keep a documented effect and say
so in the log.

A path added to SECRET_PATHS, SECRET_LIST_PATHS or SECRET_MAP_PATHS fails
`test_every_credential_path_is_classified` until it is listed here or in
OPTIONAL_WHEN_UNSET.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from forgd_verdict.policy import (
    OPTIONAL_WHEN_UNSET,
    SECRET_LIST_PATHS,
    SECRET_MAP_PATHS,
    SECRET_PATHS,
    Policy,
    PolicyInvalid,
    default_policy,
    unset_credentials,
    warn_unset_credentials,
)

SRC = Path(__file__).resolve().parents[1] / "src" / "forgd_verdict"
UNSET = "$FORGD_TEST_UNSET_CREDENTIAL"


@pytest.fixture(autouse=True)
def _unset(monkeypatch):
    monkeypatch.delenv(UNSET[1:], raising=False)


def _policy(**sections) -> Policy:
    policy = default_policy()
    for key, value in sections.items():
        policy.raw[key] = {**(policy.raw.get(key) or {}), **value}
    return policy


def _salt():
    from forgd_verdict.policy import Unsalted

    with pytest.raises(Unsalted):
        _policy(privacy={"hash_salt": UNSET}).refuse_unsalted("verdict server")


def _required_header():
    with pytest.raises(PolicyInvalid, match=re.escape(f"required_headers.x-forgd-shared is {UNSET}")):
        _ = _policy(server={"required_headers": {"x-forgd-shared": UNSET}}).required_headers


def _form_key():
    from forgd_verdict.dashboard.admin import AdminConfig

    auth = SimpleNamespace(mode="oidc_jwt", platform="", issuers=())
    with pytest.raises(ValueError, match="form_key is empty"):
        AdminConfig.parse({"groups": [{"group": "ops"}], "allowed_origins": ["https://d.example"],
                           "form_key": UNSET}, auth)


def _signing_key():
    from forgd_verdict.dashboard.app import _require_signing_key

    with pytest.raises(ValueError, match="is not set"):
        _require_signing_key({"overrides": {"signing_key": UNSET}})


def _sink_token():
    from forgd_verdict.sink.base import SinkUnavailable
    from forgd_verdict.sink.factory import build_forwarders

    with pytest.raises(SinkUnavailable, match=re.escape(UNSET)):
        build_forwarders([{"name": "siem", "type": "otlp", "endpoint": "https://otel.example:4318",
                           "token": UNSET}], ["regex"], background=False)


def _managed_key(caplog):
    from forgd_verdict.managed.scanner import run_managed_ingest

    policy = _policy(privacy={"hash_salt": "a-salt-for-this-test"},
                     managed_agents={"workspaces": [{"key": "ws1", "label": "ws1", "api_key": UNSET}]})
    result = run_managed_ingest(policy, store=None)
    assert result["workspaces"][0]["error"] == "no api key"
    assert "managed agents workspace has no API key" in caplog.text


def _hook_token(key, capsys, monkeypatch, tmp_path):
    if key == "ship_token":
        from forgd_verdict.hook.ship import run_ship

        monkeypatch.setenv("FORGD_VERDICT_SPOOL", str(tmp_path / "spool"))
        run_ship(None, endpoint="https://intake.example/intake", token=None,
                 spool_root=str(tmp_path / "spool"))
    else:
        from forgd_verdict.hook import cli

        policy = _policy(hook={"scan_endpoint": "https://intake.example/scan", "scan_token": UNSET,
                               "project_overrides": True})
        monkeypatch.setattr(cli, "open_url", lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
        assert cli._remote_verdict(policy, {}, 10) is None
    assert f"hook.{key} resolves to nothing" in capsys.readouterr().err


# Paths that refuse to start, or report where they are read, with a check of each.
REFUSES = {
    ("privacy", "hash_salt"): _salt,
    ("server", "required_headers"): _required_header,
    ("dashboard", "admins", "form_key"): _form_key,
    ("overrides", "signing_key"): _signing_key,
    ("sinks", "token"): _sink_token,
}
REPORTED_WHERE_READ = {
    ("managed_agents", "workspaces", "api_key"): "managed",
    ("hook", "ship_token"): "hook",
    ("hook", "scan_token"): "hook",
}


def _all_paths() -> set[tuple[str, ...]]:
    return {*SECRET_PATHS, *((*p, k) for p, k in SECRET_LIST_PATHS), *SECRET_MAP_PATHS}


def test_every_credential_path_is_classified():
    classified = [*REFUSES, *REPORTED_WHERE_READ, *OPTIONAL_WHEN_UNSET]
    assert len(classified) == len(set(classified)), "a path is classified twice"
    assert set(classified) == _all_paths(), sorted(set(classified) ^ _all_paths())


@pytest.mark.parametrize("path", sorted(REFUSES), ids=".".join)
def test_an_unset_reference_refuses(path):
    REFUSES[path]()


def test_an_unset_managed_agents_key_is_reported(caplog):
    _managed_key(caplog)


@pytest.mark.parametrize("key", ["ship_token", "scan_token"])
def test_an_unset_hook_token_is_said_on_stderr(key, capsys, monkeypatch, tmp_path):
    _hook_token(key, capsys, monkeypatch, tmp_path)


def _with_unset(path: tuple[str, ...]) -> Policy:
    """A policy whose value at `path` is the unset reference."""
    *parents, key = path
    raw = default_policy().raw
    node = raw
    for part in parents[:-1]:
        node = node.setdefault(part, {})
    value = [UNSET] if key == "tokens" else UNSET
    if path in {p + (k,) for p, k in SECRET_LIST_PATHS}:
        node[parents[-1]] = [{"name": "e1", "label": "e1", key: value}]
    else:
        node.setdefault(parents[-1], {})[key] = value
    return Policy(raw=raw)


@pytest.mark.parametrize("path", sorted(OPTIONAL_WHEN_UNSET), ids=".".join)
def test_an_optional_reference_left_unset_is_logged_by_each_role_that_reads_it(path, caplog):
    roles, effect = OPTIONAL_WHEN_UNSET[path]
    policy = _with_unset(path)
    assert [ref for _, ref in unset_credentials(policy, path)] == [UNSET]
    log = logging.getLogger("forgd_verdict.test")
    for role in roles:
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="forgd_verdict.test"):
            assert warn_unset_credentials(log, policy, role)
        assert UNSET in caplog.text and effect in caplog.text, role


@pytest.mark.parametrize("role", sorted({r for roles, _ in OPTIONAL_WHEN_UNSET.values() for r in roles}))
def test_each_role_warns_at_start(role):
    calls = [p for p in SRC.rglob("*.py")
             if re.search(rf'warn_unset_credentials\([^)]*"{role}"\)', p.read_text(encoding="utf-8"))]
    assert calls, f"no warn_unset_credentials(..., {role!r}) call"


def test_a_set_or_literal_value_is_not_reported(monkeypatch):
    monkeypatch.setenv(UNSET[1:], "x" * 40)
    assert not unset_credentials(_with_unset(("server", "metrics_token")), ("server", "metrics_token"))
    policy = _with_unset(("otel", "orgs", "token"))
    policy.raw["otel"]["orgs"][0]["token"] = "a-literal"
    assert not unset_credentials(policy, ("otel", "orgs", "token"))


def test_a_fleet_with_one_token_set_is_not_reported(monkeypatch):
    """The previous token is unset outside a rotation."""
    monkeypatch.setenv("FORGD_TEST_SET_CREDENTIAL", "x" * 40)
    policy = _with_unset(("intake", "fleet", "tokens"))
    policy.raw["intake"]["fleet"][0]["tokens"] = ["$FORGD_TEST_SET_CREDENTIAL", UNSET]
    assert not unset_credentials(policy, ("intake", "fleet", "tokens"))
