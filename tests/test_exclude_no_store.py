"""`exclude` and `reset-stats` refuse when no store is named, and find one that is."""

from __future__ import annotations

import json

import pytest
from conftest import OVERRIDES_PUBLIC_TEXT

from forgd_verdict import cli
from forgd_verdict.overrides import reader_for
from forgd_verdict.store import LocalFileStore

ADMINS = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
          "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}
NO_STORE = ("no store configured: pass --store, set server.store, or export "
            "FORGD_VERDICT_STORE")
ARGVS = pytest.mark.parametrize("argv", [
    ["exclude", "--list"], ["exclude", "--request-id", "req-x"], ["exclude", "--clear"],
], ids=["list", "request-id", "clear"])


@pytest.fixture
def no_store_env(monkeypatch, tmp_path):
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)


def _policy(tmp_path, raw):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(raw))
    return str(path)


def _excluded_off(root):
    return LocalFileStore(root, instance="t").get_excluded()


def _excluded_on(root, policy_path):
    from forgd_verdict.policy import load_policy

    reader = reader_for(load_policy(policy_path).raw, LocalFileStore(root, instance="t"), "cli")
    return set(reader.excluded())


@ARGVS
def test_with_overrides_off_exclude_refuses_without_a_store(no_store_env, tmp_path, capsys, argv):
    assert cli.main(["--policy", _policy(tmp_path, {}), *argv]) == 2
    assert NO_STORE in capsys.readouterr().err
    assert not (tmp_path / "findings").exists()


@pytest.mark.usefixtures("control_identity", "signing_env")
@ARGVS
def test_with_overrides_on_exclude_refuses_without_a_store(no_store_env, tmp_path, capsys, argv):
    assert cli.main(["--policy", _policy(tmp_path, ADMINS), *argv]) == 2
    assert NO_STORE in capsys.readouterr().err
    assert not (tmp_path / "findings").exists()


def test_with_overrides_off_reset_stats_refuses_with_the_same_message(no_store_env, tmp_path,
                                                                      capsys):
    assert cli.main(["--policy", _policy(tmp_path, {}), "reset-stats"]) == 2
    assert NO_STORE in capsys.readouterr().err


def test_with_overrides_off_exclude_uses_the_policy_store(no_store_env, tmp_path):
    store = tmp_path / "real"
    policy = _policy(tmp_path, {"server": {"store": str(store)}})
    assert cli.main(["--policy", policy, "exclude", "--request-id", "req-x"]) == 0
    assert _excluded_off(store) == {"req-x"}
    assert not (tmp_path / "findings").exists()


def test_with_overrides_off_exclude_uses_the_store_variable(no_store_env, tmp_path, monkeypatch):
    store = tmp_path / "real"
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(store))
    assert cli.main(["--policy", _policy(tmp_path, {}), "exclude", "--request-id", "req-x"]) == 0
    assert _excluded_off(store) == {"req-x"}
    assert not (tmp_path / "findings").exists()


def test_with_overrides_off_store_flag_beats_the_policy_store(no_store_env, tmp_path):
    flag, configured = tmp_path / "flag", tmp_path / "configured"
    policy = _policy(tmp_path, {"server": {"store": str(configured)}})
    assert cli.main(["--policy", policy, "exclude", "--store", str(flag),
                     "--request-id", "req-x"]) == 0
    assert _excluded_off(flag) == {"req-x"}
    assert _excluded_off(configured) == set()


@pytest.mark.usefixtures("control_identity", "signing_env")
@pytest.mark.parametrize("source", ["policy", "variable"])
def test_with_overrides_on_exclude_finds_a_configured_store(no_store_env, tmp_path, monkeypatch,
                                                           source):
    store = tmp_path / "real"
    raw = dict(ADMINS)
    if source == "policy":
        raw["server"] = {"store": str(store)}
    else:
        monkeypatch.setenv("FORGD_VERDICT_STORE", str(store))
    policy = _policy(tmp_path, raw)
    assert cli.main(["--policy", policy, "overrides", "init"]) == 0
    assert cli.main(["--policy", policy, "exclude", "--request-id", "req-x"]) == 0
    assert "req-x" in _excluded_on(store, policy)
    assert not (tmp_path / "findings").exists()
