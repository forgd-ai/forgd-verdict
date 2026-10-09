"""The CLI's reads of the object verify records as `overrides show` does,
and a service that honours runtime overrides with no store is not ready.

Each test names the mutation that makes it fail.
"""

from __future__ import annotations

import argparse
import json
import logging

import pytest
from conftest import DETECTORS, OVERRIDES_KEY, OVERRIDES_PUBLIC_TEXT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forgd_verdict import cli
from forgd_verdict.overrides import (
    ACTION_EXCLUDE,
    ACTION_INIT,
    ACTION_MIGRATE,
    ERROR_NO_STORE,
    Change,
    apply_change,
    cold,
    reader_for,
    readiness,
)
from forgd_verdict.store import LocalFileStore

ADMINS = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
          "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}
ACTOR = {"issuer": "cli", "subject": "t", "name": "t", "verified": False}
ROGUE = Ed25519PrivateKey.generate()

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")


def _policy(tmp_path):
    path = tmp_path / "admins.json"
    path.write_text(json.dumps(ADMINS))
    return path


def _main(tmp_path, *argv):
    return cli.main(["--policy", str(_policy(tmp_path)), *argv])


def _rogue_store(tmp_path, change):
    """A store initialized with this run's key, then changed by `change`
    signed with a key no verify key lists."""
    store = LocalFileStore(tmp_path / "s", instance="t")
    apply_change(store, ACTOR, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    if change.action == ACTION_MIGRATE:
        store.set_excluded(["req_legacy"])
        apply_change(store, ACTOR, change, migrate=(None, frozenset(store.get_excluded())),
                     detectors=DETECTORS, signing_key=ROGUE)
    else:
        apply_change(store, ACTOR, change, detectors=DETECTORS, signing_key=ROGUE)
    return store


def test_exclude_list_verifies_the_object(tmp_path, capsys):
    """An exclusion under a record no verify key signed is not listed.
    Mutation: read with a RuntimeOverrides that has no verify keys."""
    store = _rogue_store(tmp_path, Change(ACTION_EXCLUDE, value="req_rogue"))
    assert _main(tmp_path, "exclude", "--store", str(store.root), "--list") == 0
    assert "0 frame(s) with findings; 0 excluded" in capsys.readouterr().out


@pytest.mark.parametrize("argv, warning", [
    (("exclude", "--clear"), "markers/excluded_requests object still apply"),
    (("reset-stats", "--clear"), "markers/stats_reset object still applies"),
], ids=["exclude", "reset-stats"])
def test_the_legacy_warnings_verify_the_object(tmp_path, capsys, monkeypatch, argv, warning):
    """A retirement under a record no verify key signed does not silence the
    warning. The change itself is stubbed: it verifies with the same keys
    and would refuse this object first. Mutation: read with a
    RuntimeOverrides that has no verify keys, at either call site."""
    store = _rogue_store(tmp_path, Change(ACTION_MIGRATE))
    store.set_excluded(["req_legacy"])
    store.set_reset_marker("2026-09-01T00:00:00Z")
    monkeypatch.setattr(cli, "_change", lambda *a, **k: (0, None))
    assert _main(tmp_path, argv[0], "--store", str(store.root), *argv[1:]) == 0
    assert warning in capsys.readouterr().err


def test_the_cli_reader_carries_the_policy_keys(tmp_path):
    """Mutation: build _cli_reader without _show_keys."""
    args = argparse.Namespace(policy=str(_policy(tmp_path)))
    reader = cli._cli_reader(args, LocalFileStore(tmp_path / "s"))
    assert reader.verify_keys is not None and len(reader.verify_keys) == 1
    assert reader.key_error is None


# -- no store --------------------------------------------------------------


@pytest.mark.parametrize("role", ["verdict", "collector", "intake", "ingest", "connector",
                                  "dashboard"])
def test_honoured_with_no_store_is_an_error_and_not_ready(role, caplog, monkeypatch):
    """Mutation: let reader_for build a reader with no store as before,
    which is ready on the baseline."""
    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    reader = reader_for(ADMINS, None, role)
    with caplog.at_level(logging.ERROR, logger="forgd_verdict.overrides"):
        snap = reader.refresh()
    assert (snap.ready, snap.error, snap.in_error) == (False, ERROR_NO_STORE, True)
    assert readiness(reader) == (503, {"status": "not_ready",
                                       "reason": "runtime overrides have no store to read",
                                       "runtime_overrides": "disabled"})
    assert cold(reader) == "runtime overrides have no store to read"
    assert any(r.levelno == logging.ERROR and "no store" in r.getMessage()
               for r in caplog.records)


def test_off_with_no_store_is_ready(monkeypatch):
    """Mutation: mark a reader with no store not ready whatever the policy."""
    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    reader = reader_for({}, None, "verdict")
    assert reader.refresh().ready and cold(reader) is None


def test_the_verdict_server_with_no_store_is_not_ready(tmp_path, monkeypatch):
    """Mutation: let cold() ignore a reader with no store."""
    from conftest import WHSEC, make_policy

    from forgd_verdict.server.app import VerdictServer

    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    server = VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": None}, **ADMINS))
    try:
        assert server.overrides.no_store
        assert cold(server.overrides) == "runtime overrides have no store to read"
    finally:
        server.close()
