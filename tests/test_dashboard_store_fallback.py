"""The dashboard warns when it falls back to ./findings."""

from __future__ import annotations

import logging
import os
import subprocess
import sys

import pytest

from forgd_verdict.dashboard.app import create_app
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge

WARNING = "dashboard has no findings store;"


@pytest.fixture
def no_store_env(monkeypatch, tmp_path):
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)


def _warnings(caplog, **kw):
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.dashboard"):
        create_app(**kw)
    return [r for r in caplog.records if WARNING in r.getMessage()]


def _policy_with_store(monkeypatch, store):
    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {"server": {"store": store}}))
    monkeypatch.setattr("forgd_verdict.policy.load_policy", lambda *a, **k: policy)


def test_falling_back_to_local_findings_warns(caplog, no_store_env, tmp_path):
    [record] = _warnings(caplog)
    assert str(tmp_path / "findings") in record.getMessage()
    assert record.fields["path"] == str(tmp_path / "findings")
    assert "--store" in record.fields["remediation"]
    assert "FORGD_VERDICT_STORE" in record.fields["remediation"]


def test_the_warning_says_when_the_directory_was_just_created(caplog, no_store_env, tmp_path):
    [record] = _warnings(caplog)
    assert "will be created" in record.getMessage()

    [record] = _warnings(caplog)
    assert "created" not in record.getMessage()


def test_the_warning_names_a_policy_store_it_ignores(caplog, no_store_env, monkeypatch):
    # The value can be a URL; the warning names the key, never the value.
    _policy_with_store(monkeypatch, "https://example.invalid/findings")
    [record] = _warnings(caplog)
    assert "server.store" in record.getMessage()
    assert "example.invalid" not in record.getMessage()
    assert "example.invalid" not in repr(record.fields)


def test_an_ignored_policy_store_is_named_when_findings_already_exists(
        caplog, no_store_env, monkeypatch, tmp_path):
    (tmp_path / "findings").mkdir()
    _policy_with_store(monkeypatch, "https://example.invalid/findings")
    [record] = _warnings(caplog)
    assert "The policy sets server.store" in record.getMessage()
    assert "created" not in record.getMessage()


def test_an_empty_store_variable_falls_back_and_warns(caplog, no_store_env, monkeypatch):
    monkeypatch.setenv("FORGD_VERDICT_STORE", "")
    assert len(_warnings(caplog)) == 1


def test_without_a_policy_store_the_warning_does_not_mention_one(caplog, no_store_env):
    [record] = _warnings(caplog)
    assert "server.store" not in record.getMessage()


def test_a_store_argument_does_not_warn(caplog, no_store_env, tmp_path):
    assert _warnings(caplog, store_spec=str(tmp_path / "s")) == []


def test_the_store_variable_does_not_warn(caplog, no_store_env, monkeypatch, tmp_path):
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "s"))
    assert _warnings(caplog) == []


def test_a_render_with_no_store_prints_the_warning(tmp_path):
    # A subprocess: under pytest the root logger has a handler, so the
    # last-resort stderr handler a real run relies on never fires.
    env = {k: v for k, v in os.environ.items() if not k.startswith("FORGD_")}
    out = subprocess.run(
        [sys.executable, "-m", "forgd_verdict.dashboard", "--render", "out.html"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert WARNING in out.stderr
