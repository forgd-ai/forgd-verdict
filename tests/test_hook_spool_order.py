"""The hook's decision reaches stdout before any spool or guard work, and
nothing the spool does changes the decision or the exit code."""

from __future__ import annotations

import io
import json
import sys

import pytest
from conftest import FAKE_AWS_KEY

from forgd_verdict.hook import cli as hook_cli
from forgd_verdict.policy import _deep_merge, load_policy

PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
           "tool_use_id": "toolu_01", "session_id": "22222222-2222-2222-2222-222222222222",
           "tool_input": {"command": f"echo {FAKE_AWS_KEY}"}}


class _Stdout(io.StringIO):
    """Records what had been flushed when each flush happened."""

    def __init__(self):
        super().__init__()
        self.flushed = ""

    def flush(self):
        self.flushed = self.getvalue()
        super().flush()


@pytest.fixture
def hook(tmp_path, monkeypatch):
    raw = _deep_merge(load_policy("policy.yaml").raw, {
        "hook": {"spool": str(tmp_path / "spool"), "spool_enabled": True,
                 "scan_endpoint": "", "ship_mode": "off"}})
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(raw))
    out = _Stdout()

    def call():
        # Set here, not at fixture setup: pytest's capture replaces
        # sys.stdout again when the test body starts.
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(PAYLOAD)))
        return hook_cli.main(["--policy", str(path)])

    return call, out


def test_the_decision_is_flushed_before_the_spool_or_guard_starts(hook, monkeypatch):
    call, out = hook
    seen: list[tuple[str, str]] = []
    real_spool, real_guard = hook_cli._spool, hook_cli.MetadataGuard

    def spool(*a, **k):
        seen.append(("spool", out.flushed))
        return real_spool(*a, **k)

    def guard(*a, **k):
        seen.append(("guard", out.flushed))
        return real_guard(*a, **k)

    monkeypatch.setattr(hook_cli, "_spool", spool)
    monkeypatch.setattr(hook_cli, "MetadataGuard", guard)
    assert call() == 0
    decision = json.loads(out.getvalue())
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert [name for name, _ in seen] == ["spool", "guard"]
    assert all(flushed == out.getvalue() for _, flushed in seen)


def test_a_spool_that_raises_changes_neither_output_nor_exit_code(hook, monkeypatch):
    call, out = hook
    code = call()
    expected = out.getvalue()
    out.seek(0)
    out.truncate()

    def boom(*a, **k):
        raise RuntimeError("spool failed")

    monkeypatch.setattr(hook_cli, "_spool", boom)
    assert expected
    assert call() == code
    assert out.getvalue() == expected
