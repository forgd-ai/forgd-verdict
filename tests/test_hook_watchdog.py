"""`hook.watchdog_ms`: the hook decides before Claude Code's timeout.

Claude Code kills a hook that outlives its `timeout` (10 s for the scan
hooks in every shipped fragment) and lets the prompt through unscanned.
Each test runs the hook in a process whose T0 scan, or policy load, never
returns."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

PROBE = "AKIAQYLPMN5HGZTHX4UQ"  # gitleaks:allow
PROMPT = json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "s",
                     "prompt": f"key {PROBE}"})
DEADLINE_MS = 1000
SLACK_S = 4.0
# A run that never decides is stopped here, so a missing watchdog fails the
# test rather than hanging the suite.
STOP_S = 20

HANG_T0 = """
import threading
from forgd_verdict.detectors import t0_regex
t0_regex.T0RegexDetector.scan = lambda self, units: threading.Event().wait()
"""
# `_sre` never releases the GIL, so a thread that has to take it to fire
# waits as long as the match does: about 2**40 steps here.
HANG_GIL = """
import re
from forgd_verdict.detectors import t0_regex
t0_regex.T0RegexDetector.scan = lambda self, units: re.match(r"(a+)+$", "a" * 40 + "b")
"""
GIL_BUDGET_S = 3.0
# SIGALRM is raised while `deliver` is writing the decision to stdout, so
# the expiry handler runs with the watchdog's lock held by the thread it
# interrupted.
ALARM_IN_DELIVER = """
import signal, sys

class _AlarmOnDecision:
    def __init__(self, inner):
        self._inner = inner
    def write(self, text):
        if '"decision"' in text:
            signal.raise_signal(signal.SIGALRM)
        return self._inner.write(text)
    def __getattr__(self, name):
        return getattr(self._inner, name)

sys.stdout = _AlarmOnDecision(sys.stdout)
"""
HANG_LOAD = f"""
import threading
from forgd_verdict import policy
from forgd_verdict.hook import cli
policy.DEFAULT_POLICY["hook"]["watchdog_ms"] = {DEADLINE_MS}
cli.load_policy = lambda *a, **k: threading.Event().wait()
"""
MAIN = """
import sys
from forgd_verdict.hook.cli import main
sys.exit(main(sys.argv[1:]))
"""


def _policy(tmp_path: Path, on_error: str, **hook) -> str:
    path = tmp_path / "etc" / "policy.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({
        "detectors": {"gitleaks": {"enabled": False}},
        "hook": {"on_error": on_error, "ship_mode": "off", "watchdog_ms": DEADLINE_MS,
                 **hook}}))
    return str(path)


def _run(tmp_path: Path, prelude: str, on_error: str, **hook):
    argv = [sys.executable, "-I", "-c", prelude + MAIN,
            "--policy", _policy(tmp_path, on_error, **hook),
            "--spool", str(tmp_path / "state" / "spool")]
    started = time.monotonic()
    try:
        done = subprocess.run(argv, input=PROMPT, capture_output=True, text=True,
                              timeout=STOP_S, env={**os.environ})
    except subprocess.TimeoutExpired:
        pytest.fail(f"the hook was still running after {STOP_S} s")
    return done, time.monotonic() - started


def _spooled(tmp_path: Path) -> list[str]:
    spool = tmp_path / "state" / "spool"
    return [p.read_text() for p in spool.rglob("*") if p.is_file()] if spool.exists() else []


def test_a_hung_scan_under_on_error_block_blocks_before_the_deadline(tmp_path):
    done, took = _run(tmp_path, HANG_T0, "block")
    assert took < DEADLINE_MS / 1000 + SLACK_S
    assert done.returncode == 2, done.stderr
    assert done.stdout == ""
    assert "did not finish" in done.stderr
    assert PROBE not in done.stdout + done.stderr


def test_a_hung_scan_under_on_error_allow_says_so_in_the_session(tmp_path):
    done, took = _run(tmp_path, HANG_T0, "allow")
    assert took < DEADLINE_MS / 1000 + SLACK_S
    assert done.returncode == 0, done.stderr
    body = json.loads(done.stdout)
    assert "decision" not in body
    assert "did not finish" in body["systemMessage"]
    assert PROBE not in done.stdout + done.stderr


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="SIGALRM")
def test_a_scan_holding_the_gil_under_on_error_block_blocks_before_the_deadline(tmp_path):
    done, took = _run(tmp_path, HANG_GIL, "block")
    assert took < GIL_BUDGET_S
    assert done.returncode == 2, done.stderr
    assert done.stdout == ""
    assert "did not finish" in done.stderr
    assert PROBE not in done.stdout + done.stderr


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="SIGALRM")
def test_a_scan_holding_the_gil_under_on_error_allow_says_so_in_the_session(tmp_path):
    done, took = _run(tmp_path, HANG_GIL, "allow")
    assert took < GIL_BUDGET_S
    assert done.returncode == 0, done.stderr
    body = json.loads(done.stdout)
    assert "decision" not in body
    assert "did not finish" in body["systemMessage"]
    assert PROBE not in done.stdout + done.stderr


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="SIGALRM")
def test_an_expiry_while_the_decision_is_written_leaves_the_decision(tmp_path):
    done, took = _run(tmp_path, ALARM_IN_DELIVER, "block")
    assert took < GIL_BUDGET_S
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["decision"] == "block"
    assert "did not finish" not in done.stdout + done.stderr


def test_a_hung_scan_spools_nothing(tmp_path):
    _run(tmp_path, HANG_T0, "block")
    assert _spooled(tmp_path) == []


def test_a_hung_policy_load_counts_against_the_deadline(tmp_path):
    done, took = _run(tmp_path, HANG_LOAD, "block")
    assert took < DEADLINE_MS / 1000 + SLACK_S
    assert done.returncode == 2, done.stderr
    assert "did not finish" in done.stderr
    assert PROBE not in done.stdout + done.stderr


def test_a_scan_that_finishes_in_time_is_unchanged(tmp_path):
    done, _took = _run(tmp_path, "", "block")
    assert done.returncode == 0, done.stderr
    body = json.loads(done.stdout)
    assert body["decision"] == "block"
    assert "did not finish" not in done.stdout + done.stderr
    assert "systemMessage" not in body
    assert PROBE not in done.stdout + done.stderr
    assert _spooled(tmp_path)


@pytest.mark.parametrize("value", [0, -1, 10000, 20000, "8000", True, 1.5])
def test_a_watchdog_at_or_past_claude_codes_timeout_is_refused(tmp_path, value):
    from forgd_verdict.policy import load_policy

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"hook": {"watchdog_ms": value}}))
    with pytest.raises(ValueError, match="watchdog_ms") as exc:
        load_policy(str(path), for_hook=True)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 10000:
        assert "Claude Code" in str(exc.value)


def test_the_default_watchdog_leaves_room_under_the_hook_timeout():
    from forgd_verdict.policy import DEFAULT_POLICY, ENV_OVERRIDES

    assert DEFAULT_POLICY["hook"]["watchdog_ms"] == 8000
    assert not [n for n, (path, _c) in ENV_OVERRIDES.items() if path == ("hook", "watchdog_ms")]


def test_the_session_end_drain_is_not_cut_short(tmp_path):
    """SessionEnd decides nothing and runs async under its own longer
    timeout; the drain it starts may outlast the watchdog."""
    marker = tmp_path / "drained"
    prelude = f"""
import time
from forgd_verdict.hook import ship
def slow(policy, **kw):
    time.sleep({DEADLINE_MS / 1000 * 2})
    open({str(marker)!r}, "w").write("done")
ship.run_ship = slow
"""
    argv = [sys.executable, "-I", "-c", prelude + MAIN,
            "--policy", _policy(tmp_path, "block", ship_mode="on"),
            "--spool", str(tmp_path / "state" / "spool")]
    done = subprocess.run(argv, input=json.dumps({"hook_event_name": "SessionEnd"}),
                          capture_output=True, text=True, timeout=STOP_S)
    assert done.returncode == 0, done.stderr
    assert marker.read_text() == "done"
    assert "did not finish" not in done.stderr
