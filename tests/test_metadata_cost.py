"""The metadata guard's cost: which detectors it runs, and whose budget pays."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from conftest import FAKE_AWS_KEY, WHSEC, frame, make_policy, sign

from forgd_verdict.detectors import GitleaksDetector
from forgd_verdict.detectors.base import TIER_T0, TIER_T1
from forgd_verdict.metadata import MetadataGuard, guard_detectors
from forgd_verdict.policy import load_policy
from forgd_verdict.store.local import LocalFileStore

BUDGET_MS = 200


class _CountsTheGuard:
    """A T0 that counts the calls made with the guard's numbered units.
    Given to the guard only, not to the request's scan."""

    name = "guard-counter"
    tier = TIER_T0
    severity = "warn"

    def __init__(self):
        self.guard_calls = 0

    def available(self) -> bool:
        return True

    def scan(self, units):
        units = list(units)
        if units and all(u.locator.isdigit() for u in units):
            self.guard_calls += 1
        return []


class _Refuses:
    """Any detector the guard must not call."""

    severity = "block"

    def __init__(self, name, tier, uses_daemon=False):
        self.name, self.tier, self.uses_daemon = name, tier, uses_daemon
        self.calls = 0

    def available(self) -> bool:
        return True

    def scan(self, units):
        self.calls += 1
        return []


def test_gitleaks_as_a_subprocess_is_not_a_guard_detector():
    gl = GitleaksDetector("block", "s")
    assert not gl.uses_daemon
    assert gl not in guard_detectors([gl])


def test_gitleaks_through_its_daemon_is_a_guard_detector():
    gl = GitleaksDetector("block", "s", daemon="gl.sock")
    assert gl.uses_daemon
    assert guard_detectors([gl]) == [gl]


def test_the_guard_does_not_call_a_subprocess_t1_or_a_t2():
    t1 = _Refuses("gitleaks", TIER_T1)
    t2 = _Refuses("presidio", 2, uses_daemon=True)
    daemon = _Refuses("gitleaks-daemon", TIER_T1, uses_daemon=True)
    guard = MetadataGuard([t1, t2, daemon], "s")
    guard.clean({"request_id": "req_1", "model": "claude-opus-5"})
    assert t1.calls == 0 and t2.calls == 0
    assert daemon.calls == 1


def test_the_shipped_policy_without_a_daemon_guards_with_t0_only():
    detectors = load_policy("policy.yaml").build_detectors()
    assert {d.tier for d in guard_detectors(detectors)} == {TIER_T0}


async def _post(app, raw: bytes, headers: dict,
                observe: Callable[[], int]) -> tuple[int, dict, int]:
    """(status, body, `observe()` when the response body was sent)."""
    scope = {"type": "http", "method": "POST", "path": "/hook", "query_string": b"",
             "headers": [(k.lower().encode(), str(v).encode()) for k, v in headers.items()]}
    sent: dict = {}
    done = {"v": False}

    async def receive():
        if done["v"]:
            return {"type": "http.disconnect"}
        done["v"] = True
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            sent["status"] = message["status"]
        elif message["type"] == "http.response.body" and "at" not in sent:
            sent["at"] = observe()
            sent["body"] = json.loads(message["body"] or b"{}")

    await app(scope, receive, send)
    return sent["status"], sent["body"], sent["at"]


@pytest.mark.parametrize("frame_type", ["prompt", "completion"])
async def test_a_slow_guard_does_not_delay_the_verdict(frame_type, tmp_path):
    from forgd_verdict.server.app import VerdictServer

    server = VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "budget_ms": BUDGET_MS},
    ), store=LocalFileStore(tmp_path / "store", instance="t"))
    counter = _CountsTheGuard()
    server.meta = MetadataGuard([*server.detectors, counter], server.policy.hash_salt)
    try:
        raw = json.dumps(frame(type=frame_type, messages=[
            {"role": "user", "content": [{"type": "text", "text": f"use {FAKE_AWS_KEY}"}]}],
        )).encode()
        status, body, before = await _post(
            server, raw, sign(raw), lambda: counter.guard_calls)
    finally:
        server.close()
    assert status == 200 and body["action"] == "deny"
    assert before == 0, "the guard ran before the response was sent"
    # The guard still ran, after the response.
    assert counter.guard_calls >= 1
