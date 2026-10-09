"""A session over MAX_SCAN_UNITS on a cold cache catches up frame by frame.

The first full scan of a long transcript cannot cover all of it. It must
still leave a high-water mark at the last whole message it scanned, so the
next frame scans only the rest and the session stops denying once the rest
fits.
"""

from __future__ import annotations

from conftest import FAKE_AWS_KEY, make_policy

from forgd_verdict.budget import Budget
from forgd_verdict.cache import InMemoryLRUCache
from forgd_verdict.core import decide, scan_frame
from forgd_verdict.extract import frame_units
from forgd_verdict.models import MAX_SCAN_UNITS, UNSCANNED_CAPPED
from forgd_verdict.policy import load_policy

PAIRS = 3_300
KEY = ("tenant", "session-cold")


def _pair(i: int, secret: str = "") -> list[dict]:
    lines = [f"{40 + i % 300}:def handler_{i}(event):",
             f"{41 + i % 300}:    return route(event, {i}){secret}",
             f"{42 + i % 300}:"]
    return [
        {"role": "assistant", "content": [{
            "type": "tool_use", "id": f"toolu_{i:05d}", "tool_name": "Bash",
            "input": {"command": f"grep -n 'handler_{i}' src/pkg/module_{i % 97}.py",
                      "description": f"Find handler {i}", "timeout": 120000}}]},
        {"role": "user", "content": [{
            "type": "tool_result", "tool_use_id": f"toolu_{i:05d}", "tool_name": "Bash",
            "content": [{"type": "text", "text": line} for line in lines]}]},
    ]


def _session(secrets: dict[int, str] | None = None) -> list[dict]:
    secrets = secrets or {}
    msgs: list[dict] = [{"role": "user", "content": "Find every handler and summarise."}]
    for i in range(PAIRS):
        msgs.extend(_pair(i, secrets.get(i, "")))
    return msgs


def _unit_count(msgs: list[dict]) -> int:
    return sum(len(frame_units(msgs[i:i + 1], i)) for i in range(len(msgs)))


def _detectors():
    return load_policy("policy.yaml").build_detectors(salt="s" * 32)


class _Session:
    def __init__(self):
        self.cache = InMemoryLRUCache(max_sessions=4, ttl_s=600)
        self.detectors = _detectors()
        self.policy = make_policy()

    def frame(self, msgs):
        result = scan_frame(msgs, frame_units, self.detectors, Budget(60_000), self.cache, KEY)
        verdict = decide(result.findings, self.policy, dropped=result.detectors_skipped)
        return result, verdict

    def mark(self) -> int:
        state = self.cache.get(KEY)
        return 0 if state is None else state.scanned_messages


def test_the_session_is_over_the_unit_cap():
    msgs = _session()
    assert frame_units(msgs).capped
    assert MAX_SCAN_UNITS < _unit_count(msgs) < 2 * MAX_SCAN_UNITS


def test_a_cold_session_over_the_cap_catches_up():
    msgs = _session()
    s = _Session()

    r1, v1 = s.frame(msgs)
    assert UNSCANNED_CAPPED in r1.detectors_skipped
    mark = s.mark()
    assert 0 < mark < len(msgs)
    assert not frame_units(msgs[:mark]).capped

    msgs.append({"role": "user", "content": "Thanks, now write it up."})
    r2, v2 = s.frame(msgs)
    assert r2.cache_hit
    assert r2.detectors_skipped == []
    assert v2.action == "allow"
    assert s.mark() == len(msgs)

    actions = [v1.action, v2.action]
    for n in range(3):
        msgs.append({"role": "assistant", "content": f"Section {n} is done."})
        r, v = s.frame(msgs)
        assert r.cache_hit and r.detectors_skipped == []
        actions.append(v.action)
    assert actions[1:] == ["allow"] * 4
    assert actions.count("deny") <= 1


def test_secrets_either_side_of_the_mark_are_reported():
    early, late = 2, PAIRS - 1
    msgs = _session({early: f" key={FAKE_AWS_KEY}", late: f" key={FAKE_AWS_KEY}"})
    early_at, late_at = f"msg[{2 + 2 * early}]", f"msg[{2 + 2 * late}]"
    s = _Session()

    r1, _ = s.frame(msgs)
    mark = s.mark()
    assert 2 + 2 * early < mark <= 2 + 2 * late
    assert any(f.locator.startswith(early_at) for f in r1.findings
               if f.detector == "regex:aws-access-key")

    msgs.append({"role": "user", "content": "And the summary?"})
    r2, v2 = s.frame(msgs)
    assert r2.cache_hit
    found = {f.locator.split(".")[0] for f in r2.findings if f.detector == "regex:aws-access-key"}
    assert {early_at, late_at} <= found
    assert v2.action == "deny"


def test_one_message_over_the_cap_is_not_advanced_past():
    msgs = _session()[:21]
    giant_at = len(msgs)
    msgs.append({"role": "user", "content": [{
        "type": "tool_result", "tool_use_id": "toolu_big", "tool_name": "Bash",
        "content": [{"type": "text", "text": f"row {i}"} for i in range(MAX_SCAN_UNITS + 10)]}]})
    msgs.append({"role": "assistant", "content": "That output was long."})
    s = _Session()

    for n in range(3):
        r, v = s.frame(msgs)
        assert UNSCANNED_CAPPED in r.detectors_skipped
        assert v.action == "deny"
        assert s.mark() <= giant_at
        msgs.append({"role": "user", "content": f"Try again {n}."})
