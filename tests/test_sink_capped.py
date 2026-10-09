"""A group whose scan hit a cap is forwarded with every scanned value
masked whole.

Over MAX_SCAN_UNITS some units were never scanned, and over
MAX_SCAN_FINDINGS some findings were dropped, so the findings the sink is
handed may be missing a match in any value of the group.
"""

from __future__ import annotations

import json
import textwrap

from conftest import ASGIClient, make_policy

from forgd_verdict import core
from forgd_verdict.core import decide
from forgd_verdict.models import FINDINGS_CAPPED, UNSCANNED, UNSCANNED_CAPPED
from forgd_verdict.otel.app import Collector
from forgd_verdict.policy import load_policy
from forgd_verdict.sink.fake import FakeSink

ORG = "00000000-0000-0000-0000-00000000000a"
TOKEN = "prod-token-long-enough-to-be-one"
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _aws_key(i: int) -> str:
    return "AKIA" + "".join(_B32[(i >> (5 * j)) & 31] for j in range(16))


def _app(tmp_path, redact: str = ""):
    redact_line = f"redact: {redact}" if redact else ""
    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: test-salt}}
        server: {{store: ""}}
        detectors: {{gitleaks: {{enabled: false}}}}
        otel:
          orgs:
            - {{label: prod, id: "{ORG}", token: {TOKEN}}}
        sinks:
          - name: siem
            type: otlp
            endpoint: https://collector.test
            {redact_line}
    """), encoding="utf-8")
    app = Collector(load_policy(str(pol)), store=None, late_detectors=[])
    for fwd in app.forwarders:
        fwd.pipeline.sink = FakeSink(max_events=1000, max_bytes=10_000_000)
    return app


def _body(prompts: list[str]) -> bytes:
    """One turn: a log record per prompt, all with the same prompt.id."""
    return json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
        "attributes": [
            {"key": "event.name", "value": {"stringValue": "claude_code.user_prompt"}},
            {"key": "prompt.id", "value": {"stringValue": "p1"}},
            {"key": "prompt", "value": {"stringValue": p}},
        ]} for p in prompts]}]}]}).encode()


async def _forwarded(app, prompts: list[str]) -> str:
    status, _ = await ASGIClient(app).post(
        "/v1/logs", _body(prompts),
        {"authorization": f"Bearer {TOKEN}", "content-type": "application/json"})
    assert status == 200
    fwd = app.forwarders[0]
    fwd.pipeline.flush()
    events = [e for b in fwd.pipeline.sink.batches for e in b]
    assert events
    return json.dumps([e.attributes for e in events])


async def test_a_value_in_a_unit_over_the_cap_is_not_forwarded(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "MAX_SCAN_UNITS", 10)
    secret = _aws_key(1)
    # The earliest unit is the one the cap drops.
    prompts = [f"deploy with {secret} now"] + [f"ordinary prompt {i}" for i in range(20)]
    app = _app(tmp_path)
    try:
        out = await _forwarded(app, prompts)
    finally:
        app.close()
    assert secret not in out
    assert "ordinary prompt" not in out


async def test_a_value_whose_finding_was_over_the_cap_is_not_forwarded(
        tmp_path, monkeypatch):
    monkeypatch.setattr(core, "MAX_SCAN_FINDINGS", 5)
    secret = _aws_key(99)
    prompts = [" ".join(_aws_key(i) for i in range(10)), f"later {secret} here"]
    # Only the tier that found the keys, so no skipped tier masks the group.
    app = _app(tmp_path, redact="[regex]")
    try:
        out = await _forwarded(app, prompts)
    finally:
        app.close()
    assert secret not in out


async def test_one_oversize_value_does_not_mask_the_rest(tmp_path, monkeypatch):
    # The truncated-tail marker masks only its own value.
    monkeypatch.setattr("forgd_verdict.otel.extract.MAX_UNIT_BYTES", 64)
    app = _app(tmp_path)
    try:
        out = await _forwarded(app, ["x" * 200, "an ordinary prompt here"])
    finally:
        app.close()
    assert "an ordinary prompt here" in out


def test_decide_treats_the_cap_marker_as_unscanned():
    deny = make_policy(server={"on_tier_dropped": "deny"})
    for marker in (UNSCANNED, UNSCANNED_CAPPED):
        verdict = decide([], deny, dropped=[marker])
        assert verdict.action == "deny"
        assert "size limit" in verdict.deny_reason
    for marker in (UNSCANNED, UNSCANNED_CAPPED):
        assert decide([], make_policy(), dropped=[marker]).action == "deny"


def test_a_capped_scan_is_counted_as_oversize_not_as_a_dropped_tier():
    from test_store import rec

    from forgd_verdict.store.base import SOURCE_INFERENCE_HOOK
    from forgd_verdict.store.query import build_summary

    capped = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    capped.tiers_dropped = [UNSCANNED_CAPPED]
    s = build_summary([capped])
    assert s.tiers_dropped == 0
    assert s.oversize_unscanned == 1


def test_a_findings_capped_scan_is_counted_as_neither_a_dropped_tier_nor_oversize():
    from test_store import rec

    from forgd_verdict.store.base import SOURCE_INFERENCE_HOOK
    from forgd_verdict.store.query import build_summary

    capped = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    capped.tiers_dropped = [FINDINGS_CAPPED]
    s = build_summary([capped])
    assert s.tiers_dropped == 0
    assert s.oversize_unscanned == 0
