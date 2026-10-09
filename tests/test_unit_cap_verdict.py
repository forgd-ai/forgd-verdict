"""`unscanned:capped` denies whenever the policy has a blocking detector,
whatever `server.on_tier_dropped` says. `findings:capped` decides nothing."""

from __future__ import annotations

import json

import pytest
from conftest import FAKE_AWS_KEY, WHSEC, ASGIClient, frame, make_policy, sign

from forgd_verdict.core import MAX_SCAN_FINDINGS, decide, scan
from forgd_verdict.extract import frame_units
from forgd_verdict.models import (
    FINDINGS_CAPPED,
    MAX_SCAN_UNITS,
    UNSCANNED,
    UNSCANNED_CAPPED,
    Finding,
    ScanUnit,
)
from forgd_verdict.otel.collect import collect
from forgd_verdict.otel.extract import records_units
from forgd_verdict.otel.payload import decode
from forgd_verdict.policy import Policy, load_policy


def _evicting_messages(first: str = f"key {FAKE_AWS_KEY}") -> list[dict]:
    """`first`, then a tool_result of MAX_SCAN_UNITS + 1 numbers (about 60 KB
    as JSON) that pushes it out of a scan of the last units."""
    return [
        {"role": "user", "content": [{"type": "text", "text": first}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1",
                                      "content": [0] * (MAX_SCAN_UNITS + 1)}]},
    ]


def _shipped(**server) -> Policy:
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["server"].update(server)
    return Policy(raw=raw)


def _no_blocking(policy: Policy) -> Policy:
    raw = json.loads(json.dumps(policy.raw, default=str))
    for config in raw["detectors"].values():
        if isinstance(config, dict):
            config["severity"] = "warn"
    return Policy(raw=raw)


def _detectors(policy: Policy) -> list:
    return [d for d in policy.build_detectors() if d.name != "gitleaks"]


def _warn(detector: str) -> Finding:
    return Finding(detector=detector, severity="warn", locator="x",
                   excerpt_hash="h")


def test_the_shipped_policy_allows_on_a_dropped_tier():
    assert _shipped().on_tier_dropped == "allow"


def test_a_key_evicted_by_the_unit_cap_denies_under_the_shipped_policy():
    policy = _shipped()
    result = scan(frame_units(_evicting_messages()), _detectors(policy))
    assert UNSCANNED_CAPPED in result.detectors_skipped
    assert not result.findings
    verdict = decide(result.findings, policy, dropped=result.detectors_skipped)
    assert verdict.action == "deny"
    assert "size limit" in verdict.deny_reason


def test_the_cap_allows_when_no_detector_blocks():
    policy = _no_blocking(_shipped())
    assert decide([], policy, dropped=[UNSCANNED_CAPPED]).action == "allow"
    assert decide([], _no_blocking(_shipped(on_tier_dropped="deny")),
                  dropped=[UNSCANNED_CAPPED]).action == "allow"


def test_a_blocking_finding_under_the_cap_is_reported_as_itself():
    policy = _shipped()
    key = scan(frame_units([{"role": "user", "content": [
        {"type": "text", "text": f"key {FAKE_AWS_KEY}"}]}]), _detectors(policy))
    verdict = decide(key.findings, policy, dropped=[UNSCANNED_CAPPED])
    assert verdict.action == "deny"
    assert "AWS" in verdict.deny_reason


def test_the_unit_cap_denies_with_only_warn_findings():
    verdict = decide([_warn("email")], _shipped(), dropped=[UNSCANNED_CAPPED])
    assert verdict.action == "deny"


def test_an_oversize_value_denies_under_either_on_tier_dropped():
    assert decide([], _shipped(), dropped=[UNSCANNED]).action == "deny"
    assert decide([], _shipped(on_tier_dropped="deny"), dropped=[UNSCANNED]).action == "deny"


@pytest.mark.parametrize("first,reason", [
    (f"key {FAKE_AWS_KEY}", "AWS"),
    ("nothing sensitive here", "size limit"),
])
async def test_the_server_denies_a_frame_over_the_unit_cap(tmp_path, first, reason):
    """A cold frame scans the whole messages that fit from the start, so a
    key ahead of the oversized message is found and named; with no key the
    deny is for the cap."""
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "on_tier_dropped": "allow",
                "csv_path": str(tmp_path / "t.csv")},
    )
    from forgd_verdict.server.app import VerdictServer

    server = VerdictServer(policy)
    rows = []
    server.sink.submit = lambda row, findings: rows.append(row)
    raw = json.dumps(frame(_evicting_messages(first))).encode()
    try:
        status, body = await ASGIClient(server).post("/hook", raw, sign(raw))
    finally:
        server.close()
    assert status == 200
    assert body["action"] == "deny"
    assert reason in body["deny_reason"]
    assert FAKE_AWS_KEY not in json.dumps(body)
    assert UNSCANNED_CAPPED in rows[0]["tiers_dropped"]


def _capped_otel_records() -> list:
    """One log record whose MAX_SCAN_UNITS + 1 short attributes cap the
    collector's scan of it."""
    from test_otel_payload import RESOURCE, logs_json

    attributes = {"event.name": "claude_code.user_prompt", "session.id": "s",
                  "prompt": f"key {FAKE_AWS_KEY}"}
    attributes.update({f"f{i}": "abcdefgh" for i in range(MAX_SCAN_UNITS + 1)})
    body = logs_json([{"attributes": attributes, "body": ""}], RESOURCE)
    return decode(body, "application/json", "logs")


def test_the_collector_records_a_capped_turn_as_a_deny_under_the_shipped_policy():
    records = _capped_otel_records()
    assert records_units(records).capped
    policy = _shipped().for_profile("otel")
    assert policy.on_tier_dropped == "allow"
    (rec,), _ = collect(records, _detectors(policy), budget_ms=1000, policy=policy)
    assert UNSCANNED_CAPPED in rec.tiers_dropped
    assert rec.action == "deny"


def test_the_collector_keeps_a_known_content_key_under_the_unit_cap():
    records = _capped_otel_records()
    units = records_units(records)
    assert units.capped
    assert len(units) == MAX_SCAN_UNITS
    assert any(FAKE_AWS_KEY in u.text for u in units)
    policy = _shipped().for_profile("otel")
    (rec,), _ = collect(records, _detectors(policy), budget_ms=1000, policy=policy)
    assert rec.action == "deny"
    assert rec.findings_count >= 1
    assert "regex:aws-access-key" in [f.detector for f in rec.findings]
    assert FAKE_AWS_KEY not in json.dumps([f.__dict__ for f in rec.findings], default=str)


def test_the_collector_allows_a_capped_turn_when_no_detector_blocks():
    policy = _no_blocking(_shipped()).for_profile("otel")
    (rec,), _ = collect(_capped_otel_records(), _detectors(policy), budget_ms=1000,
                        policy=policy)
    assert UNSCANNED_CAPPED in rec.tiers_dropped
    assert rec.action == "allow"


class _Warns:
    """A tier that reports one warn finding per unit."""
    name = "warns"
    tier = 0

    def scan(self, units):
        return [Finding("email", "warn", u.locator, f"w{i}") for i, u in enumerate(units)]


def _warn_units(n: int) -> list[ScanUnit]:
    return [ScanUnit(locator=f"$.f{i}", tool_name=None, text=f"row {i}") for i in range(n)]


def test_warn_findings_over_the_findings_cap_allow_under_the_shipped_policy():
    result = scan(_warn_units(MAX_SCAN_FINDINGS + 1), [_Warns()])
    assert result.detectors_skipped == [FINDINGS_CAPPED]
    assert len(result.findings) == MAX_SCAN_FINDINGS
    for policy in (_shipped(), _shipped(on_tier_dropped="deny")):
        verdict = decide(result.findings, policy, dropped=result.detectors_skipped)
        assert verdict.action == "allow"


def test_a_block_finding_over_the_findings_cap_denies_as_itself():
    policy = _shipped()
    units = _warn_units(MAX_SCAN_FINDINGS + 1)
    units.append(ScanUnit(locator="$.key", tool_name=None, text=f"key {FAKE_AWS_KEY}"))
    result = scan(units, [_Warns(), *_detectors(policy)])
    assert FINDINGS_CAPPED in result.detectors_skipped
    assert UNSCANNED_CAPPED not in result.detectors_skipped
    verdict = decide(result.findings, policy, dropped=result.detectors_skipped)
    assert verdict.action == "deny"
    assert "AWS" in verdict.deny_reason
