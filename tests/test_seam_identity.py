"""A finding on the seam between two adjacent values masks a value only
when its match lies in that value or crosses the join into it."""

from __future__ import annotations

import json
import shutil

import pytest
from conftest import GITLEAKS_FIXTURES

from forgd_verdict.budget import Budget
from forgd_verdict.core import scan
from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.otel.extract import records_units
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink import redact
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.factory import emitted_ids

pytestmark = pytest.mark.skipif(not shutil.which("gitleaks"),
                                reason="gitleaks binary not installed")

TOKEN = GITLEAKS_FIXTURES["shopify-access-token"]
SESSION = "sess-abcdefgh-01"
SALT = "seam-identity-test-salt"


def _detectors():
    gl = GitleaksDetector()
    assert gl.available() and not gl.uses_daemon
    return [T0RegexDetector(), gl]


def _record(session: str, request: str) -> OtelRecord:
    return OtelRecord(kind="log", name="claude_code.user_prompt",
                      attributes={"session.id": session, "request_id": request,
                                  "prompt": "hello there"},
                      resource={"service.name": "claude-code"})


def _redacted(record: OtelRecord):
    detectors = _detectors()
    result = scan(records_units([record]), detectors, Budget(60_000))
    config = SinkConfig(name="s", endpoint="https://collector.test")
    plan = redact.RedactionPlan.build(config, emitted_ids(detectors))
    (event,) = redact.redact_events([record], redact.index_findings(result.findings), plan,
                                    config, surface="claude-code", org="o",
                                    observed_at="2026-10-06T00:00:00Z", detectors=detectors)
    return event


def test_a_seam_into_the_next_identity_value_leaves_a_clean_one_unchanged():
    event = _redacted(_record(SESSION, TOKEN))
    assert event.attributes["session.id"] == SESSION
    assert TOKEN not in json.dumps(event.attributes)
    assert event.attributes["request_id"].startswith("[redacted:")


def test_a_token_split_across_two_identity_values_masks_both():
    cut = 19
    event = _redacted(_record(TOKEN[:cut], TOKEN[cut:]))
    assert event.attributes["session.id"].startswith("[redacted:")
    assert event.attributes["request_id"].startswith("[redacted:")


def test_the_collector_stores_a_clean_session_beside_a_seamed_token():
    from forgd_verdict.otel.collect import collect

    out, _ = collect([_record(SESSION, TOKEN)], _detectors(), budget_ms=60_000, salt=SALT,
                     org_id="org-a")
    (record,) = out
    assert record.session_id == SESSION
    assert TOKEN not in record.to_json()
    assert record.findings_count >= 1


def _content(first: str, second: str) -> OtelRecord:
    return OtelRecord(kind="log", name="claude_code.api_request",
                      attributes={"prompt": first, "response": second},
                      resource={"service.name": "claude-code"})


def test_a_seam_into_the_next_content_value_leaves_a_clean_one_unchanged():
    clean = "plain words only here"
    event = _redacted(_content(clean, f"use {TOKEN} please"))
    assert event.attributes["prompt"] == clean
    assert TOKEN not in json.dumps(event.attributes)


def test_a_token_split_across_two_content_values_masks_both():
    cut = 19
    event = _redacted(_content(f"see {TOKEN[:cut]}", f"{TOKEN[cut:]} ok"))
    assert TOKEN[:cut] not in event.attributes["prompt"]
    assert TOKEN[cut:] not in event.attributes["response"]
