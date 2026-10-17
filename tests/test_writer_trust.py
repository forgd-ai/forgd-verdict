"""Records shipped with an intake token never stand in for, or outrank, an
adapter's.

Every laptop in a fleet holds the fleet's token, so a record it ships says
what the holder chose. The verdict server, the collector and the ingest jobs
write records Anthropic authenticated. A reader that picks one record among
several prefers the adapter's, labels the token's, and keeps the token's
out of the inference hook's headline numbers.
"""

from __future__ import annotations

import asyncio
import dataclasses
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import ASGIClient

from forgd_verdict.connector import tools
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.entitlements import MODE_NONE, Entitlements, Principal
from forgd_verdict.intake.app import Intake
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_INFERENCE_HOOK,
    SOURCE_PRECEDENCE,
    SOURCES,
    TOKEN_SOURCES,
    WRITER_ADAPTER,
    WRITER_INTAKE_TOKEN,
    DenialRecord,
    FindingRow,
    VerdictRecord,
    source_rank,
    utcnow,
    writer_class,
)
from forgd_verdict.store.query import build_summary
from forgd_verdict.store.views import summary_payload

TOKEN = "fleet-token-synthetic-0123456789abcdef"
ORG = "org_0123456789"
REF = "fv_awsaccesske_01K5QW8ZPJ7N2R4T6V8XYA0BCD"
SESSION = "11111111-2222-4333-8444-555555555555"


def _policy() -> Policy:
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "laptops", "token": TOKEN}]},
        "privacy": {"hash_salt": "s"}}))


def _caller(store) -> tools.Caller:
    reader = tools.Reader(store=store, auth=AuthConfig(mode=MODE_NONE),
                          entitlements=Entitlements())
    return tools.Caller(reader, Principal(name="reviewer"))


def _real_deny(store, source=SOURCE_INFERENCE_HOOK, observed_at=None) -> None:
    store.write_verdicts([VerdictRecord(
        source=source, observed_at=observed_at or utcnow(), surface="claude-ai",
        tenant_hash=ORG, action="deny", reference_id=REF, request_id="wh-1",
        session_id=SESSION,
        findings=[FindingRow("regex:aws-access-key", "block", "msg[0]", "a" * 64)],
        findings_count=1)])


async def _ship(store, record: VerdictRecord) -> None:
    intake = Intake(_policy(), store=store)
    try:
        status, body = await ASGIClient(intake).post(
            "/intake", (record.to_json() + "\n").encode(),
            {"authorization": f"Bearer {TOKEN}", "content-type": "application/x-ndjson"})
        assert status == 200 and body["accepted"] == 1
        intake.flush()
    finally:
        intake.close()


def _forged() -> VerdictRecord:
    return VerdictRecord(source=SOURCE_CODE_HOOK, action="allow", reference_id=REF,
                         session_id=SESSION, request_id="PreToolUse:Bash:forged",
                         findings=[FindingRow("entropy:generic", "warn", "tool_input.command",
                                              "b" * 64)],
                         findings_count=1)


# -- the reproducer -----------------------------------------------------------


async def test_a_shipped_allow_does_not_shadow_a_real_deny(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    _real_deny(store)
    store.write_denials([DenialRecord(activity_id="act-1", created_at=utcnow(),
                                      reference_id=REF, tenant_hash=ORG)])
    time.sleep(1.1)
    await _ship(store, _forged())
    caller = _caller(store)

    out = await tools.record(caller, reference_id=REF)
    assert out["record"]["source"] == SOURCE_INFERENCE_HOOK
    assert out["record"]["action"] == "deny"
    assert out["record"]["writer"] == WRITER_ADAPTER
    (other,) = out["other_sources"]
    assert other["source"] == SOURCE_CODE_HOOK and other["writer"] == WRITER_INTAKE_TOKEN
    assert out["earlier_observations"] == 1

    out = await tools.record(caller, session_id=SESSION)
    assert out["record"]["source"] == SOURCE_INFERENCE_HOOK


async def test_reconciliation_joins_a_denial_to_the_inference_hook_only(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    store.write_denials([DenialRecord(activity_id="act-1", created_at=utcnow(),
                                      reference_id=REF, tenant_hash=ORG)])
    await _ship(store, _forged())
    rec = await tools.reconciliation(_caller(store), window="7d")
    assert [(d["reference_id"], d["verdict_found"]) for d in rec["denials"]["rows"]] == [
        (REF, False)]
    _real_deny(store)
    rec = await tools.reconciliation(_caller(store), window="7d")
    assert [d["verdict_found"] for d in rec["denials"]["rows"]] == [True]


async def test_reconciliation_joins_by_request_id_to_the_inference_hook_only(tmp_path):
    """A denial with Anthropic's request id and no reference id joins the
    inference hook's verdict for that frame, and no token writer's record
    can stand in for it however it names the request. Mutation: collect
    request ids from every source."""
    store = LocalFileStore(tmp_path, instance="t")
    store.write_denials([DenialRecord(activity_id="act-1", created_at=utcnow(),
                                      request_id="wh-1", event="tool_call",
                                      tenant_hash=ORG)])
    forged = _forged()
    forged.request_id = "wh-1"
    await _ship(store, forged)
    rec = await tools.reconciliation(_caller(store), window="7d")
    assert [(d["joined_by"], d["event"]) for d in rec["denials"]["rows"]] == [
        (None, "tool_call")]
    _real_deny(store)
    rec = await tools.reconciliation(_caller(store), window="7d")
    assert [d["joined_by"] for d in rec["denials"]["rows"]] == ["request_id"]
    assert rec["counts"]["joined_by_request_id"] == 1
    assert rec["counts"]["denials_tool_call"] == 1


async def test_record_finds_the_denial_by_the_verdict_s_request_id(tmp_path):
    """Mutation: look the denial up by reference_id alone."""
    store = LocalFileStore(tmp_path, instance="t")
    _real_deny(store)
    store.write_denials([DenialRecord(activity_id="act-1", created_at=utcnow(),
                                      request_id="wh-1", tenant_hash=ORG)])
    out = await tools.record(_caller(store), reference_id=REF)
    assert out["denial"]["activity_id"] == "act-1"
    assert out["denial"]["event"] == "prompt"


# -- the class: every token source against every adapter source -------------------


def test_every_source_has_a_writer_class_and_a_rank():
    assert set(SOURCES) > TOKEN_SOURCES
    assert sorted(SOURCE_PRECEDENCE) == sorted(SOURCES)
    for source in SOURCES:
        assert writer_class(source) == (WRITER_INTAKE_TOKEN if source in TOKEN_SOURCES
                                        else WRITER_ADAPTER)
    assert writer_class("made-up") == WRITER_INTAKE_TOKEN
    adapters = [s for s in SOURCES if s not in TOKEN_SOURCES]
    assert max(map(source_rank, adapters)) < min(map(source_rank, TOKEN_SOURCES))


def test_the_intake_writes_only_token_sources():
    """The intake is the only writer a laptop or agent token reaches, so each
    source it names is one readers class as a token's."""
    text = (Path(__file__).parents[1] / "src/forgd_verdict/intake/app.py").read_text()
    named = set(re.findall(r"\bSOURCE_[A-Z_]+\b", text))
    from forgd_verdict.store import base

    assert {getattr(base, n) for n in named} == set(TOKEN_SOURCES)


@pytest.mark.parametrize("token_source", sorted(TOKEN_SOURCES))
@pytest.mark.parametrize("adapter_source",
                         sorted(s for s in SOURCES if s not in TOKEN_SOURCES))
def test_a_newer_token_row_never_outranks_an_adapter_row(tmp_path, token_source,
                                                         adapter_source):
    store = LocalFileStore(tmp_path, instance="t")
    an_hour_ago = (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _real_deny(store, adapter_source, observed_at=an_hour_ago)
    store.write_verdicts([VerdictRecord(
        source=token_source, observed_at=utcnow(), surface="agent:x", tenant_hash=ORG,
        action="allow", reference_id=REF, session_id=SESSION)])
    for kw in ({"reference_id": REF}, {"session_id": SESSION}):
        out = asyncio.run(tools.record(_caller(store), **kw))
        assert out["record"]["source"] == adapter_source, kw
        assert [r["source"] for r in out["other_sources"]] == [token_source]


@pytest.mark.parametrize("token_source", sorted(TOKEN_SOURCES))
def test_token_rows_do_not_move_the_headline_deny_rate(token_source):
    live = [VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at=utcnow(),
                          surface="claude-ai", tenant_hash=ORG,
                          action="deny" if i % 2 else "allow") for i in range(10)]
    before = build_summary(live)
    flood = [VerdictRecord(source=token_source, observed_at=utcnow(), surface="agent:x",
                           tenant_hash=ORG, action="allow") for _ in range(500)]
    flood += [VerdictRecord(source=token_source, observed_at=utcnow(), surface="agent:x",
                            tenant_hash=ORG, action="deny") for _ in range(7)]
    after = build_summary(live + flood)
    assert before.deny_rate == after.deny_rate == 0.5
    assert after.adapter_would_deny == before.would_deny == 5
    assert after.token_would_deny == 7 and after.token_decisions == 507
    payload = summary_payload(after, "7d")
    assert payload["deny_rate"] == 0.5
    assert payload["intake_token"] == {"decisions": 507, "would_deny": 7,
                                       "deny_rate": round(7 / 507, 4)}
    surfaces = payload["surfaces"]
    assert [s["surface"] for s in surfaces] == ["claude-ai", "agent:x"]
    assert [s["writer"] for s in surfaces] == [WRITER_ADAPTER, WRITER_INTAKE_TOKEN]


def test_a_tally_row_does_not_move_the_headline_deny_rate():
    live = [VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at=utcnow(),
                          surface="claude-ai", tenant_hash=ORG, action=a)
            for a in ("deny", "allow")]
    tally = VerdictRecord(source=SOURCE_CODE_HOOK, observed_at=utcnow(),
                          surface="claude-code-local", tenant_hash=ORG, action="allow",
                          request_id="tally:x", tally=4999)
    s = build_summary([*live, tally])
    assert s.deny_rate == 0.5 and s.total_requests == 5001
    assert s.surfaces[0].surface == "claude-ai"


def test_the_event_log_marks_a_token_row():
    from forgd_verdict.dashboard.render import _writer_cell

    adapter = VerdictRecord(source=SOURCE_INFERENCE_HOOK, client=None)
    token = dataclasses.replace(adapter, source=SOURCE_CODE_HOOK, client="laptops")
    assert "via token" not in _writer_cell(adapter)
    assert "via token" in _writer_cell(token)


def test_spotcheck_reads_session_ids_from_compliance_records_only(tmp_path, monkeypatch):
    import argparse

    from forgd_verdict import cli, spotcheck
    from forgd_verdict.compliance import scanner as compliance_scanner
    from forgd_verdict.store.base import SOURCE_COMPLIANCE_SCAN

    store = LocalFileStore(tmp_path / "s", instance="t")
    finding = [FindingRow("regex:aws-access-key", "block", "msg[0]", "a" * 64)]
    store.write_verdicts([
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at=utcnow(),
                      session_id="clls_real", findings=finding, findings_count=1),
        VerdictRecord(source=SOURCE_CODE_HOOK, observed_at=utcnow(),
                      session_id="clls_from_a_laptop", findings=finding, findings_count=1)])
    asked: list[str] = []

    class Sample:
        sources_scanned = units_scanned = 0
        values: dict = {}

        def rows(self, *_):
            return []

    def sample_named(scanner, detector, ids, family="local"):
        asked.extend(ids)
        return Sample()

    monkeypatch.setattr(compliance_scanner, "ComplianceScanner", lambda *a, **k: object())
    monkeypatch.setattr(spotcheck, "sample_named", sample_named)
    policy = tmp_path / "policy.yaml"
    policy.write_text("privacy:\n  hash_salt: s\n")
    args = argparse.Namespace(
        env_file=None, policy=str(policy), session=None, from_store=str(tmp_path / "s"),
        detector="regex:aws-access-key", family="local", chats=False, since=None,
        max_sources=10, limit=25, reveal=False)
    cli._cmd_spotcheck(args)
    assert asked == ["clls_real"]


def _hook_rows(n_allow: int, n_deny: int, org: str = ORG) -> list[VerdictRecord]:
    return [VerdictRecord(source=SOURCE_CODE_HOOK, observed_at=utcnow(),
                          surface="claude-code-local", tenant_hash=org, action=a)
            for a in ["allow"] * n_allow + ["deny"] * n_deny]


def test_a_code_hook_only_scope_shows_no_adapter_data_not_zero(tmp_path):
    from forgd_verdict.dashboard.render import _would_deny_tile

    s = build_summary(_hook_rows(3, 1))
    assert s.deny_rate is None and s.token_deny_rate == 0.25
    payload = summary_payload(s, "7d")
    assert payload["deny_rate"] is None
    assert payload["intake_token"] == {"decisions": 4, "would_deny": 1, "deny_rate": 0.25}
    tile = _would_deny_tile(s)
    assert "no adapter data" in tile and "0.0%" not in tile
    assert "via intake token: 1 of 4 (25.0%)" in tile

    store = LocalFileStore(tmp_path, instance="t")
    store.write_verdicts(_hook_rows(3, 1))
    out = asyncio.run(tools.summary(_caller(store), window="7d"))
    assert out["deny_rate"] is None and out["intake_token"]["deny_rate"] == 0.25


def test_a_mixed_scope_shows_both_rates():
    from forgd_verdict.dashboard.render import _would_deny_tile

    live = [VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at=utcnow(),
                          surface="claude-ai", tenant_hash=ORG, action=a)
            for a in ("deny", "allow", "allow", "allow")]
    s = build_summary(live + _hook_rows(1, 1))
    payload = summary_payload(s, "7d")
    assert payload["deny_rate"] == 0.25 and payload["intake_token"]["deny_rate"] == 0.5
    tile = _would_deny_tile(s)
    assert "25.0% of live evaluations" in tile and "via intake token: 1 of 2 (50.0%)" in tile


def test_a_scope_with_no_token_rows_has_no_token_rate():
    live = [VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at=utcnow(),
                          surface="claude-ai", tenant_hash=ORG, action="allow")]
    s = build_summary(live)
    assert s.deny_rate == 0.0 and s.token_deny_rate is None
    assert summary_payload(s, "7d")["intake_token"]["deny_rate"] is None
