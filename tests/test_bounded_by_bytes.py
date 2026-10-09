"""Collector state that holds caller data is bounded by bytes, not only by
a count of entries: the seen-findings memory, the sink queue and the late
redaction queue."""

from __future__ import annotations

from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.models import Finding
from forgd_verdict.otel.collect import SeenFindings
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink.base import RedactedEvent, SinkConfig
from forgd_verdict.sink.factory import emitted_ids
from forgd_verdict.sink.fake import FakeSink
from forgd_verdict.sink.late import LateGroup, LateJob, LateRedactor
from forgd_verdict.sink.pipeline import SinkPipeline
from forgd_verdict.sink.redact import RedactionPlan

ORG = "00000000-0000-0000-0000-000000000001"
BIG = 1_000_000


def _finding(i: int) -> Finding:
    return Finding(detector="regex:aws-access-key", severity="block", locator="l",
                   excerpt_hash=f"{i:064x}")


def _held(seen: SeenFindings) -> int:
    """Characters of caller data `seen` holds in keys and marks."""
    return sum(len(str(part)) for key, marks in seen._sessions.items()
               for part in (*key, *(m for mark in marks for m in mark)))


def test_seen_findings_does_not_keep_a_raw_session_id():
    seen = SeenFindings()
    for i in range(20):
        seen.new(ORG, f"{i}" + "s" * BIG, [_finding(0)])
    assert _held(seen) < 20 * 1000


def test_seen_findings_still_remembers_a_long_session():
    seen = SeenFindings()
    session = "s" * BIG
    assert seen.new(ORG, session, [_finding(1)])
    assert seen.new(ORG, session, [_finding(1)]) == []
    assert seen.new(ORG, session + "x", [_finding(1)])


def test_seen_findings_forget_reverses_new():
    seen = SeenFindings()
    added: list = []
    seen.new(ORG, "sess", [_finding(1)], added)
    seen.forget(added)
    assert seen.new(ORG, "sess", [_finding(1)])


def test_seen_findings_bounds_marks_across_sessions():
    seen = SeenFindings(max_sessions=10_000, per_session=1_000, max_marks=5_000)
    for s in range(50):
        seen.new(ORG, f"session-{s}", [_finding(s * 1000 + i) for i in range(1000)])
    assert sum(len(m) for m in seen._sessions.values()) <= 5_000
    # The newest session is kept whole.
    assert seen.new(ORG, "session-49", [_finding(49_000)]) == []


def _event(text: str) -> RedactedEvent:
    return RedactedEvent(kind="log", name="evt", observed_at="t", surface="s", org=ORG,
                         attributes={"v": text}, resource={}, redactions={})


def test_the_sink_queue_is_bounded_by_bytes():
    sink = FakeSink(max_events=1, max_bytes=10_000_000)
    p = SinkPipeline(sink, max_queue=10_000, max_queue_bytes=5 * BIG, background=False)
    for i in range(20):
        p.offer([_event(str(i) * BIG)])
    assert p._queued_bytes <= 5 * BIG
    assert sum(sum(e.byte_size() for e in b) for b in p._q) == p._queued_bytes
    assert p.dropped >= 15
    # The newest is kept.
    assert p._q[-1][0].attributes["v"].startswith("19")


def test_an_event_over_the_sink_byte_bound_is_dropped_without_evicting():
    p = SinkPipeline(FakeSink(max_events=1, max_bytes=10_000_000), max_queue=10_000,
                     max_queue_bytes=BIG, background=False)
    p.offer([_event("small")])
    p.offer([_event("x" * 2 * BIG)])
    assert len(p._q) == 1 and p.dropped == 1


def test_flushing_the_sink_queue_returns_its_bytes():
    sink = FakeSink(max_events=1, max_bytes=10_000_000)
    p = SinkPipeline(sink, max_queue=10_000, max_queue_bytes=5 * BIG, background=False)
    for i in range(3):
        p.offer([_event(str(i) * 1000)])
    p.flush()
    assert p._queued_bytes == 0 and not p._q


def _late(bound: int) -> LateRedactor:
    cfg = SinkConfig(name="siem", endpoint="https://collector.test")
    t0 = T0RegexDetector()
    return LateRedactor(plan=RedactionPlan.build(cfg, emitted_ids([t0])), config=cfg,
                        offer=lambda events: None, cheap_detectors=[t0], late_detectors=[],
                        max_queue=10_000, max_queue_bytes=bound, background=False)


def _job(text: str) -> LateJob:
    return LateJob([LateGroup([OtelRecord(kind="log", name="evt", attributes={"v": text})],
                              [], "s")], ORG, "t")


def test_the_late_queue_is_bounded_by_bytes():
    late = _late(5 * BIG)
    for i in range(20):
        late.offer(_job(str(i) * BIG))
    assert late._queued_bytes <= 5 * BIG
    assert late.dropped >= 15
    assert late._q[-1].groups[0].records[0].attributes["v"].startswith("19")


def test_a_late_job_over_the_byte_bound_is_dropped_without_evicting():
    late = _late(BIG)
    late.offer(_job("small"))
    late.offer(_job("x" * 2 * BIG))
    assert len(late._q) == 1 and late.dropped == 1


def test_draining_the_late_queue_returns_its_bytes():
    late = _late(5 * BIG)
    late.offer(_job("plain words"))
    late.drain()
    assert late._queued_bytes == 0


def test_an_unrecognised_attribute_name_is_held_bounded(tmp_path, monkeypatch):
    """/stats tallies unrecognised names across exports; a long one is held
    as its placeholder."""
    import asyncio

    from conftest import ASGIClient
    from test_otel_collector import auth, make_policy
    from test_otel_payload import RESOURCE, logs_json

    from forgd_verdict.otel.app import Collector
    from forgd_verdict.store.local import LocalFileStore

    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    app = Collector(make_policy(), store=LocalFileStore(tmp_path / "f", instance="t"))
    body = logs_json([{"attributes": {
        "event.name": "claude_code.user_prompt", "n" * 20_000: "some plain text value",
        "session.id": "sess-1"}, "body": ""}], RESOURCE)
    try:
        status, _ = asyncio.run(ASGIClient(app).post("/v1/logs", body, auth()))
    finally:
        app.close()
    assert status == 200
    assert app._unrecognised and max(map(len, app._unrecognised)) < 1000
