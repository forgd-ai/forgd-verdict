"""Adapter 5 -- the outbound control point.

The tests that matter here are about what LEAVES. A bug in an inbound
adapter under-reports; a bug here sends a customer's secrets to their SIEM
uncensored while the dashboard says the scan was clean.
"""

from __future__ import annotations

import pytest
from conftest import FakeConnect

from forgd_verdict.models import Finding, ScanUnit
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink.base import RedactedEvent, SinkConfig, SinkUnavailable
from forgd_verdict.sink.factory import build_forwarders
from forgd_verdict.sink.fake import FakeSink
from forgd_verdict.sink.otlp import OtlpSink, SinkSendFailed, build_sink
from forgd_verdict.sink.pipeline import SinkPipeline, chunk
from forgd_verdict.sink.redact import RedactionPlan, redact_events
from forgd_verdict.sink.transport import HttpTransport

KEY = "AKIAQYLPMN5HGZTHX4UQ"

# The backstop runs in every test. Passing [] would switch off the
# check these tests exist to exercise.
from forgd_verdict.detectors.t0_regex import T0RegexDetector  # noqa: E402

_DETS = [T0RegexDetector()]


def _event(n: int = 1, **kw) -> RedactedEvent:
    return RedactedEvent(
        kind="span", name=f"e{n}", observed_at="2026-09-21T00:00:00Z",
        surface="claude-cowork", org="o", **kw)


def _cfg(**kw) -> SinkConfig:
    kw.setdefault("name", "s")
    kw.setdefault("endpoint", "https://collector.test")
    return SinkConfig(**kw)


# -- redaction ------------------------------------------------------------


def _scan_one(text: str, detector: str, start: int, end: int):
    """A record with one attribute, and the finding a scan would produce."""
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"user.message": text})
    unit = ScanUnit(locator="otel[0].agent.query.user.message", tool_name=None,
                    text=text)
    f = Finding(detector=detector, severity="block", locator=unit.locator,
                excerpt_hash="h", start=start, end=end)
    return rec, {unit.locator: [f]}


def test_the_matched_span_goes_and_the_prose_around_it_stays():
    """The whole point. A customer wants the prompt in Splunk WITHOUT the
    key in it -- replacing the entire attribute would meet the letter of
    that and destroy the thing they asked to keep."""
    text = f"deploy with {KEY} please"
    rec, found = _scan_one(text, "regex:aws-access-key-id",
                           text.index(KEY), text.index(KEY) + len(KEY))
    plan = RedactionPlan.build(_cfg(redact=["regex:aws-access-key-id"]),
                               ["regex:aws-access-key-id"])
    out = redact_events([rec], found, plan, _cfg(redact=["regex:aws-access-key-id"]),
                        surface="claude-cowork", org="o",
                        observed_at="2026-09-21T00:00:00Z", detectors=_DETS)
    msg = out[0].attributes["user.message"]
    assert KEY not in msg
    assert msg == "deploy with [redacted:regex:aws-access-key-id] please"
    assert out[0].redactions == {"regex:aws-access-key-id": 1}


def test_a_detector_not_on_the_list_is_left_alone():
    """Configurability is the feature. An org that does not care about NRP
    landing in Splunk keeps it, and one that does adds it to the list --
    neither is the default."""
    text = f"deploy with {KEY} please"
    rec, found = _scan_one(text, "presidio:nrp", 0, 6)
    plan = RedactionPlan.build(_cfg(redact=["regex:aws-access-key-id"]),
                               ["regex:aws-access-key-id", "presidio:nrp"])
    out = redact_events([rec], found, plan, _cfg(), surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    assert out[0].attributes["user.message"] == text
    assert out[0].redactions == {}


def test_several_matches_in_one_value_all_go():
    """Replacing left to right shifts every later offset by the difference
    between the match and the mask, which censors the wrong characters and
    leaves part of the second secret in place. This is why it runs right to
    left."""
    b = "AKIAZZZZZZZZZZZZZZZZ"
    text = f"first {KEY} then {b} end"
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"user.message": text})
    loc = "otel[0].agent.query.user.message"
    found = {loc: [
        Finding("regex:aws-access-key-id", "block", loc, "h1",
                start=text.index(KEY), end=text.index(KEY) + len(KEY)),
        Finding("regex:aws-access-key-id", "block", loc, "h2",
                start=text.index(b), end=text.index(b) + len(b)),
    ]}
    cfg = _cfg(redact=["regex:aws-access-key-id"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key-id"])
    out = redact_events([rec], found, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    msg = out[0].attributes["user.message"]
    assert KEY not in msg and b not in msg, msg
    assert msg.count("[redacted:regex:aws-access-key-id]") == 2
    assert out[0].redactions == {"regex:aws-access-key-id": 2}


def test_a_finding_with_no_span_takes_the_whole_value():
    """Coarse on purpose. The alternative is forwarding a value we know
    contains a match and cannot locate, which is the one outcome this
    adapter exists to prevent."""
    text = f"deploy with {KEY} please"
    rec, found = _scan_one(text, "gitleaks:aws", None, None)
    cfg = _cfg(redact=["gitleaks:aws"])
    plan = RedactionPlan.build(cfg, ["gitleaks:aws"])
    out = redact_events([rec], found, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    assert out[0].attributes["user.message"] == "[redacted:gitleaks:aws:whole-value]"
    assert KEY not in out[0].attributes["user.message"]


def test_an_offset_that_does_not_fit_takes_the_whole_value():
    """A span past the end of the text means what was scanned and what is
    leaving are not the same string. Guessing would censor the wrong
    characters; this drops the value instead."""
    text = "short"
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"user.message": text * 3})
    loc = "otel[0].agent.query.user.message"
    found = {loc: [Finding("regex:x", "block", loc, "h", start=900, end=999)]}
    cfg = _cfg(redact=["regex:x"])
    plan = RedactionPlan.build(cfg, ["regex:x"])
    out = redact_events([rec], found, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    assert out[0].attributes["user.message"].startswith("[redacted:")


def test_the_redaction_note_says_what_and_never_the_value():
    """The same invariant the store holds, applied on the way out: a SIEM
    can alert on "this was censored and why" without being handed it."""
    text = f"deploy with {KEY} please"
    rec, found = _scan_one(text, "regex:aws-access-key-id",
                           text.index(KEY), text.index(KEY) + len(KEY))
    cfg = _cfg(redact=["regex:aws-access-key-id"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key-id"])
    out = redact_events([rec], found, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    blob = repr(out[0].redactions) + OtlpSink(cfg)._body(out).decode()
    assert KEY not in blob
    assert "forgd.redacted" in blob


# -- fail closed ----------------------------------------------------------


def test_a_sink_refuses_to_start_when_a_redaction_tier_is_missing():
    """Adapter 3 degrading is right: it under-reports. Adapter 5 degrading
    is a LEAK -- the data leaves anyway, uncensored, and the counter that
    would tell you is in someone else's system."""
    with pytest.raises(SinkUnavailable) as e:
        RedactionPlan.build(_cfg(redact=["presidio:email_address"]),
                            ["regex:aws-access-key-id"])
    assert "presidio:email_address" in str(e.value)
    assert "uncensored" in str(e.value)


def test_redacting_nothing_is_allowed_and_is_not_a_failure():
    """A customer may want their own raw telemetry in their own SIEM. That
    is a choice, not a misconfiguration."""
    plan = RedactionPlan.build(_cfg(redact=[]), [])
    assert plan.detectors == frozenset()


# -- filtering and metadata ----------------------------------------------


def test_dropped_event_types_never_reach_the_sink():
    """Splunk licenses per GB ingested, so this is a line item."""
    recs = [OtelRecord(kind="span", name="token_usage", attributes={}),
            OtelRecord(kind="span", name="agent.query", attributes={})]
    cfg = _cfg(drop_events=["token_usage"])
    out = redact_events(recs, {}, RedactionPlan.build(cfg, []), cfg,
                        surface="s", org="o", observed_at="t", detectors=_DETS)
    assert [e.name for e in out] == ["agent.query"]


def test_static_metadata_is_stamped_on_the_way_out():
    rec = OtelRecord(kind="span", name="agent.query", attributes={})
    cfg = _cfg(metadata={"env": "prod", "business_unit": "platform"})
    out = redact_events([rec], {}, RedactionPlan.build(cfg, []), cfg,
                        surface="s", org="o", observed_at="t", detectors=_DETS)
    assert out[0].attributes["env"] == "prod"
    assert out[0].attributes["business_unit"] == "platform"


# -- conformance: every sink type must pass these -------------------------


def _sinks():
    return [FakeSink(), OtlpSink(_cfg())]


@pytest.mark.parametrize("sink", _sinks(), ids=lambda s: s.type)
def test_a_sink_declares_the_limits_the_core_batches_against(sink):
    """Chunking is the core's job precisely because these differ -- HEC
    around 1 MB, CloudWatch 1 MB and 10k, Datadog 5 MB. An exporter that
    re-chunks is an exporter that can get it wrong on its own."""
    assert sink.max_batch_events > 0
    assert sink.max_batch_bytes > 0
    assert isinstance(sink.requires_ordering, bool)


@pytest.mark.parametrize("sink", _sinks(), ids=lambda s: s.type)
def test_a_sink_describes_itself_without_leaking_its_credential(sink):
    d = sink.describe()
    assert d["type"] and d["name"]
    assert "token" not in repr(d).lower() or "authenticated" in repr(d)


def test_the_core_chunks_against_the_declared_limits_not_the_sinks_own():
    sink = FakeSink(max_events=3)
    batches = chunk([_event(i) for i in range(7)], sink)
    assert [len(b) for b in batches] == [3, 3, 1]


def test_an_event_larger_than_the_limit_is_still_sent_alone():
    """Dropping it would silently lose the biggest events, which are the
    ones most likely to carry something worth seeing."""
    sink = FakeSink(max_events=10, max_bytes=10)
    big = _event(1, attributes={"x": "y" * 500})
    batches = chunk([big, _event(2)], sink)
    assert len(batches) == 2 and batches[0] == [big]


def test_an_unbuilt_type_is_refused_and_the_refusal_names_what_exists():
    with pytest.raises(SinkUnavailable) as e:
        build_sink(_cfg(type="splunk_hec"))
    msg = str(e.value)
    assert "'otlp' and 'azure-monitor'" in msg
    assert "splunk_hec" in msg
    assert "registered in build_sink" in msg


# -- the queue: never reach Anthropic -------------------------------------


def test_a_full_queue_drops_the_oldest_and_counts_it():
    """The newest telemetry is the useful telemetry when something is on
    fire, and keeping the oldest means a recovered sink flushes an hour of
    history before anything current."""
    p = SinkPipeline(FakeSink(max_events=1), max_queue=3, background=False)
    for i in range(6):
        p.offer([_event(i)])
    assert p.dropped == 3
    p.flush()
    assert [e.name for e in p.sink.events] == ["e3", "e4", "e5"]


def test_offering_never_raises_into_the_ingest_path():
    """A non-200 to Anthropic is an export failure and sustained failures
    trip the circuit breaker. A Splunk outage must not become telemetry
    loss from Claude."""
    p = SinkPipeline(FakeSink(fail_times=99), max_queue=10, background=False)
    p.offer([_event(1)])
    p.flush()
    assert p.dropped == 1
    assert p.sent == 0


def test_a_failed_batch_is_retried_before_it_is_dropped():
    p = SinkPipeline(FakeSink(fail_times=2), max_queue=10, max_retries=2,
                     background=False)
    p.offer([_event(1)])
    p.flush()
    assert p.sent == 1 and p.dropped == 0 and p.retries == 2


def test_the_stats_say_which_destination_dropped():
    """A drop counter that cannot name the sink is not worth reading."""
    p = SinkPipeline(FakeSink(), max_queue=10, background=False)
    assert p.stats()["sink"]["name"] == "fake"


# -- the wire -------------------------------------------------------------


def test_the_otlp_body_is_a_logs_payload_at_the_signal_path():
    """`endpoint` is a BASE url and the exporter appends the signal path --
    the same rule Anthropic's exporter follows inbound."""
    s = OtlpSink(_cfg(endpoint="https://collector.test/"))
    assert s._url == "https://collector.test/v1/logs"


def test_a_non_2xx_is_a_send_failure_and_not_a_silent_success():
    s = OtlpSink(_cfg(), connect=FakeConnect(503))
    with pytest.raises(SinkSendFailed):
        s.send([_event(1)])
    assert s.failed == 1


def test_a_sink_with_no_endpoint_refuses_to_build():
    """A queue that fills and drops looks exactly like a working sink with
    a quiet week."""
    with pytest.raises(SinkUnavailable):
        OtlpSink(SinkConfig(name="s", endpoint=""))


# -- end to end, with the real scan core ----------------------------------


def test_a_real_key_scanned_by_the_real_detectors_does_not_reach_the_wire():
    """The test the rest of this file is scaffolding for.

    Everything above builds Findings by hand, which proves the redactor
    honours what it is told and not that it is told the truth. This runs
    the actual scan over an actual record, feeds the actual findings in,
    and asserts the key is absent from the bytes that would go out.
    """
    from forgd_verdict.otel.extract import record_units_by_key

    text = f"here is the prod key {KEY} do not share it"
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"user.message": text})

    det = T0RegexDetector()
    pairs = record_units_by_key(rec, 0)
    findings = det.scan([u for _, u in pairs])
    assert findings, "the scan core should find the key; fixture is wrong"
    detector_id = findings[0].detector

    by_locator: dict[str, list[Finding]] = {}
    for f in findings:
        by_locator.setdefault(f.locator, []).append(f)

    cfg = _cfg(redact=[detector_id])
    plan = RedactionPlan.build(cfg, [detector_id])
    events = redact_events([rec], by_locator, plan, cfg, surface="claude-cowork",
                           org="o", observed_at="2026-09-21T00:00:00Z", detectors=_DETS)

    wire = OtlpSink(cfg)._body(events).decode()
    assert KEY not in wire, "the key reached the wire"
    assert "do not share it" in wire, "the prose around it should survive"
    assert "forgd.redacted" in wire


def test_the_scan_still_sees_the_raw_text_after_redaction_is_configured():
    """Detection quality must not depend on what the customer censors.

    The scan runs on the original and the store keeps its finding; only
    the outbound copy is masked. If these were the other way round, turning
    on redaction would quietly reduce what verdict detects.
    """
    from forgd_verdict.otel.extract import record_units_by_key

    text = f"prod key {KEY}"
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"user.message": text})
    findings = T0RegexDetector().scan(
        [u for _, u in record_units_by_key(rec, 0)])
    assert findings

    cfg = _cfg(redact=[findings[0].detector])
    plan = RedactionPlan.build(cfg, [findings[0].detector])
    by_locator = {findings[0].locator: list(findings)}
    redact_events([rec], by_locator, plan, cfg, surface="s", org="o",
                  observed_at="t", detectors=_DETS)

    # The record the scanner saw is untouched by the redactor.
    assert rec.attributes["user.message"] == text
    again = T0RegexDetector().scan([u for _, u in record_units_by_key(rec, 0)])
    assert [f.detector for f in again] == [f.detector for f in findings]


# -- through the real collector ------------------------------------------


def _collector_with_sink(tmp_path, redact, monkeypatch):
    """A real OtelApp with one sink, whose transport is captured."""
    import textwrap

    from forgd_verdict.otel.app import Collector
    from forgd_verdict.policy import load_policy

    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: test-salt}}
        otel:
          orgs:
            - {{name: demo, id: "00000000-0000-0000-0000-000000000001",
                token: a-token-long-enough-to-be-one}}
        sinks:
          - name: siem
            type: otlp
            endpoint: https://collector.test
            redact: [{redact}]
    """), encoding="utf-8")
    app = Collector(load_policy(str(pol)), store=None)
    captured: list[list[RedactedEvent]] = []
    for fwd in app.forwarders:
        real = fwd.pipeline.sink
        fwd.pipeline.sink = FakeSink(max_events=100, max_bytes=10_000_000)
        assert real.type == "otlp"
    return app, captured


def test_the_collector_forwards_a_redacted_copy_and_stores_the_finding(tmp_path,
                                                                       monkeypatch):
    """The whole adapter, through the real app.

    A key arrives in an export. The store gets a finding for it; the sink
    gets the same event with the key replaced and the prose intact.
    """
    app, _ = _collector_with_sink(tmp_path, "regex:aws-access-key", monkeypatch)
    text = f"ship it with {KEY} thanks"
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"service.name": "office-agent",
                                 "prompt.id": "p1", "user.message": text})

    hook = app._forward_group("00000000-0000-0000-0000-000000000001")
    from forgd_verdict.budget import Budget
    from forgd_verdict.core import scan
    from forgd_verdict.otel.extract import record_units_by_key
    units = [u for _, u in record_units_by_key(rec, 0)]
    findings = scan(units, app.detectors, Budget(5000)).findings
    assert any(f.detector.startswith("regex:") for f in findings)

    hook([rec], findings, "claude-for-m365")
    hook.finish()
    for fwd in app.forwarders:
        fwd.pipeline.flush()

    sent = [e for fwd in app.forwarders for e in fwd.pipeline.sink.events]
    assert sent, "the sink received nothing"
    msg = sent[0].attributes["user.message"]
    assert KEY not in msg
    assert "ship it with" in msg and "thanks" in msg
    assert sent[0].surface == "claude-for-m365"


@pytest.mark.parametrize("value", [{"intValue": 4539148803436467},
                                   {"intValue": "4539148803436467"},
                                   {"doubleValue": 4539148803436467.0}],
                         ids=["int", "int as string", "double"])
def test_a_numeric_attribute_that_matched_is_not_forwarded(value, tmp_path, monkeypatch):
    import json

    from forgd_verdict.budget import Budget
    from forgd_verdict.core import scan
    from forgd_verdict.otel.extract import record_units_by_key
    from forgd_verdict.otel.payload import decode

    pan = "4539148803436467"
    body = {"resourceLogs": [{"resource": {"attributes": [
        {"key": "service.name", "value": {"stringValue": "office-agent"}}]},
        "scopeLogs": [{"logRecords": [{"attributes": [
            {"key": "event.name", "value": {"stringValue": "tool_result"}},
            {"key": "tool.card", "value": value}]}]}]}]}
    records = decode(json.dumps(body).encode(), "application/json", "logs")
    app, _ = _collector_with_sink(tmp_path, "regex:pan", monkeypatch)
    units = [u for r in records for _, u in record_units_by_key(r, 0)]
    findings = scan(units, app.detectors, Budget(5000)).findings
    assert [f.detector for f in findings] == ["regex:pan"]
    assert pan not in repr(findings)

    forward = app._forward_group("00000000-0000-0000-0000-000000000001")
    forward(records, findings, "claude-for-m365")
    forward.finish()
    for fwd in app.forwarders:
        fwd.pipeline.flush()
    sent = [e for fwd in app.forwarders for e in fwd.pipeline.sink.events]
    assert sent, "the sink received nothing"
    assert "tool.card" in sent[0].attributes
    assert pan not in repr(sent)


def test_a_deployment_with_no_sinks_builds_nothing(tmp_path):
    """Optional means optional: no config, no queue, no thread, no cost."""
    import textwrap

    from forgd_verdict.otel.app import Collector
    from forgd_verdict.policy import load_policy

    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent("""
        privacy: {hash_salt: test-salt}
        otel:
          orgs:
            - {name: demo, id: "00000000-0000-0000-0000-000000000001", token: a-token-long-enough-to-be-one}
    """), encoding="utf-8")
    app = Collector(load_policy(str(pol)), store=None)
    assert app.forwarders == []


def test_a_sink_naming_an_absent_detector_stops_the_collector_starting(tmp_path):
    """The fail-closed rule, at the only moment it can be enforced cheaply.

    Left to runtime this is a sink that forwards uncensored while the
    dashboard reports a clean scan.
    """
    import textwrap

    from forgd_verdict.otel.app import Collector
    from forgd_verdict.policy import load_policy

    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent("""
        privacy: {hash_salt: test-salt}
        otel:
          orgs:
            - {name: demo, id: "00000000-0000-0000-0000-000000000001", token: a-token-long-enough-to-be-one}
        sinks:
          - name: siem
            endpoint: https://collector.test
            redact: [detector:that:does:not:exist]
    """), encoding="utf-8")
    with pytest.raises(SinkUnavailable) as e:
        Collector(load_policy(str(pol)), store=None)
    assert "uncensored" in str(e.value)


def test_a_typod_rule_id_is_refused_rather_than_silently_redacting_nothing():
    """The failure that arrives through a spelling mistake.

    Checking the config against detector NAMES alone would accept
    `regex:typo`: the `regex` tier is running, so nothing refuses, the
    rule never matches, and the value leaves uncensored. A fixture that
    asks for `regex:aws-access-key-id` when the rule is
    `regex:aws-access-key` is enough to do it.
    """
    from forgd_verdict.sink.factory import emitted_ids

    available = emitted_ids([T0RegexDetector()])
    assert "regex:aws-access-key" in available, available[:5]

    with pytest.raises(SinkUnavailable) as e:
        RedactionPlan.build(_cfg(redact=["regex:aws-access-key-id"]), available)
    # The refusal lists real ids, so the fix is in the error message.
    assert "regex:aws-access-key'" in str(e.value)


def test_a_bare_tier_name_censors_everything_that_tier_finds():
    """`redact: [regex]` is the coarse setting and has to keep working --
    an org that wants every pattern match gone should not have to
    enumerate fifteen rule ids and keep the list current."""
    from forgd_verdict.sink.factory import emitted_ids

    plan = RedactionPlan.build(_cfg(redact=["regex"]),
                               emitted_ids([T0RegexDetector()]))
    assert plan.wants("regex:aws-access-key")
    assert plan.wants("regex:stripe-secret-key")
    assert not plan.wants("presidio:nrp")


def test_the_drop_counter_is_reachable_on_stats(tmp_path):
    """A sink drops rather than blocking ingest, so a downstream outage is
    invisible upstream. This counter is the only place it shows, and a
    counter nobody can read is not a counter."""
    import textwrap

    from forgd_verdict.otel.app import Collector
    from forgd_verdict.policy import load_policy

    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent("""
        privacy: {hash_salt: test-salt}
        otel:
          orgs:
            - {name: demo, id: "00000000-0000-0000-0000-000000000001", token: a-token-long-enough-to-be-one}
        sinks:
          - {name: siem, type: otlp, endpoint: https://collector.test}
    """), encoding="utf-8")
    app = Collector(load_policy(str(pol)), store=None)
    stats = app.stats()
    assert stats["sinks"][0]["sink"]["name"] == "siem"
    assert stats["sinks"][0]["dropped"] == 0


# -- leaks and stalls, each with the case that produces it ---------------


def test_the_same_secret_twice_in_one_value_does_not_half_leak():
    """`core.scan` dedupes on (detector, locator, excerpt_hash).

    So the SAME key twice in one attribute collapses to ONE finding with
    ONE span. Masking only that span leaves the second copy on the wire,
    next to a mask announcing the first has been removed:
    "use K and also K again" -> 1 finding at (4, 24), and K in the output.
    """
    from forgd_verdict.budget import Budget
    from forgd_verdict.core import scan
    from forgd_verdict.otel.extract import record_units_by_key

    text = f"use {KEY} and also {KEY} again"
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"user.message": text})
    dets = [T0RegexDetector()]
    units = [u for _, u in record_units_by_key(rec, 0)]
    findings = scan(units, dets, Budget(5000)).findings
    assert len(findings) == 1, "fixture assumes the dedupe collapses these"

    cfg = _cfg(redact=["regex:aws-access-key"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    out = redact_events([rec], {findings[0].locator: findings}, plan, cfg,
                        surface="s", org="o", observed_at="t", detectors=dets)
    assert KEY not in out[0].attributes["user.message"]


def test_a_wrong_offset_is_caught_rather_than_masking_innocent_text():
    """Presidio analyses `prose_only(unit.text)`, so its offsets are in
    transformed coordinates. Applied to the original they cut the wrong
    substring and leave the match in place -- visibly censored and still
    leaking. This is the general case: a span that does not point at the
    thing it claims to."""
    text = f"padding padding {KEY} tail"
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"user.message": text})
    loc = "otel[0].agent.query.user.message"
    # A span pointing at the padding rather than the key.
    bad = Finding("regex:aws-access-key", "block", loc, "h", start=0, end=7)
    cfg = _cfg(redact=["regex:aws-access-key"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    out = redact_events([rec], {loc: [bad]}, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=[T0RegexDetector()])
    assert KEY not in out[0].attributes["user.message"]


def test_a_value_longer_than_the_scan_saw_is_not_forwarded():
    """`record_units` truncates at MAX_UNIT_BYTES; the attribute forwarded
    is the whole value. Anything past the cut was never looked at, and the
    findings list looks entirely normal."""
    from forgd_verdict.otel.extract import MAX_UNIT_BYTES

    text = "a" * (MAX_UNIT_BYTES + 100) + KEY
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"user.message": text})
    cfg = _cfg(redact=["regex:aws-access-key"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    out = redact_events([rec], {}, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    assert KEY not in out[0].attributes["user.message"]
    assert out[0].redactions.get("unscanned-tail") == 1


def test_the_backstop_is_what_catches_these_and_not_the_spans():
    """Stated as its own test so the next person does not delete it.

    `_still_matches` re-scans the masked value with the detectors the sink
    redacts. Without it the three cases above forward a live credential.
    """
    from forgd_verdict.sink.redact import _still_matches

    plan = RedactionPlan.build(_cfg(redact=["regex:aws-access-key"]),
                               ["regex:aws-access-key"])
    dets = [T0RegexDetector()]
    assert _still_matches(f"leftover {KEY}", plan, dets)
    assert not _still_matches("nothing here at all", plan, dets)
    # A detector that raises must not be read as "safe".
    class Boom:
        def scan(self, units): raise RuntimeError("boom")
    assert _still_matches("anything", plan, [Boom()])


def test_ingest_does_not_wait_on_the_downstream_sink():
    """Flushing inline made every export wait on the customer's SIEM.

    With `timeout_s` 10 and two retries that is up to 30 s holding the
    OTLP response open -- a delivery failure to Anthropic, and sustained
    delivery failures trip the circuit breaker. So the queue this was
    built around was defeated by where it was called from.

    `offer` must return promptly no matter how badly `send` behaves.
    """
    sends = []

    class Counting(FakeSink):
        def send(self, events):
            sends.append(len(events))
            return len(events)

    # `background=False` starts no worker, so any `send` here ran inside
    # `offer`.
    p = SinkPipeline(Counting(), max_queue=10, background=False)
    p.offer([_event(1)])
    assert sends == [], "offer called the sink inline"
    assert p.stats()["queued"] == 1


def test_each_sink_has_its_own_send_lock():
    """As a class attribute this serialised every sink in the process, so
    a slow Splunk would stall a fast blob sink -- the one thing a queue
    per destination exists to prevent."""
    a = SinkPipeline(FakeSink(), background=False)
    b = SinkPipeline(FakeSink(), background=False)
    assert a._sending is not b._sending


def test_what_is_never_scanned_is_forwarded_and_that_is_documented():
    """The guarantee is "a DETECTED value is not forwarded", not "the
    stream contains no secrets".

    Identity attributes, values under MIN_SCAN_CHARS and `resource` are
    never scanned, so nothing is detected in them and nothing is masked.
    Pinned as a test so the claim in docs/PLATFORM.md stays the claim in the
    code -- a reader who assumes the stronger guarantee is the person this
    adapter would surprise.
    """
    rec = OtelRecord(
        kind="span", name="agent.query",
        attributes={"user.email": "someone@example.com", "short": "abc"},
        resource={"host.name": "laptop-01"},
    )
    cfg = _cfg(redact=["regex:aws-access-key"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    out = redact_events([rec], {}, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    assert out[0].attributes["user.email"] == "someone@example.com"
    assert out[0].resource["host.name"] == "laptop-01"


def test_redaction_without_detectors_to_verify_it_is_refused():
    """`detectors` defaulted to (), so a caller omitting it silently
    switched the backstop off and got unverified masking."""
    text = f"key {KEY}"
    rec, found = _scan_one(text, "regex:aws-access-key", 4, 4 + len(KEY))
    cfg = _cfg(redact=["regex:aws-access-key"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    with pytest.raises(SinkUnavailable):
        redact_events([rec], found, plan, cfg, surface="s", org="o",
                      observed_at="t", detectors=[])


def test_a_batch_bigger_than_the_whole_bound_is_dropped_not_appended():
    """An empty queue ended the eviction loop, so an oversized batch was
    appended anyway and the bound was advisory."""
    p = SinkPipeline(FakeSink(max_events=100), max_queue=2, background=False)
    p.offer([_event(i) for i in range(5)])
    assert p.dropped == 5
    p.flush()
    assert p.sink.events == []


# -- redaction config, masking and budget edges --------------------------


class _FakePresidio:
    """Stands in for PresidioPIIDetector, which needs the model installed.

    Reproduces the thing that mattered: `.name` and the finding-id prefix
    are DIFFERENT strings.
    """
    name = "presidio_pii"
    finding_prefix = "presidio"
    tier = 2
    severity = "warn"

    def __init__(self, entities=("EMAIL_ADDRESS", "PERSON")):
        self._entities = entities

    def available(self):
        return True

    def finding_ids(self):
        return [f"presidio:{e.lower()}" for e in self._entities]

    def scan(self, units):
        return []


def test_the_documented_pii_redaction_config_starts_and_works():
    """`.name` is `presidio_pii`; every finding is `presidio:<entity>`.

    If emitted_ids advertises `.name`, RedactionPlan validates against that
    while `wants` tests the finding-id prefix. So:

        redact: [presidio:email_address]  -> refused to start
        redact: [presidio]                -> refused to start
        redact: [presidio_pii]            -> starts, matches NOTHING

    policy.yaml and docs/PLATFORM.md both document the first. The collector
    would not boot on its own example, and the spelling that boots puts
    an SSN on the wire in an event with no forgd.redacted marker.
    """
    from forgd_verdict.sink.factory import emitted_ids

    ids = emitted_ids([_FakePresidio()])
    plan = RedactionPlan.build(_cfg(redact=["presidio:email_address"]), ids)
    assert plan.wants("presidio:email_address")

    tier = RedactionPlan.build(_cfg(redact=["presidio"]), ids)
    assert tier.wants("presidio:email_address")
    assert tier.wants("presidio:person")


def test_the_internal_detector_name_is_refused_rather_than_matching_nothing():
    """`presidio_pii` is the class's name, not what its findings say.

    Accepting it was the whole failure: it built, logged itself as
    redacting, and matched nothing. Refusing names the spelling that
    works.
    """
    from forgd_verdict.sink.factory import emitted_ids

    with pytest.raises(SinkUnavailable) as e:
        RedactionPlan.build(_cfg(redact=["presidio_pii"]),
                            emitted_ids([_FakePresidio()]))
    assert "presidio" in str(e.value)


def test_an_entity_that_is_switched_off_is_refused():
    """The entity list is configuration, so it can be checked exactly --
    asking to redact one nobody enabled should not quietly do nothing."""
    from forgd_verdict.sink.factory import emitted_ids

    ids = emitted_ids([_FakePresidio(entities=("PERSON",))])
    with pytest.raises(SinkUnavailable):
        RedactionPlan.build(_cfg(redact=["presidio:email_address"]), ids)


def test_a_rule_of_a_detector_that_cannot_enumerate_is_refused():
    """gitleaks cannot list its rules, so `gitleaks:aws-access-token`
    cannot be checked -- and accepting it on the tier alone would accept
    `gitleaks:typo` too, which redacts nothing. The bare tier name is how
    to ask for all of it.
    """
    from forgd_verdict.detectors.gitleaks import GitleaksDetector
    from forgd_verdict.sink.factory import emitted_ids

    ids = emitted_ids([GitleaksDetector()])
    with pytest.raises(SinkUnavailable):
        RedactionPlan.build(_cfg(redact=["gitleaks:aws-access-token"]), ids)
    assert RedactionPlan.build(_cfg(redact=["gitleaks"]), ids).wants(
        "gitleaks:aws-access-token")


def test_two_detectors_naming_one_region_mask_it_once():
    """`regex:ssn` and `regex:ssn-labeled` both report (20, 31) on a
    labelled SSN -- the common path, not an edge case; the core collapses
    exactly that pair for deny reasons.

    Rewriting per finding without tracking coverage nested the second
    mask inside the first:

        employee record ssn [redacted:regex:ssn-labeled]egex:ssn] filed

    Not a leak -- the secret was gone and the backstop agreed -- but it
    mangles the prose this feature exists to preserve and counts one
    region twice.
    """
    text = "employee record ssn 451-39-8827 filed and archived"
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"user.message": text})
    loc = "otel[0].agent.query.user.message"
    a, b = text.index("451"), text.index("451") + 11
    found = {loc: [Finding("regex:ssn", "block", loc, "h1", start=a, end=b),
                   Finding("regex:ssn-labeled", "block", loc, "h2", start=a, end=b)]}
    cfg = _cfg(redact=["regex"])
    plan = RedactionPlan.build(cfg, ["regex", "regex:ssn", "regex:ssn-labeled"])
    out = redact_events([rec], found, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    msg = out[0].attributes["user.message"]
    assert "451-39-8827" not in msg
    assert msg.count("[redacted:") == 1, msg
    assert msg.endswith(" filed and archived"), msg
    assert sum(out[0].redactions.values()) == 1, out[0].redactions


def test_a_tier_the_budget_skipped_is_not_reported_as_nothing_to_redact():
    """`core.scan` drops tier >= T2 when the budget is spent and records
    it in `detectors_skipped`. The findings list then looks exactly like a
    clean scan, so every attribute was forwarded raw -- measured at
    budget_ms=0 on prose containing a name, the value went out verbatim
    with no forgd.redacted marker.

    We do not know what is in that value, so it does not leave.
    """
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"tool.output": "notes about a person here"})
    cfg = _cfg(redact=["presidio"])
    plan = RedactionPlan.build(_cfg(redact=["presidio"]),
                               ["presidio", "presidio:person"])
    out = redact_events([rec], {}, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=[_FakePresidio()],
                        skipped=["presidio_pii"])
    assert "person here" not in out[0].attributes["tool.output"]
    assert out[0].redactions.get("tier-skipped") == 1


def test_a_skipped_tier_nobody_asked_to_redact_changes_nothing():
    """Fail-closed has to be proportionate: a sink redacting only keys
    should not blank every value because the PII tier ran out of budget."""
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"tool.output": "notes about a person here"})
    cfg = _cfg(redact=["regex:aws-access-key"])
    plan = RedactionPlan.build(cfg, ["regex", "regex:aws-access-key"])
    out = redact_events([rec], {}, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS,
                        skipped=["presidio_pii"])
    assert out[0].attributes["tool.output"] == "notes about a person here"


def test_dropping_a_turn_by_name_drops_its_span_events_too():
    """Span events are separate records with their own names, and the
    office agents put the CONTENT on them with the parent's identity keys
    inherited. Matching only a record's own name meant an operator who
    cut `agent.query` kept the record carrying tool.output.
    """
    import json as _json

    from forgd_verdict.otel.payload import decode

    body = {"resourceSpans": [{"scopeSpans": [{"spans": [{
        "name": "agent.query",
        "attributes": [{"key": "user.email",
                        "value": {"stringValue": "a@example.com"}}],
        "events": [{"name": "agent.query.tool_result",
                    "attributes": [{"key": "tool.output",
                                    "value": {"stringValue": "secretish output"}}]}],
    }]}]}]}
    records = decode(_json.dumps(body).encode(), "application/json", "traces")
    assert len(records) == 2, [r.name for r in records]

    cfg = _cfg(drop_events=["agent.query"])
    plan = RedactionPlan.build(cfg, [])
    out = redact_events(records, {}, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    assert out == [], [e.name for e in out]


def test_a_sender_supplying_its_own_body_does_not_collide_with_ours():
    """Both produced `otel[i].<name>.body`. A locator is what adapter 5
    looks findings up by AND what dedupe keys on, so the same secret in
    both collapsed to one finding and one set of offsets was applied to
    two different strings.
    """
    from forgd_verdict.otel.extract import record_units_by_key

    rec = OtelRecord(kind="log", name="ev",
                     attributes={"_body": "the log record body here",
                                 "body": "a sender attribute here"})
    locs = [u.locator for _, u in record_units_by_key(rec, 0)]
    assert len(locs) == len(set(locs)), locs
    # The sender's key keeps the readable name; ours takes the suffix.
    assert "otel[0].ev.body" in locs and "otel[0].ev.body#log" in locs
    # Decoder-agnostic by construction: both payload paths set the same
    # `_body` key (payload.py:154 json, :441 protobuf) and the fix is in
    # extract.py, which sees an OtelRecord whatever produced it.


def test_metadata_never_overwrites_a_redacted_attribute():
    """`update()` replaced the masked value, so the wire said "stamped"
    while `redactions` still reported a redaction -- content and counter
    disagreeing, and the operator losing the attribute silently."""
    text = f"key {KEY} here"
    rec, found = _scan_one(text, "regex:aws-access-key", 4, 4 + len(KEY))
    cfg = _cfg(redact=["regex:aws-access-key"],
               metadata={"user.message": "stamped", "env": "prod"})
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    out = redact_events([rec], found, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    assert out[0].attributes["user.message"].startswith("key [redacted:")
    assert out[0].attributes["env"] == "prod"
    assert out[0].redactions.get("metadata-collision") == 1


def test_three_spanless_findings_of_one_detector_count_as_three():
    """The counts dict comprehension read `counts.get` once per key and
    never saw its own earlier iterations, so it reported 1."""
    from forgd_verdict.sink.redact import _mask_text

    loc = "l"
    fs = [Finding("regex:x", "block", loc, f"h{i}") for i in range(3)]
    plan = RedactionPlan.build(_cfg(redact=["regex:x"]), ["regex:x"])
    _, counts = _mask_text("some text here", fs, plan, [])
    assert counts == {"regex:x": 3}, counts


def test_the_truncation_guard_is_unreachable_and_that_is_asserted():
    """`unit.text` is value[:MAX_UNIT_BYTES] (1,048,576) and every decode
    path already caps an attribute at MAX_VALUE_CHARS (1,000,000), so
    nothing is truncated and the branch never fires.

    Not a leak. But a one-line change to either constant silently decides
    whether the only truncation guard has any coverage, and the two
    constants live in different files.
    """
    from forgd_verdict.otel.extract import MAX_UNIT_BYTES
    from forgd_verdict.otel.payload import MAX_VALUE_CHARS

    assert MAX_VALUE_CHARS <= MAX_UNIT_BYTES, (
        "a decoded attribute can now exceed what the scanner reads, so the "
        "unscanned-tail branch in sink/redact.py is live -- give it a test "
        "that forces it rather than relying on this inequality"
    )


# -- the wire format and the reserved namespace --------------------------


def test_a_batch_mixing_resources_keeps_every_one_of_them():
    """`_body` built ONE resourceLogs entry from `events[0].resource`.

    Chunking is by size and count, not by sender, so a batch routinely
    mixes records. Every non-first resource was discarded, a record whose
    sender said `organization.id: org-B` was serialised under org-A's
    resource, and reversing the inputs flipped which org survived.

    Misattribution is the worse half: a SIEM routing on resource
    attributes files it against the wrong customer.
    """
    import json as _json

    def ev(n, res):
        return RedactedEvent(kind="log", name=n, observed_at="t", surface="s",
                             org="o", resource=res)

    evs = [ev("a", {"k8s.pod": "alpha", "organization.id": "org-A"}),
           ev("b", {"k8s.pod": "beta", "organization.id": "org-B"}),
           ev("c", {"k8s.pod": "alpha", "organization.id": "org-A"})]
    body = _json.loads(OtlpSink(_cfg())._body(evs))

    seen = {}
    for rl in body["resourceLogs"]:
        attrs = {a["key"]: a["value"].get("stringValue")
                 for a in rl["resource"]["attributes"]}
        names = [r["body"]["stringValue"] for r in rl["scopeLogs"][0]["logRecords"]]
        seen[attrs["organization.id"]] = (attrs["k8s.pod"], names)

    assert seen == {"org-A": ("alpha", ["a", "c"]),
                    "org-B": ("beta", ["b"])}
    # And the same batch reversed produces the same grouping, not a
    # different survivor.
    rev = _json.loads(OtlpSink(_cfg())._body(list(reversed(evs))))
    assert len(rev["resourceLogs"]) == 2


def test_a_sender_cannot_supply_an_attribute_in_our_namespace():
    """`forgd.` is ours, and that is enforced at the decode boundary.

    A decoder that accepts any non-empty string key lets a sender set
    `forgd.redacted`, `forgd.surface`, `forgd.org` or `forgd.parent_span`
    and have them survive into the forwarded event.
    """
    import json as _json

    from forgd_verdict.otel.payload import decode

    body = {"resourceLogs": [{"scopeLogs": [{"logRecords": [{
        "body": {"stringValue": "hello"},
        "attributes": [
            {"key": "forgd.redacted", "value": {"stringValue": "false"}},
            {"key": "forgd.surface", "value": {"stringValue": "claude-code-FAKE"}},
            {"key": "forgd.org", "value": {"stringValue": "org-EVIL"}},
            {"key": "forgd.parent_span", "value": {"stringValue": "forged"}},
            {"key": "tool.output", "value": {"stringValue": "kept"}},
        ],
    }]}]}]}
    records = decode(_json.dumps(body).encode(), "application/json", "logs")
    attrs = records[0].attributes
    assert not [k for k in attrs if k.startswith("forgd.")], attrs
    assert attrs["tool.output"] == "kept"


def test_a_forged_parent_span_cannot_keep_an_event_out_of_a_dropped_turn():
    """The sharpest consequence of an unreserved namespace.

    `forgd.parent_span` is written with `setdefault` and READ BACK to
    decide whether an event belongs to a dropped turn. A sender-supplied
    value would win, so setting it to a name nobody dropped would keep the
    event -- carrying the parent's inherited identity keys -- on the wire,
    while an honest sender has both records dropped.
    """
    import json as _json

    from forgd_verdict.otel.payload import decode

    body = {"resourceSpans": [{"scopeSpans": [{"spans": [{
        "name": "agent.query",
        "attributes": [{"key": "user.email",
                        "value": {"stringValue": "alice@customer.test"}}],
        "events": [{"name": "agent.query.tool_result", "attributes": [
            {"key": "tool.output", "value": {"stringValue": "sensitive output"}},
            # The forgery.
            {"key": "forgd.parent_span", "value": {"stringValue": "benign"}},
        ]}],
    }]}]}]}
    records = decode(_json.dumps(body).encode(), "application/json", "traces")
    cfg = _cfg(drop_events=["agent.query"])
    plan = RedactionPlan.build(cfg, [])
    out = redact_events(records, {}, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=_DETS)
    assert out == [], [e.attributes for e in out]


# -- conformance: what every sink type must satisfy ----------------------
#
# These are the behaviours the pipeline depends on. Checking only that the
# declared limits are positive and that describe() has a type and a name
# misses mutations of the real sink: OtlpSink.send returning 0 while still
# shipping the batch, or an event dropped from the body.


def _conformance_sinks():
    return [FakeSink(max_events=100, max_bytes=10_000_000), OtlpSink(_cfg())]


@pytest.mark.parametrize("sink", _conformance_sinks(), ids=lambda s: s.type)
def test_send_returns_the_number_it_accepted(sink, monkeypatch):
    """`SinkPipeline.flush` does `sent += sink.send(batch)` and reports it.

    A sink that ships the batch and returns the wrong number corrupts the
    only counter an operator has. Nothing checked the return value: making
    OtlpSink return 0 left the whole suite green.
    """
    if isinstance(sink, OtlpSink):
        sink._http = HttpTransport(sink._url, 1.0, connect=FakeConnect(200))
    events = [_event(i) for i in range(4)]
    assert sink.send(events) == len(events)


@pytest.mark.parametrize("sink", _conformance_sinks(), ids=lambda s: s.type)
def test_sending_nothing_is_allowed_and_sends_nothing(sink):
    """The pipeline can hand an empty batch through a race with close."""
    assert sink.send([]) == 0


@pytest.mark.parametrize("sink", _conformance_sinks(), ids=lambda s: s.type)
def test_close_is_idempotent(sink):
    """`SinkPipeline.close` calls it, and so does a second close from a
    shutdown path that does not know the first ran."""
    sink.close()
    sink.close()


@pytest.mark.parametrize("sink", _conformance_sinks(), ids=lambda s: s.type)
def test_describe_never_carries_the_credential(sink):
    """`describe()` goes to /stats, which is read by anyone holding the
    metrics token -- a different set of people from whoever holds the
    sink's bearer."""
    blob = repr(sink.describe())
    assert "tok" not in blob.lower() or "authenticated" in blob


def test_every_event_handed_to_the_otlp_sink_appears_in_the_body_once():
    """The completeness check.

    The resource-grouping test catches a dropped event only incidentally,
    and only with several resources -- so with a single-resource batch,
    which is the common case, nothing else catches it.
    """
    import json as _json

    events = [_event(i) for i in range(5)]
    body = _json.loads(OtlpSink(_cfg())._body(events))
    names = [r["body"]["stringValue"]
             for rl in body["resourceLogs"]
             for sl in rl["scopeLogs"]
             for r in sl["logRecords"]]
    assert names == [e.name for e in events], names


# -- an absent `redact` redacts everything --------------------------------

ALL_IDS = ("regex:aws-access-key", "regex:slack-token", "gitleaks:generic",
           "presidio:US_SSN")


def test_no_redact_key_redacts_everything():
    """Without this default, a sink with an endpoint and no `redact`
    forwards every matched secret verbatim while looking configured.
    "The operator did not say" is read as "redact everything".
    """
    plan = RedactionPlan.build(_cfg(redact=[]), ALL_IDS)
    assert plan.detectors == frozenset(ALL_IDS)
    for det in ALL_IDS:
        assert plan.wants(det)


def test_opting_out_is_a_word_someone_has_to_type():
    """Still supported -- a customer may want their own raw telemetry in
    their own SIEM -- but it is a decision a reviewer can grep for
    rather than the state a config falls into by omission."""
    plan = RedactionPlan.build(_cfg(redact=["none"]), ALL_IDS)
    assert plan.detectors == frozenset()
    assert not plan.wants("regex:aws-access-key")


def test_naming_some_detectors_still_means_only_those():
    plan = RedactionPlan.build(_cfg(redact=["presidio"]), ALL_IDS)
    assert plan.wants("presidio:US_SSN")
    assert not plan.wants("regex:aws-access-key")


def test_a_partial_list_no_longer_hides_behind_the_old_default():
    """`redact: [presidio]` while a gitleaks finding occurs forwards the
    gitleaks match raw. That is correct -- it is what the operator asked
    for -- but it is the narrower case rather than what everyone gets."""
    plan = RedactionPlan.build(_cfg(redact=["presidio"]), ALL_IDS)
    assert not plan.wants("gitleaks:generic")
    assert RedactionPlan.build(_cfg(redact=[]), ALL_IDS).wants("gitleaks:generic")


# -- $ENV_VAR in sink config ---------------------------------------------


def test_an_env_reference_is_resolved(monkeypatch):
    """policy.yaml documents `token: $FORGD_SINK_TOKEN_SIEM` and neither
    field went through `env_or_literal`, so the sink sent that string as
    its bearer."""
    monkeypatch.setenv("SINK_TOK", "real-bearer")
    monkeypatch.setenv("SINK_EP", "https://collector.example:4318")
    fs = build_forwarders(
        [{"name": "siem", "endpoint": "$SINK_EP", "token": "$SINK_TOK"}],
        ALL_IDS)
    assert fs[0].config.token == "real-bearer"
    assert fs[0].config.endpoint == "https://collector.example:4318"


def test_an_endpoint_with_an_unset_token_refuses_to_start(monkeypatch):
    """The destination exists and we would talk to it wrongly. That is a
    misconfiguration, not an absence."""
    monkeypatch.delenv("SINK_TOK_MISSING", raising=False)
    with pytest.raises(SinkUnavailable) as e:
        build_forwarders(
            [{"name": "siem", "endpoint": "https://x:4318",
              "token": "$SINK_TOK_MISSING"}], ALL_IDS)
    assert "$SINK_TOK_MISSING" in str(e.value)


def test_an_unset_endpoint_variable_skips_the_sink(monkeypatch, caplog):
    """This deployment does not have that destination.

    The committed policy.yaml is what a fork inherits. A reference to OUR
    variable must not turn their first install into a crashloop -- the
    same call `compliance_orgs` makes for an org with no key.
    """
    import logging

    monkeypatch.delenv("SINK_EP_MISSING", raising=False)
    with caplog.at_level(logging.WARNING):
        fs = build_forwarders(
            [{"name": "azmon", "type": "azure-monitor",
              "endpoint": "$SINK_EP_MISSING"}], ALL_IDS)
    assert fs == []
    # The variable name rides in the structured fields, which is where the
    # rest of this codebase puts anything an operator has to act on.
    named = [r for r in caplog.records
             if "SINK_EP_MISSING" in str(getattr(r, "fields", ""))]
    assert named, caplog.text


def test_a_skipped_sink_does_not_stop_a_configured_one(monkeypatch):
    monkeypatch.delenv("SINK_EP_MISSING", raising=False)
    monkeypatch.setenv("SINK_EP_REAL", "https://real:4318")
    fs = build_forwarders([
        {"name": "absent", "endpoint": "$SINK_EP_MISSING"},
        {"name": "present", "endpoint": "$SINK_EP_REAL"},
    ], ALL_IDS)
    assert [f.config.name for f in fs] == ["present"]


def test_a_literal_still_works():
    fs = build_forwarders(
        [{"name": "siem", "endpoint": "https://x:4318", "token": "literal"}],
        ALL_IDS)
    assert fs[0].config.token == "literal"


def test_no_token_is_fine():
    """The Azure Monitor sink has none -- it uses a managed identity."""
    fs = build_forwarders([{"name": "s", "endpoint": "https://x:4318"}], ALL_IDS)
    assert fs[0].config.token == ""


# -- the protocol is not enforced at runtime --------------------------------


SINK_SURFACE = ("send", "describe", "close", "max_batch_bytes",
                "max_batch_events", "requires_ordering")


@pytest.mark.parametrize("sink_type", ["otlp", "azure-monitor"])
def test_every_built_sink_implements_the_whole_protocol(sink_type):
    """`Sink` is a Protocol, so a missing member is not a type error and
    not an import error -- it is an AttributeError on the first batch.

    A sink missing `max_batch_events` configures cleanly, logs "sink
    configured", and then throws inside `pipeline.chunk` for every batch,
    so nothing is forwarded and the only sign is a warning in the
    collector log.
    """
    endpoint = ("https://dcr.eastus-1.ingest.monitor.azure.com"
                "/dataCollectionRules/dcr-1/streams/Custom-X_CL"
                if sink_type == "azure-monitor" else "https://x:4318")
    sink = build_sink(_cfg(type=sink_type, endpoint=endpoint))
    missing = [m for m in SINK_SURFACE if not hasattr(sink, m)]
    assert not missing, f"{sink_type} is missing {missing}"


@pytest.mark.parametrize("sink_type", ["otlp", "azure-monitor"])
def test_a_built_sink_can_be_chunked(sink_type):
    """The call that actually failed. `chunk` reads two of those members,
    and reading them is the only thing that proves they exist."""
    endpoint = ("https://dcr.eastus-1.ingest.monitor.azure.com"
                "/dataCollectionRules/dcr-1/streams/Custom-X_CL"
                if sink_type == "azure-monitor" else "https://x:4318")
    sink = build_sink(_cfg(type=sink_type, endpoint=endpoint))
    events = [RedactedEvent(kind="log", name="e", observed_at="2026-09-21T00:00:00Z",
                            surface="claude-ai", org="o") for _ in range(3)]
    assert sum(len(b) for b in chunk(events, sink)) == 3


# -- the event name ------------------------------------------------------


def _redact_one(record, findings_by_locator=None):
    from forgd_verdict.policy import load_policy
    policy = load_policy("policy.yaml")
    detectors = policy.build_detectors()
    ids = []
    for d in detectors:
        get = getattr(d, "finding_ids", None)
        ids.extend(get() if get else [d.name])
    cfg = SinkConfig(name="s", endpoint="https://x:4318")
    return redact_events(
        [record], findings_by_locator or {},
        RedactionPlan.build(cfg, ids), cfg,
        surface="claude-code", org="org",
        observed_at="2026-09-21T00:00:00Z", detectors=detectors)


def test_a_secret_in_the_event_name_is_masked():
    """The event name was on the "what this adapter does not redact" list
    and was the only leg of it with no test -- every case used a benign
    `name="agent.query"`.

    A name is sender-controlled and lands verbatim in a
    finding's locator, so a secret used as one was both forwarded raw AND
    copied into the evidence.
    """
    key = "AKIAIOSFODNN7EXAMPLE"
    rec = OtelRecord(kind="log", name=f"agent.query.{key}",
                     attributes={"event.name": "user.message"},
                     resource={"service.name": "claude-code"})
    out = _redact_one(rec)
    assert key not in out[0].name
    assert "[redacted:regex:aws-access-key]" in out[0].name
    assert out[0].redactions.get("regex:aws-access-key") == 1


def test_an_ordinary_event_name_is_untouched():
    """A name is not prose and almost never matches, so this must cost
    nothing visible on every other record."""
    rec = OtelRecord(kind="log", name="agent.query",
                     attributes={"event.name": "user.message"},
                     resource={})
    out = _redact_one(rec)
    assert out[0].name == "agent.query"
    assert out[0].redactions == {}


# -- a credential in the endpoint URL ------------------------------------


def test_userinfo_and_query_are_stripped_from_a_reported_endpoint():
    """A URL carries a credential two ways and both escaped: `describe()`
    returned the full URL, `stats()` carried it, `/stats` serves that to
    metrics-token holders, and a send failure put it in an exception the
    pipeline logs.

    The separate `token` field was always clean -- redacted in the policy
    and reported as a boolean. This makes the endpoint match it.
    """
    from forgd_verdict.sink.base import safe_endpoint

    out = safe_endpoint("https://user:pass@collector.example/x?tenant=abc")
    assert "pass" not in out and "SECRET" not in out
    assert "collector.example" in out


def test_an_ordinary_endpoint_is_unchanged():
    from forgd_verdict.sink.base import safe_endpoint

    assert safe_endpoint("https://collector.example:4318") == \
        "https://collector.example:4318"


def test_describe_does_not_report_the_raw_endpoint():
    sink = OtlpSink(SinkConfig(name="s",
                               endpoint="https://u:p@c.example/x?tenant=abc"))
    import json as _json

    reported = _json.dumps(sink.describe())
    assert "SECRET" not in reported and ":p@" not in reported


def test_the_signal_path_goes_before_the_query():
    """`endpoint.rstrip("/") + PATH_LOGS` appended the signal path AFTER
    any query string -- `...?tenant=abc/v1/logs` -- so a sink
    configured with one posted to a URL that does not exist."""
    sink = OtlpSink(SinkConfig(name="s", endpoint="https://c.example/x?tenant=abc"))
    assert sink._url == "https://c.example/x/v1/logs?tenant=abc"


def test_a_plain_endpoint_still_gets_the_path():
    sink = OtlpSink(SinkConfig(name="s", endpoint="https://c.example:4318"))
    assert sink._url == "https://c.example:4318/v1/logs"


def test_a_value_under_an_attribute_name_that_matches_is_masked_whole():
    # The scan scrubs a finding's locator when the attribute name itself
    # matches a detector, so its findings are keyed by the scrubbed locator
    # and the raw lookup misses.
    other = "AKIAIOSFODNN7EXAMPLE"
    text = f"deploy with {other}"
    rec = OtelRecord(kind="span", name="agent.query", attributes={KEY: text})
    scrubbed = "otel[0].agent.query.<redacted>"
    f = Finding(detector="regex:aws-access-key-id", severity="block", locator=scrubbed,
                excerpt_hash="h", start=text.index(other), end=len(text))
    cfg = _cfg(redact=["regex:aws-access-key-id"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key-id"])
    out = redact_events([rec], {scrubbed: [f]}, plan, cfg, surface="claude-cowork",
                        org="o", observed_at="2026-09-21T00:00:00Z", detectors=_DETS)
    forwarded = str(out[0].attributes)
    assert other not in forwarded and KEY not in forwarded


def test_a_value_whose_findings_sit_under_the_scrubbed_locator_is_masked_in_place():
    from forgd_verdict.core import _cheap, _scrub_locator
    from forgd_verdict.sink.redact import index_findings

    other = "AKIAIOSFODNN7EXAMPLE"
    text = f"deploy with {other} now"
    rec = OtelRecord(kind="span", name="agent.query", attributes={KEY: text})
    raw = f"otel[0].agent.query.{KEY}"
    scrubbed = _scrub_locator(raw, _cheap(_DETS))
    assert scrubbed != raw
    f = Finding(detector="regex:aws-access-key-id", severity="block", locator=scrubbed,
                excerpt_hash="h", start=text.index(other), end=text.index(other) + len(other),
                raw_locator=raw)
    cfg = _cfg(redact=["regex:aws-access-key-id"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key-id"])
    out = redact_events([rec], index_findings([f]), plan, cfg, surface="claude-cowork",
                        org="o", observed_at="2026-09-21T00:00:00Z", detectors=_DETS)
    values = list(out[0].attributes.values())
    assert "deploy with [redacted:regex:aws-access-key-id] now" in values
    assert KEY not in str(out[0].attributes)


def _sink_scrub_calls(n: int) -> int:
    from forgd_verdict.detectors.base import TIER_T1

    calls = []

    class _Counting:
        name, tier = "counting", TIER_T1

        def scan(self, units):
            calls.append(len(units))
            return []

    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={f"attr_number_{k:04d}": f"plain value {k:04d}"
                                 for k in range(n)})
    cfg = _cfg(redact=["counting"])
    plan = RedactionPlan.build(cfg, ["counting"])
    out = redact_events([rec], {}, plan, cfg, surface="claude-cowork", org="o",
                        observed_at="2026-09-21T00:00:00Z", detectors=[_Counting()])
    assert out[0].attributes["attr_number_0003"] == "plain value 0003"
    return len(calls)


@pytest.mark.serial  # timed against core._SCRUB_BUDGET_S
def test_the_attribute_locator_scrub_probes_once_per_detector_whatever_the_attribute_count():
    """One export with many attributes: the locator scrub makes the same
    number of detector calls for 10 attributes as for 400."""
    assert _sink_scrub_calls(400) == _sink_scrub_calls(10)


def test_findings_under_a_whole_redacted_locator_mask_only_their_own_value(monkeypatch):
    """Past the scrub budget both findings sit at the locator `<redacted>`.
    Each value is masked with its own span, never the other unit's. Each
    record is scanned alone, as the collector scans each turn, so neither
    is the left side of a seam and both keep their spans."""
    from forgd_verdict.core import REDACTED, scan
    from forgd_verdict.otel.extract import record_units
    from forgd_verdict.sink.factory import emitted_ids
    from forgd_verdict.sink.redact import index_findings

    monkeypatch.setattr("forgd_verdict.core._SCRUB_BUDGET_BYTES", 0)
    other = "AKIAIOSFODNN7EXAMPLE"
    pad = "pad " * 80
    recs = [OtelRecord(kind="span", name="agent.query",
                       attributes={f"name_{KEY}": f"short {other} {pad}"}),
            OtelRecord(kind="span", name="agent.query",
                       attributes={f"name_{other}": f"{pad}before {KEY} end"})]
    findings = [f for i, rec in enumerate(recs)
                for f in scan(record_units(rec, i), _DETS).findings]
    assert len(findings) == 2 and {f.locator for f in findings} == {REDACTED}
    assert all(f.start is not None for f in findings)
    cfg = _cfg(redact=["regex"])
    plan = RedactionPlan.build(cfg, emitted_ids(_DETS))
    out = redact_events(recs, index_findings(findings), plan, cfg, surface="s",
                        org="o", observed_at="2026-09-21T00:00:00Z", detectors=_DETS)
    mask = f"[redacted:{findings[0].detector}]"
    assert [list(e.attributes.values()) for e in out] == [
        [f"short {mask} {pad}"], [f"{pad}before {mask} end"]]


def test_a_name_whose_dotted_sub_run_matches_masks_its_value_whole_and_is_renamed():
    """A detector need not match a superstring of what it matches: this one
    matches only the exact run inside the attribute name, and the value
    holds nothing."""
    import re

    class _Run:
        name, tier = "run", 0
        pat = re.compile(r"k(?:\.p\d\d){4}")

        def scan(self, units):
            return [Finding("run", "block", u.locator, "0" * 64) for u in units
                    if self.pat.fullmatch(u.text)]

    name = "pre.k.p00.p01.p02.p03.post"
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={name: "an ordinary value", "plain.name": "an ordinary value"})
    cfg = _cfg(redact=["run"])
    plan = RedactionPlan.build(cfg, ["run"])
    (out,) = redact_events([rec], {}, plan, cfg, surface="s", org="o",
                           observed_at="2026-09-21T00:00:00Z", detectors=[_Run()])
    assert out.attributes == {"[redacted:metadata-name:0]": "[redacted:metadata-name:whole-value]",
                              "plain.name": "an ordinary value"}


# -- findings the scan placed beside the unit ------------------------------

B64_KEY = "a2V5PUFLSUFRWUxQTU41SEdaVEhYNFVR"   # base64 of "key=" + KEY
KEY_HEAD, KEY_TAIL = KEY[:10], KEY[10:]


def _forwarded(tmp_path, monkeypatch, attributes, redact="regex:aws-access-key"):
    """The scan the collector runs, then its forward hook; returns the
    forwarded events and the findings the store would get."""
    from forgd_verdict.budget import Budget
    from forgd_verdict.core import scan
    from forgd_verdict.otel.extract import records_units

    app, _ = _collector_with_sink(tmp_path, redact, monkeypatch)
    rec = OtelRecord(kind="span", name="agent.query", attributes=attributes)
    findings = scan(records_units([rec]), app.detectors, Budget(5000)).findings
    forward = app._forward_group("00000000-0000-0000-0000-000000000001")
    forward([rec], findings, "claude-for-m365")
    forward.finish()
    for fwd in app.forwarders:
        fwd.pipeline.flush()
    sent = [e for fwd in app.forwarders for e in fwd.pipeline.sink.events]
    assert len(sent) == 1
    return sent[0], findings


def test_a_base64_wrapped_key_is_not_forwarded(tmp_path, monkeypatch):
    event, findings = _forwarded(tmp_path, monkeypatch,
                                 {"blob.data": f"payload {B64_KEY} end"})
    assert any(f.locator.endswith("#b64") for f in findings)
    wire = repr(event.attributes)
    assert B64_KEY not in wire and KEY not in wire
    assert event.attributes["blob.data"] == "[redacted:regex:aws-access-key:whole-value]"


def test_a_key_split_across_two_attributes_is_not_forwarded(tmp_path, monkeypatch):
    attrs = {"first.part": f"token is {KEY_HEAD}", "second.part": f"{KEY_TAIL} and more"}
    event, findings = _forwarded(tmp_path, monkeypatch, attrs)
    wire = repr(event.attributes)
    assert KEY_HEAD not in wire and KEY_TAIL not in wire
    for key in attrs:
        assert event.attributes[key] == "[redacted:regex:aws-access-key:whole-value]"
    # What is stored does not change: the seam finding sits on the left
    # attribute only, as it did before the sink could see both sides.
    assert [f.to_log() for f in findings] == [
        {"detector": det, "severity": "block",
         "locator": "otel[0].agent.query.first.part",
         "excerpt_hash": findings[0].excerpt_hash, "tool_name": None}
        for det in ("regex:aws-access-key", "gitleaks:aws-access-token")]
    from forgd_verdict.store.base import FindingRow
    assert all(f.seam_others == ("otel[0].agent.query.second.part",) for f in findings)
    assert "second.part" not in repr(findings)
    assert "seam_others" not in FindingRow.__dataclass_fields__


def test_a_wrapped_key_under_a_scrubbed_name_is_not_forwarded(tmp_path, monkeypatch):
    event, _ = _forwarded(tmp_path, monkeypatch,
                          {f"cfg.{KEY}": f"payload {B64_KEY} end"})
    assert B64_KEY not in repr(event.attributes)
    assert KEY not in repr(event.attributes)


def test_a_split_key_under_a_scrubbed_name_is_not_forwarded(tmp_path, monkeypatch):
    attrs = {"first.part": f"token is {KEY_HEAD}",
             f"cfg.{KEY}": f"{KEY_TAIL} and more"}
    event, _ = _forwarded(tmp_path, monkeypatch, attrs)
    wire = repr(event.attributes)
    assert KEY_HEAD not in wire and KEY_TAIL not in wire and KEY not in wire
