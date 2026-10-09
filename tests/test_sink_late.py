"""The slow redaction tiers run after the export is acknowledged.

Presidio is off on the collector's ingest path, so a forwarded stream kept
names, emails and phone numbers verbatim. These tests use a stand-in T2
detector so they need neither Presidio nor its model.
"""

from __future__ import annotations

import textwrap
import threading

import pytest

from forgd_verdict.budget import Budget
from forgd_verdict.core import scan
from forgd_verdict.detectors.base import TIER_T2
from forgd_verdict.models import Finding
from forgd_verdict.otel.app import Collector
from forgd_verdict.otel.extract import record_units_by_key
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.policy import load_policy
from forgd_verdict.sink.base import SinkUnavailable
from forgd_verdict.sink.fake import FakeSink

ORG = "00000000-0000-0000-0000-000000000001"
NAME = "Alice Fernsby"
KEY = "AKIA" + "IOSFODNN7EXAMPLE"


class FakeNER:
    """Finds NAME wherever it appears, with spans, like Presidio does."""

    name = "presidio_pii"
    finding_prefix = "presidio"
    tier = TIER_T2
    severity = "warn"

    def __init__(self, *, fail: bool = False, gate: threading.Event | None = None):
        self.fail = fail
        self.gate = gate
        self.calls = 0

    def finding_ids(self):
        return ["presidio:person"]

    def available(self):
        return True

    def scan(self, units):
        self.calls += 1
        if self.gate is not None:
            self.gate.wait(5)
        if self.fail:
            raise RuntimeError("model failed to load")
        out = []
        for u in units:
            i = u.text.find(NAME)
            while i >= 0:
                out.append(Finding(detector="presidio:person", severity="warn",
                                   locator=u.locator, excerpt_hash="h",
                                   start=i, end=i + len(NAME)))
                i = u.text.find(NAME, i + 1)
        return out


def _app(tmp_path, ner, redact: str | None = None):
    red = f"redact: [{redact}]" if redact else ""
    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: test-salt}}
        server: {{store: ""}}
        otel:
          orgs:
            - {{name: demo, id: "{ORG}", token: a-token-long-enough-to-be-one}}
        sinks:
          - name: siem
            type: otlp
            endpoint: https://collector.test
            {red}
    """), encoding="utf-8")
    app = Collector(load_policy(str(pol)), store=None, late_detectors=[ner])
    for fwd in app.forwarders:
        fwd.pipeline.sink = FakeSink(max_events=100, max_bytes=10_000_000)
    return app


def _send(app, text):
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"service.name": "office-agent",
                                 "prompt.id": "p1", "user.message": text})
    units = [u for _, u in record_units_by_key(rec, 0)]
    result = scan(units, app.detectors, Budget(5000))
    forward = app._forward_group(ORG)
    forward([rec], result.findings, "claude-for-m365", result.detectors_skipped)
    forward.finish()


def _sent(app):
    fwd = app.forwarders[0]
    if fwd.late is not None:
        fwd.late.drain()
    fwd.pipeline.flush()
    return [e for b in fwd.pipeline.sink.batches for e in b]


def test_a_name_is_masked_on_the_way_out(tmp_path):
    ner = FakeNER()
    app = _app(tmp_path, ner)
    try:
        _send(app, f"please email {NAME} the report")
        (event,) = _sent(app)
    finally:
        app.close()
    msg = event.attributes["user.message"]
    assert NAME not in msg
    assert msg == "please email [redacted:presidio:person] the report"
    assert event.redactions == {"presidio:person": 1}


def test_the_cheap_tiers_still_mask_in_the_same_event(tmp_path):
    """The late stage merges its findings with the inline ones; it does
    not replace them."""
    app = _app(tmp_path, FakeNER())
    try:
        _send(app, f"{NAME} used {KEY} again")
        (event,) = _sent(app)
    finally:
        app.close()
    msg = event.attributes["user.message"]
    assert NAME not in msg and KEY not in msg


def test_the_ingest_path_does_not_wait_for_the_slow_tier(tmp_path):
    """The whole point: Presidio's cost lands after the 200."""
    gate = threading.Event()
    ner = FakeNER(gate=gate)
    app = _app(tmp_path, ner)
    fwd = app.forwarders[0]
    try:
        # Stop the background worker from racing the assertion.
        fwd.late._closing.set()
        fwd.late._wake.set()
        fwd.late._worker.join(timeout=5)
        _send(app, f"call {NAME}")
        # Returned without the detector having run at all.
        assert ner.calls == 0
        assert fwd.late.stats()["queued"] == 1
        gate.set()
        fwd.late.drain()
        assert ner.calls >= 1
    finally:
        gate.set()
        app.close()


def test_a_failed_slow_tier_masks_whole_values_rather_than_forwarding(tmp_path):
    """A T2 pass that fails must
    not send the value it could not look at."""
    app = _app(tmp_path, FakeNER(fail=True))
    try:
        _send(app, f"please email {NAME} the report")
        (event,) = _sent(app)
        assert app.forwarders[0].late.stats()["failed"] == 1
    finally:
        app.close()
    msg = event.attributes["user.message"]
    assert NAME not in msg
    assert msg.startswith("[redacted:tier-skipped:presidio_pii")


def test_a_sink_that_does_not_redact_the_slow_tier_gets_no_late_stage(tmp_path):
    """No Presidio pass for a sink that only asked for keys: the cost is
    paid only by the sinks that need it."""
    ner = FakeNER()
    app = _app(tmp_path, ner, redact="regex:aws-access-key")
    try:
        assert app.forwarders[0].late is None
        _send(app, f"{NAME} used {KEY}")
        (event,) = _sent(app)
    finally:
        app.close()
    assert ner.calls == 0
    msg = event.attributes["user.message"]
    assert KEY not in msg and NAME in msg


def test_naming_the_slow_tier_without_it_available_still_refuses(tmp_path):
    """Unchanged rule: `redact: [presidio:person]` on a deployment with no
    T2 tier forwards nothing rather than forwarding uncensored."""
    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: test-salt}}
        server: {{store: ""}}
        otel:
          orgs:
            - {{name: demo, id: "{ORG}", token: a-token-long-enough-to-be-one}}
        sinks:
          - name: siem
            type: otlp
            endpoint: https://collector.test
            redact: [presidio:person]
    """), encoding="utf-8")
    with pytest.raises(SinkUnavailable, match="presidio:person"):
        Collector(load_policy(str(pol)), store=None, late_detectors=[])


def test_a_full_late_queue_drops_the_oldest_with_a_counter(tmp_path):
    app = _app(tmp_path, FakeNER())
    late = app.forwarders[0].late
    try:
        late._closing.set()
        late._wake.set()
        late._worker.join(timeout=5)
        late.max_queue = 2
        for i in range(5):
            _send(app, f"message {i} for {NAME}")
        s = late.stats()
        assert s["queued"] == 2 and s["dropped"] == 3
    finally:
        app.close()


def test_no_sinks_means_no_slow_tier_is_ever_built(tmp_path, monkeypatch):
    """Loading Presidio costs seconds and about a gigabyte; a collector
    with nowhere to forward must not pay it."""
    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: test-salt}}
        server: {{store: ""}}
        otel:
          orgs:
            - {{name: demo, id: "{ORG}", token: a-token-long-enough-to-be-one}}
          sink_detectors:
            presidio_pii: {{enabled: true}}
    """), encoding="utf-8")
    called = []
    monkeypatch.setattr(Collector, "_late_detectors",
                        lambda self: called.append(1) or [])
    app = Collector(load_policy(str(pol)), store=None)
    app.close()
    assert called == []


# -- shutdown, and redacting what was scanned ----------------------------

def test_a_pass_running_at_shutdown_is_counted_not_stranded(tmp_path):
    """If close() gives the worker a fixed 5 s and then closes the pipeline
    under it, a pass that finishes later offers into a closed pipeline and
    its events sit there forever with nothing counting them."""
    gate = threading.Event()
    app = _app(tmp_path, FakeNER(gate=gate))
    fwd = app.forwarders[0]
    _send(app, f"call {NAME}")
    # Wait for the worker to pick the job up and block inside the tier.
    for _ in range(200):
        if fwd.late._inflight:
            break
        threading.Event().wait(0.01)
    assert fwd.late._inflight == 1
    fwd.late.close(timeout_s=0.1)
    fwd.pipeline.close()
    assert fwd.late.stats()["dropped"] == 1
    # The pass now finishes and offers into the closed pipeline: counted.
    gate.set()
    fwd.late._worker.join(timeout=60)
    assert not fwd.late._worker.is_alive()
    assert fwd.pipeline.stats()["dropped"] == 1
    assert fwd.pipeline.sink.batches == []


def test_nothing_is_accepted_once_closing(tmp_path):
    app = _app(tmp_path, FakeNER())
    fwd = app.forwarders[0]
    fwd.late.close()
    _send(app, f"call {NAME}")
    assert fwd.late.stats()["dropped"] == 1
    assert fwd.late.stats()["queued"] == 0
    app.close()


def test_the_late_stage_redacts_the_record_as_it_was_scanned(tmp_path):
    """A caller changing an attribute after offer() must not change what is
    forwarded: the inline findings describe the record as it was."""
    app = _app(tmp_path, FakeNER())
    fwd = app.forwarders[0]
    late = fwd.late
    late._closing.set()
    late._wake.set()
    late._worker.join(timeout=5)
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"service.name": "office-agent",
                                 "prompt.id": "p1", "user.message": "nothing here"})
    units = [u for _, u in record_units_by_key(rec, 0)]
    result = scan(units, app.detectors, Budget(5000))
    forward = app._forward_group(ORG)
    forward([rec], result.findings, "claude-for-m365", ())
    forward.finish()
    # Mutated after the ingest path handed it over.
    rec.attributes["user.message"] = f"now with {KEY}"
    late.drain()
    fwd.pipeline.flush()
    (event,) = [e for b in fwd.pipeline.sink.batches for e in b]
    assert event.attributes["user.message"] == "nothing here"
    app.close()


@pytest.mark.parametrize("sinks, needed", [
    ([], False),
    ([{"name": "s", "endpoint": "https://x"}], True),              # redact omitted
    ([{"name": "s", "endpoint": "https://x", "redact": ["regex"]}], False),
    ([{"name": "s", "endpoint": "https://x", "redact": ["none"]}], False),
    ([{"name": "s", "endpoint": "https://x", "redact": ["presidio"]}], True),
    ([{"name": "s", "endpoint": "https://x", "redact": ["presidio:person"]}], True),
    ([{"name": "s", "endpoint": "$FORGD_UNSET_SINK_ENDPOINT"}], False),  # not running here
])
def test_the_model_is_loaded_only_when_a_running_sink_may_use_it(sinks, needed,
                                                                 monkeypatch):
    from forgd_verdict.sink.factory import sinks_may_need_late

    monkeypatch.delenv("FORGD_UNSET_SINK_ENDPOINT", raising=False)
    assert sinks_may_need_late(sinks) is needed


# -- an attribute name that matches, with a late finding in its value ------

NAME_KEY = "AKIAQYLPMN5HGZTHX4UQ"  # gitleaks:allow


def _send_record(app, attributes):
    from forgd_verdict.otel.extract import records_units

    rec = OtelRecord(kind="span", name="agent.query", attributes=attributes)
    result = scan(records_units([rec]), app.detectors, Budget(5000))
    forward = app._forward_group(ORG)
    forward([rec], result.findings, "claude-for-m365", result.detectors_skipped)
    forward.finish()


def test_a_cheap_finding_under_a_scrubbed_name_is_masked_beside_a_late_one(tmp_path):
    import base64

    blob = base64.b64encode(f"aws_access_key_id = {KEY}".encode()).decode()
    app = _app(tmp_path, FakeNER())
    try:
        _send_record(app, {f"tool.{NAME_KEY}": f"{NAME} pasted {blob} here"})
        (event,) = _sent(app)
    finally:
        app.close()
    wire = repr(event.attributes)
    for value in (NAME, blob, KEY, NAME_KEY):
        assert value not in wire


def test_a_seam_with_its_left_half_under_a_scrubbed_name_is_masked_on_both_sides(tmp_path):
    head, tail = KEY[:10], KEY[10:]
    app = _app(tmp_path, FakeNER())
    try:
        _send_record(app, {f"tool.{NAME_KEY}": f"{NAME} token is {head}",
                           "second.part": f"{tail} and more"})
        (event,) = _sent(app)
    finally:
        app.close()
    wire = repr(event.attributes)
    for value in (NAME, head, tail, NAME_KEY):
        assert value not in wire


def test_an_export_over_the_bound_forwards_the_groups_that_fit():
    from forgd_verdict.detectors.t0_regex import T0RegexDetector
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.factory import emitted_ids
    from forgd_verdict.sink.late import LateGroup, LateJob, LateRedactor
    from forgd_verdict.sink.redact import RedactionPlan

    bound = 10
    cfg = SinkConfig(name="siem", endpoint="https://collector.test")
    t0, ner = T0RegexDetector(), FakeNER()
    plan = RedactionPlan.build(cfg, emitted_ids([t0, ner]))
    offered = []
    late = LateRedactor(plan=plan, config=cfg, offer=offered.extend,
                        cheap_detectors=[t0], late_detectors=[ner],
                        max_queue=bound, background=False)
    sizes = [1, 2, 3, 1, 4, 2, 1, 3, 2, 1, 4, 3, 2, 1]
    groups = [LateGroup([OtelRecord(kind="log", name="evt",
                                    attributes={"user.message": f"turn {g} part {i}"})
                         for i in range(n)], [], "s")
              for g, n in enumerate(sizes)]
    total = sum(sizes)
    assert total == 3 * bound
    late.offer(LateJob(groups, ORG, "2026-10-05T00:00:00Z"))
    late.drain()
    s = late.stats()
    assert 0 < len(offered) <= bound
    assert len(offered) + s["dropped"] == total
    assert s["processed"] == len(offered)
