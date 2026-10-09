"""An over-size attribute, through the receiver to a sink.

Decode keeps a capped value's head (MAX_VALUE_CHARS), and its tail on
`.tail`; the characters between them are discarded. The forwarded event
carries only the head, scanned in full. These pin that a credential in the
discarded middle or in the tail never reaches a sink, on the inline and the
late path and from both encodings, and that one in the head is masked.
"""

from __future__ import annotations

import dataclasses
import json
import textwrap

import pytest
from conftest import ASGIClient
from test_otel_payload import _kv, _len_field, _str_field
from test_sink_late import FakeNER

from forgd_verdict.otel.app import Collector
from forgd_verdict.otel.payload import MAX_VALUE_CHARS, TAIL_VALUE_CHARS, CappedValue, decode
from forgd_verdict.policy import load_policy
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.fake import FakeSink
from forgd_verdict.sink.otlp import OtlpSink

ORG = "00000000-0000-0000-0000-000000000001"
TOKEN = "a-token-long-enough-to-be-one"
RESOURCE = {"service.name": "claude-code", "organization.id": ORG}

HEAD = "AKIA" + "IOSFODNN7HEAD001"
GAP = "AKIA" + "IOSFODNN7GAPS001"
TAIL = "AKIA" + "IOSFODNN7TAIL001"


def _flat() -> str:
    """HEAD in the head, GAP in the discarded middle, TAIL in the tail."""
    return (f"head {HEAD} " + " " * MAX_VALUE_CHARS
            + f" gap {GAP} " + " " * (TAIL_VALUE_CHARS * 2)
            + f" tail {TAIL} " + " " * 1000)


def _nested() -> str:
    """One element of an array, over MAX_VALUE_CHARS, cut by `_bounded`."""
    return f"head {HEAD} " + " " * MAX_VALUE_CHARS + f" gap {GAP} tail {TAIL} "


# AnyValue, per encoding: a string, an array holding one string, or a
# kvlist holding one.
def _json_any(kind: str) -> dict:
    if kind == "flat":
        return {"stringValue": _flat()}
    if kind == "kvlist":
        return {"kvlistValue": {"values": [
            {"key": "k", "value": {"stringValue": _nested()}}]}}
    return {"arrayValue": {"values": [{"stringValue": _nested()}]}}


def _pb_any(kind: str) -> bytes:
    if kind == "flat":
        return _str_field(1, _flat())
    return _len_field(5, _len_field(1, _str_field(1, _nested())))


def _json_body(kind: str) -> bytes:
    attrs = [{"key": "event.name", "value": {"stringValue": "claude_code.user_prompt"}},
             {"key": "prompt.id", "value": {"stringValue": "turn-1"}},
             {"key": "prompt", "value": _json_any(kind)}]
    return json.dumps({"resourceLogs": [{
        "resource": {"attributes": [{"key": k, "value": {"stringValue": v}}
                                    for k, v in RESOURCE.items()]},
        "scopeLogs": [{"logRecords": [{"attributes": attrs}]}],
    }]}).encode()


def _pb_body(kind: str) -> bytes:
    attrs = (_len_field(6, _kv("event.name", "claude_code.user_prompt"))
             + _len_field(6, _kv("prompt.id", "turn-1"))
             + _len_field(6, _str_field(1, "prompt") + _len_field(2, _pb_any(kind))))
    resource = _len_field(1, b"".join(_len_field(1, _kv(k, v)) for k, v in RESOURCE.items()))
    return _len_field(1, resource + _len_field(2, _len_field(2, attrs)))


ENCODINGS = {
    "json": ("application/json", _json_body),
    "protobuf": ("application/x-protobuf", _pb_body),
}

# The protobuf decoder reads a kvlist entry's key and not its value, so a
# protobuf kvlist has nothing over the cap to cut.
CASES = [("json", "flat"), ("json", "array"), ("json", "kvlist"),
         ("protobuf", "flat"), ("protobuf", "array")]


def _collector(tmp_path, late: bool) -> Collector:
    redact = "" if late else "redact: [regex:aws-access-key]"
    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: test-salt}}
        server: {{store: ""}}
        otel:
          orgs:
            - {{name: demo, id: "{ORG}", token: {TOKEN}}}
        sinks:
          - name: siem
            type: otlp
            endpoint: https://collector.test
            {redact}
    """), encoding="utf-8")
    app = Collector(load_policy(str(pol)), store=None, late_detectors=[FakeNER()])
    for fwd in app.forwarders:
        fwd.pipeline.sink = FakeSink(max_events=100, max_bytes=50_000_000)
    assert (app.forwarders[0].late is not None) is late
    return app


@pytest.mark.parametrize("encoding, kind", CASES)
def test_the_decoded_value_holds_the_planted_keys_where_intended(encoding, kind):
    """Guards the test's own construction: GAP must be in neither the head
    nor the tail, and TAIL must be outside the head."""
    ctype, body = ENCODINGS[encoding]
    (rec,) = decode(body(kind), ctype, "logs")
    value = rec.attributes["prompt"]
    assert isinstance(value, CappedValue) and value.gap > 0
    assert HEAD in value
    assert GAP not in value and GAP not in value.tail
    assert TAIL not in value
    if kind == "flat":
        assert TAIL in value.tail


@pytest.mark.parametrize("late", [False, True], ids=["inline", "late"])
@pytest.mark.parametrize("encoding, kind", CASES)
async def test_only_the_masked_head_of_an_oversize_value_is_forwarded(
        tmp_path, encoding, kind, late):
    ctype, body = ENCODINGS[encoding]
    app = _collector(tmp_path, late)
    try:
        status, _ = await ASGIClient(app).post(
            "/v1/logs", body(kind),
            {"authorization": f"Bearer {TOKEN}", "content-type": ctype})
        assert status == 200
        fwd = app.forwarders[0]
        if fwd.late is not None:
            # Joins the worker, which may be mid-pass when `drain` would
            # find the queue already empty.
            fwd.late.close()
        fwd.pipeline.flush()
        events = fwd.pipeline.sink.events
    finally:
        app.close()

    (event,) = [e for e in events if "prompt" in e.attributes]
    value = event.attributes["prompt"]
    assert "[redacted:" in value

    wire = [
        json.dumps(dataclasses.asdict(e), default=str) for e in events
    ] + [OtlpSink(SinkConfig(name="s", endpoint="https://collector.test"))._body(events)
         .decode("utf-8")]
    for text in wire:
        for planted in (HEAD, GAP, TAIL):
            assert planted not in text

    # In memory too: nothing forwarded still carries the discarded parts.
    for e in events:
        for v in [*e.attributes.values(), *e.resource.values()]:
            assert not getattr(v, "tail", "")
            for planted in (HEAD, GAP, TAIL):
                assert planted not in str(v)
