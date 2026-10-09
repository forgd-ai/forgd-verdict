"""OTLP decoding, both encodings Anthropic can be configured to send.

The protobuf encoder below is test-only. Writing it out longhand is the
point: it is an independent implementation of the wire format, so a decoder
bug has to be made twice to pass.
"""

from __future__ import annotations

import json

import pytest

from forgd_verdict.otel.payload import (
    KIND_LOG,
    KIND_SPAN,
    SIGNAL_LOGS,
    SIGNAL_TRACES,
    DecodeError,
    decode,
)

# --- a minimal protobuf encoder, for tests only ---------------------------


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _tag(field_no: int, wire: int) -> bytes:
    return _varint(field_no << 3 | wire)


def _len_field(field_no: int, payload: bytes) -> bytes:
    return _tag(field_no, 2) + _varint(len(payload)) + payload


def _str_field(field_no: int, text: str) -> bytes:
    return _len_field(field_no, text.encode("utf-8"))


def _any_string(text: str) -> bytes:
    return _str_field(1, text)


def _kv(key: str, value: str) -> bytes:
    return _str_field(1, key) + _len_field(2, _any_string(value))


def _attrs(field_no: int, pairs: dict[str, str]) -> bytes:
    return b"".join(_len_field(field_no, _kv(k, v)) for k, v in pairs.items())


def logs_protobuf(records: list[dict], resource: dict[str, str]) -> bytes:
    log_records = b"".join(
        _len_field(2, _attrs(6, r["attributes"]) + _len_field(5, _any_string(r["body"])))
        for r in records
    )
    scope_logs = _len_field(2, log_records)
    resource_msg = _len_field(1, _attrs(1, resource))
    return _len_field(1, resource_msg + scope_logs)


def traces_protobuf(spans: list[dict], resource: dict[str, str]) -> bytes:
    span_msgs = b""
    for s in spans:
        body = _str_field(5, s["name"]) + _attrs(9, s["attributes"])
        for event in s.get("events", []):
            body += _len_field(
                11, _str_field(2, event["name"]) + _attrs(3, event["attributes"])
            )
        span_msgs += _len_field(2, body)
    scope_spans = _len_field(2, span_msgs)
    resource_msg = _len_field(1, _attrs(1, resource))
    return _len_field(1, resource_msg + scope_spans)


# --- the equivalent JSON --------------------------------------------------


def _json_attrs(pairs: dict[str, str]) -> list[dict]:
    return [{"key": k, "value": {"stringValue": v}} for k, v in pairs.items()]


def logs_json(records: list[dict], resource: dict[str, str]) -> bytes:
    return json.dumps(
        {
            "resourceLogs": [
                {
                    "resource": {"attributes": _json_attrs(resource)},
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "attributes": _json_attrs(r["attributes"]),
                                    "body": {"stringValue": r["body"]},
                                }
                                for r in records
                            ]
                        }
                    ],
                }
            ]
        }
    ).encode()


def traces_json(spans: list[dict], resource: dict[str, str]) -> bytes:
    return json.dumps(
        {
            "resourceSpans": [
                {
                    "resource": {"attributes": _json_attrs(resource)},
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "name": s["name"],
                                    "attributes": _json_attrs(s["attributes"]),
                                    "events": [
                                        {
                                            "name": e["name"],
                                            "attributes": _json_attrs(e["attributes"]),
                                        }
                                        for e in s.get("events", [])
                                    ],
                                }
                                for s in spans
                            ]
                        }
                    ],
                }
            ]
        }
    ).encode()


# --- tests ----------------------------------------------------------------

RESOURCE = {"service.name": "claude-code", "organization.id": "org-abc"}
CODE_RECORDS = [
    {
        "attributes": {
            "event.name": "claude_code.user_prompt",
            "prompt": "deploy with AKIAIOSFODNN7EXAMPLE",
            "user.email": "a@example.com",
        },
        "body": "",
    }
]


def _pb_kvlist_record(inner: dict[str, str]) -> bytes:
    kvlist = b"".join(_len_field(1, _kv(k, v)) for k, v in inner.items())
    attr = _len_field(6, _str_field(1, "tool_parameters") + _len_field(2, _len_field(6, kvlist)))
    record = _len_field(2, attr + _len_field(5, _any_string("tool call")))
    resource_msg = _len_field(1, _attrs(1, RESOURCE))
    return _len_field(1, resource_msg + _len_field(2, record))


def _json_kvlist_record(inner: dict[str, str]) -> bytes:
    return json.dumps({"resourceLogs": [{
        "resource": {"attributes": _json_attrs(RESOURCE)},
        "scopeLogs": [{"logRecords": [{
            "attributes": [{"key": "tool_parameters", "value": {"kvlistValue": {"values": [
                {"key": k, "value": {"stringValue": v}} for k, v in inner.items()]}}}],
            "body": {"stringValue": "tool call"},
        }]}],
    }]}).encode()


def test_a_protobuf_kvlist_value_is_decoded_like_json():
    inner = {"command": "deploy", "token": "AKIAIOSFODNN7EXAMPLE"}
    from_pb = decode(_pb_kvlist_record(inner), "application/x-protobuf", SIGNAL_LOGS)
    from_json = decode(_json_kvlist_record(inner), "application/json", SIGNAL_LOGS)
    assert from_pb == from_json
    assert "AKIAIOSFODNN7EXAMPLE" in from_pb[0].attributes["tool_parameters"]


def test_json_and_protobuf_decode_identically():
    """The encoding is the admin's choice in a console we do not control.

    If the two disagree, detection silently depends on a dropdown.
    """
    from_json = decode(logs_json(CODE_RECORDS, RESOURCE), "application/json", SIGNAL_LOGS)
    from_pb = decode(logs_protobuf(CODE_RECORDS, RESOURCE), "application/x-protobuf", SIGNAL_LOGS)
    assert from_json == from_pb
    assert len(from_json) == 1
    assert from_json[0].kind == KIND_LOG
    assert from_json[0].name == "claude_code.user_prompt"
    assert from_json[0].attributes["prompt"] == "deploy with AKIAIOSFODNN7EXAMPLE"
    assert from_json[0].resource["organization.id"] == "org-abc"


def test_spans_and_their_events_both_decode_in_both_encodings():
    """Office agents put content on span events, not only the span.

    A decoder that reads spans but drops their events reports that a turn
    happened and nothing about what was in it.
    """
    spans = [
        {
            "name": "agent.query",
            "attributes": {"session.id": "s-1"},
            "events": [
                {
                    "name": "agent.tool_execution",
                    "attributes": {"tool.input": "ssh-rsa AAAAB3NzaC1yc2E"},
                }
            ],
        }
    ]
    from_json = decode(traces_json(spans, RESOURCE), "application/json", SIGNAL_TRACES)
    from_pb = decode(traces_protobuf(spans, RESOURCE), "application/x-protobuf", SIGNAL_TRACES)
    assert from_json == from_pb
    assert [r.name for r in from_json] == ["agent.query", "agent.tool_execution"]
    assert from_json[0].kind == KIND_SPAN
    assert from_json[1].attributes["tool.input"] == "ssh-rsa AAAAB3NzaC1yc2E"
    # Resource identity reaches the event, not just the root span.
    assert from_json[1].resource["organization.id"] == "org-abc"


def test_the_log_body_is_scannable_but_cannot_shadow_an_attribute():
    records = [{"attributes": {"event.name": "x"}, "body": "sk-ant-api01-SECRET"}]
    rec = decode(logs_json(records, RESOURCE), "application/json", SIGNAL_LOGS)[0]
    assert rec.attributes["_body"] == "sk-ant-api01-SECRET"
    assert rec.attributes["event.name"] == "x"


def test_get_prefers_the_record_over_the_resource():
    """Identity lives in the resource for some senders and the record for
    others; a caller should not have to know which."""
    records = [{"attributes": {"organization.id": "org-record"}, "body": ""}]
    rec = decode(logs_json(records, RESOURCE), "application/json", SIGNAL_LOGS)[0]
    assert rec.get("organization.id") == "org-record"
    records = [{"attributes": {}, "body": ""}]
    rec = decode(logs_json(records, RESOURCE), "application/json", SIGNAL_LOGS)[0]
    assert rec.get("organization.id") == "org-abc"


@pytest.mark.parametrize(
    "body,ctype",
    [
        (b"not json at all", "application/json"),
        (b"\xff\xff\xff\xff", "application/x-protobuf"),
        # A length prefix that runs past the end of the buffer. The failure
        # mode to avoid is reading adjacent memory or hanging, not the error.
        (b"\x0a\xff\x01ab", "application/x-protobuf"),
    ],
)
def test_malformed_bodies_raise_rather_than_crash(body, ctype):
    with pytest.raises(DecodeError):
        decode(body, ctype, SIGNAL_LOGS)


def test_an_unsupported_content_type_is_refused():
    with pytest.raises(DecodeError):
        decode(b"", "application/grpc", SIGNAL_LOGS)


def test_an_empty_body_is_no_records_not_an_error():
    """An exporter flushing an empty batch is normal; 4xx makes it retry."""
    assert decode(b"{}", "application/json", SIGNAL_LOGS) == []


def test_a_logs_body_read_as_traces_yields_nothing_rather_than_phantom_spans():
    """The field numbers collide: resource_logs and resource_spans are both
    field 1, scope_logs and scope_spans both 2, log_records and spans both 2.

    Before `signal` existed this decoded a logs payload a second time as
    spans, inventing a record with a garbage name for every real one. A
    dashboard counting those would have reported roughly double the traffic
    and attributed half of it to a surface that never sent anything.
    """
    body = logs_protobuf(CODE_RECORDS, RESOURCE)
    assert decode(body, "application/x-protobuf", SIGNAL_LOGS)
    assert decode(body, "application/x-protobuf", SIGNAL_TRACES) == []


def test_an_unknown_signal_is_refused():
    with pytest.raises(DecodeError):
        decode(b"{}", "application/json", "metrics")


def test_a_span_event_inherits_correlation_but_not_content():
    """An office agent turn is one span plus its events: the span carries
    the identity, the events carry the content.

    Without inheritance the turn split into several records, which counts
    one prompt as several requests. Inheriting CONTENT instead would be the
    opposite error -- the same value scanned twice, reported as two.
    """
    spans = [
        {
            "name": "agent.query",
            "attributes": {"session.id": "s-1", "prompt.id": "t-1",
                           "tool.input": "parent content here"},
            "events": [
                {"name": "agent.tool_execution",
                 "attributes": {"tool.output": "child content here"}}
            ],
        }
    ]
    for body, ctype in (
        (traces_json(spans, RESOURCE), "application/json"),
        (traces_protobuf(spans, RESOURCE), "application/x-protobuf"),
    ):
        span, event = decode(body, ctype, SIGNAL_TRACES)
        assert event.attributes["session.id"] == "s-1"
        assert event.attributes["prompt.id"] == "t-1"
        assert "tool.input" not in event.attributes
        assert event.attributes["tool.output"] == "child content here"


def test_an_event_keeps_its_own_value_when_it_has_one():
    spans = [
        {
            "name": "agent.query",
            "attributes": {"session.id": "parent"},
            "events": [{"name": "e", "attributes": {"session.id": "child"}}],
        }
    ]
    _, event = decode(traces_json(spans, RESOURCE), "application/json", SIGNAL_TRACES)
    assert event.attributes["session.id"] == "child"


# -- a batch over the record cap is refused whole -------------------------


def _log_batch(n, tail_text=None):
    import json as _json

    recs = [{"body": {"stringValue": f"benign {i}"},
             "attributes": [{"key": "event.name",
                             "value": {"stringValue": "user.message"}}]}
            for i in range(n)]
    if tail_text:
        recs.append({"body": {"stringValue": tail_text},
                     "attributes": [{"key": "event.name",
                                     "value": {"stringValue": "user.message"}}]})
    return _json.dumps({"resourceLogs": [
        {"resource": {"attributes": []},
         "scopeLogs": [{"logRecords": recs}]}]}).encode()


def test_a_batch_at_the_cap_decodes_whole():
    from forgd_verdict.otel.payload import MAX_RECORDS, decode

    assert len(decode(_log_batch(MAX_RECORDS), "application/json", "logs")) == MAX_RECORDS


def test_one_record_past_the_cap_refuses_the_batch():
    from forgd_verdict.otel.payload import MAX_RECORDS, TooManyRecords, decode

    with pytest.raises(TooManyRecords):
        decode(_log_batch(MAX_RECORDS + 1), "application/json", "logs")


def test_a_protobuf_batch_past_the_cap_is_refused():
    from forgd_verdict.otel.payload import MAX_RECORDS, TooManyRecords, decode

    recs = [{"attributes": {"event.name": "user.message"}, "body": f"b{i}"}
            for i in range(MAX_RECORDS + 1)]
    with pytest.raises(TooManyRecords):
        decode(logs_protobuf(recs, RESOURCE), "application/x-protobuf", "logs")


def test_span_events_count_toward_the_cap():
    """MAX_RECORDS spans, one of them with an event, is one record over."""
    from forgd_verdict.otel.payload import MAX_RECORDS, TooManyRecords, decode

    spans = [{"name": f"s{i}", "attributes": {"k": "v"}} for i in range(MAX_RECORDS - 1)]
    spans.append({"name": "last", "attributes": {"k": "v"},
                  "events": [{"name": "e", "attributes": {"k": "v"}}]})
    with pytest.raises(TooManyRecords):
        decode(traces_json(spans, RESOURCE), "application/json", "traces")


def test_an_ordinary_batch_drops_nothing():
    out = decode(_log_batch(5), "application/json", "logs")
    assert len(out) == 5


def test_a_message_with_more_fields_than_the_cap_is_refused():
    from forgd_verdict.otel import payload

    with pytest.raises(payload.DecodeError):
        list(payload._walk(b"\x10\x00" * (payload.MAX_FIELDS + 1)))
    assert len(list(payload._walk(b"\x10\x00" * payload.MAX_FIELDS))) == payload.MAX_FIELDS


# --- escaping amplification ----------------------------------------------

_AMP_LEAF = "\\" * 300


def _json_nested(depth: int, leaf: str) -> dict:
    value: dict = {"stringValue": leaf}
    for _ in range(depth):
        value = {"arrayValue": {"values": [value]}}
    return value


def _pb_nested(depth: int, leaf: str) -> bytes:
    value = _any_string(leaf)
    for _ in range(depth):
        value = _len_field(5, _len_field(1, value))
    return value


def amplified_logs(encoding: str, records: int, attrs: int) -> bytes:
    """`records` log records of `attrs` attributes, each an array nested to
    MAX_DEPTH around a short run of backslashes."""
    from forgd_verdict.otel.payload import MAX_DEPTH

    if encoding == "json":
        value = _json_nested(MAX_DEPTH, _AMP_LEAF)
        recs = [{"attributes": [{"key": f"a{k}", "value": value} for k in range(attrs)]}
                for _ in range(records)]
        return json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": recs}]}]}).encode()
    kv = b"".join(_len_field(6, _str_field(1, f"a{k}") + _len_field(2, _pb_nested(MAX_DEPTH, _AMP_LEAF)))
                  for k in range(attrs))
    recs = b"".join(_len_field(2, kv) for _ in range(records))
    return _len_field(1, _len_field(2, recs))


_CTYPE = {"json": "application/json", "protobuf": "application/x-protobuf"}


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
@pytest.mark.parametrize(("records", "attrs"), [(1, 40), (40, 1)])
def test_escaping_amplification_is_refused_whole(encoding, records, attrs):
    """Each nesting level JSON-encodes the level below, doubling a run of
    backslashes. One such attribute rendered to MAX_VALUE_CHARS from a few
    hundred bytes, and the cap was per attribute: a 15 KB body decoded to
    40,000,000 characters, however its attributes were spread over records."""
    from forgd_verdict.otel.payload import DecodedTooLarge

    body = amplified_logs(encoding, records, attrs)
    assert len(body) < 50_000
    with pytest.raises(DecodedTooLarge):
        decode(body, _CTYPE[encoding], "logs")


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_a_large_escape_heavy_export_decodes(encoding):
    """An 8 MiB export of quote- and backslash-heavy prose, the collector's
    default max_body_bytes, decodes whole, and so do flat arrays of it."""
    from forgd_verdict.otel.payload import MAX_VALUE_CHARS

    prose = ('say "hi" C:\\temp\\x ' * (MAX_VALUE_CHARS // 24))[:MAX_VALUE_CHARS - 10]
    n = 7 if encoding == "json" else 9
    if encoding == "json":
        recs = [{"attributes": [
                    {"key": "prompt", "value": {"stringValue": prose}},
                    {"key": "args", "value": {"arrayValue": {"values": [
                        {"stringValue": prose[:20_000]} for _ in range(5)]}}}]}
                for _ in range(n)]
        body = json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": recs}]}]}).encode()
    else:
        arr = b"".join(_len_field(1, _any_string(prose[:20_000])) for _ in range(5))
        kv = (_len_field(6, _kv("prompt", prose))
              + _len_field(6, _str_field(1, "args") + _len_field(2, _len_field(5, arr))))
        body = _len_field(1, _len_field(2, b"".join(_len_field(2, kv) for _ in range(n))))
    assert 7 * 1024 * 1024 < len(body) <= 8 * 1024 * 1024
    out = decode(body, _CTYPE[encoding], "logs")
    assert len(out) == n
    assert all(r.attributes["prompt"] == prose for r in out)
    assert all(json.loads(r.attributes["args"]) == [prose[:20_000]] * 5 for r in out)


# --- inherited identity keys ----------------------------------------------


def _span_with_events(session_id: str, events: int) -> list[dict]:
    return [{"name": "agent.query",
             "attributes": {"session.id": session_id, "prompt.id": "p-1"},
             "events": [{"name": f"e{i}", "attributes": {"k": f"v{i}"}}
                        for i in range(events)]}]


def _traces(encoding: str, spans: list[dict]) -> list:
    body = (traces_json(spans, RESOURCE) if encoding == "json"
            else traces_protobuf(spans, RESOURCE))
    return decode(body, _CTYPE[encoding], "traces")


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_an_event_does_not_inherit_a_session_id_too_long_to_be_one(encoding):
    """A value past IDENTITY_MAX_CHARS is scanned as content, so copying it
    onto every event scanned it once per event."""
    from forgd_verdict.otel.payload import IDENTITY_MAX_CHARS

    long = "s" * (IDENTITY_MAX_CHARS + 1)
    span, *events = _traces(encoding, _span_with_events(long, 5))
    assert span.attributes["session.id"] == long
    assert len(events) == 5
    assert all("session.id" not in e.attributes for e in events)
    assert all(e.attributes["prompt.id"] == "p-1" for e in events)


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_an_event_inherits_a_session_id_at_the_identity_limit(encoding):
    from forgd_verdict.otel.payload import IDENTITY_MAX_CHARS

    sid = "s" * IDENTITY_MAX_CHARS
    _, *events = _traces(encoding, _span_with_events(sid, 3))
    assert all(e.attributes["session.id"] == sid for e in events)


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_scanned_text_does_not_grow_with_events_times_a_long_session_id(encoding):
    from forgd_verdict.otel.extract import record_units

    long = "s" * 100_000

    def scanned(events: int) -> int:
        return sum(len(u.text) for i, r in enumerate(_traces(encoding, _span_with_events(long, events)))
                   for u in record_units(r, i))

    assert scanned(1) >= len(long)
    assert scanned(50) - scanned(1) < len(long)
