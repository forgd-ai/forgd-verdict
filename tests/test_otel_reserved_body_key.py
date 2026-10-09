"""A log record's body is scanned even when the sender adds an attribute
named `_body`, the key the decoder reserves for the body."""

from __future__ import annotations

import json

from conftest import FAKE_GITHUB_TOKEN

from forgd_verdict.otel import payload


def _export(body: str) -> bytes:
    return json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
        "body": {"stringValue": body},
        "attributes": [{"key": "_body", "value": {"stringValue": "clean decoy"}},
                       {"key": "event.name", "value": {"stringValue": "user_prompt"}}],
    }]}]}]}).encode()


def test_a_sender_attribute_named_body_does_not_displace_the_log_body():
    [record] = payload.decode(_export(f"see {FAKE_GITHUB_TOKEN}"), "application/json", "logs")
    assert record.attributes["_body"] == f"see {FAKE_GITHUB_TOKEN}"
    assert "clean decoy" not in json.dumps(record.attributes)


def test_the_protobuf_decoder_keeps_the_body_over_a_sender_attribute():
    from test_otel_payload import logs_protobuf

    blob = logs_protobuf([{"attributes": {"_body": "clean decoy", "event.name": "user_prompt"},
                           "body": f"see {FAKE_GITHUB_TOKEN}"}], {})
    [record] = payload.decode(blob, "application/x-protobuf", "logs")
    assert record.attributes["_body"] == f"see {FAKE_GITHUB_TOKEN}"
    assert "clean decoy" not in json.dumps(record.attributes)


def test_a_sender_attribute_named_body_on_a_bodyless_record_is_dropped():
    raw = json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
        "attributes": [{"key": "_body", "value": {"stringValue": "posing as a body"}}],
    }]}]}]}).encode()
    [record] = payload.decode(raw, "application/json", "logs")
    assert "_body" not in record.attributes
