"""A JSON integer with more digits than Python converts is kept as its
digit string, so a body holding one is parsed and scanned."""

from __future__ import annotations

import json

import pytest
from conftest import FAKE_AWS_KEY, WHSEC, ASGIClient, frame, make_policy, sign

from forgd_verdict.extract import frame_units
from forgd_verdict.models import load_json

DIGITS = "4" * 5000


def test_an_integer_over_the_limit_is_its_digit_string():
    doc = load_json(f'{{"a": {DIGITS}, "b": -{DIGITS}, "c": 12, "d": 1.5}}')
    assert doc == {"a": DIGITS, "b": "-" + DIGITS, "c": 12, "d": 1.5}


def test_malformed_json_still_raises():
    with pytest.raises(json.JSONDecodeError):
        load_json("{not json")


def test_the_digits_reach_a_unit_as_text():
    messages = load_json(json.dumps([{"role": "user", "content": [
        {"type": "tool_use", "id": "t", "name": "x", "input": {"n": "BIG"}}]}])
        .replace('"BIG"', DIGITS))
    assert DIGITS in [u.text for u in frame_units(messages)]


async def test_the_server_scans_a_frame_holding_an_integer_over_the_limit(tmp_path):
    from forgd_verdict.server.app import VerdictServer

    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": str(tmp_path / "t.csv")},
    )
    server = VerdictServer(policy)
    server.sink.submit = lambda row, findings: None
    raw = json.dumps(frame([{"role": "user", "content": [
        {"type": "text", "text": f"deploy {FAKE_AWS_KEY}"},
        {"type": "tool_result", "tool_use_id": "t", "content": [{"n": "BIG"}]}]}]))
    raw = raw.replace('"BIG"', DIGITS).encode()
    try:
        status, body = await ASGIClient(server).post("/hook", raw, sign(raw))
    finally:
        server.close()
    assert status == 200
    assert body["action"] == "deny"


def test_an_otlp_body_holding_an_integer_over_the_limit_decodes():
    from test_otel_payload import RESOURCE, logs_json

    from forgd_verdict.otel.payload import decode

    body = logs_json([{"attributes": {"event.name": "claude_code.user_prompt",
                                      "prompt": f"deploy {FAKE_AWS_KEY}"},
                       "body": ""}], RESOURCE)
    assert body.rstrip().endswith(b"}")
    body = body.rstrip()[:-1] + b', "big": ' + DIGITS.encode() + b"}"
    records = decode(body, "application/json", "logs")
    assert any(FAKE_AWS_KEY in v for r in records for v in r.attributes.values())


def test_a_hook_payload_holding_an_integer_over_the_limit_parses():
    from forgd_verdict.hook.cli import _parse_payload

    raw = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "x",
                      "tool_input": {"n": "BIG"}}).replace('"BIG"', DIGITS)
    payload, error = _parse_payload(raw)
    assert error == ""
    assert payload["tool_input"]["n"] == DIGITS
