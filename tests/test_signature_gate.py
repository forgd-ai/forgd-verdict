"""The signature gate on the hook path: headers before the body, a
constant-time second factor, and a loud startup when signatures are off."""

from __future__ import annotations

import hmac
import json
import logging
import time

import pytest
from conftest import WHSEC, ASGIClient, frame, make_policy, sign

from forgd_verdict.server import signature
from forgd_verdict.server.app import VerdictServer

BODY = json.dumps(frame()).encode()


def _server(**server):
    cfg = {"mode": "enforce", "secrets": [WHSEC], "csv_path": None, **server}
    logger = logging.getLogger("forgd_verdict_test.signature_gate")
    logger.setLevel(logging.DEBUG)
    logger.propagate = True
    return VerdictServer(make_policy(server=cfg), logger=logger)


async def _call_without_body(server, headers: dict) -> tuple[int, dict, int]:
    """Drive one POST whose body must not be read. Returns (status, body,
    receive calls)."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/hook",
        "query_string": b"",
        "headers": [(k.lower().encode("latin-1"), str(v).encode("latin-1"))
                    for k, v in headers.items()],
    }
    calls = {"n": 0}
    sent: list[dict] = []

    async def receive():
        calls["n"] += 1
        return {"type": "http.request", "body": BODY, "more_body": False}

    async def send(message):
        sent.append(message)

    await server(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(payload), calls["n"]


def _without(headers: dict, name: str) -> dict:
    return {k: v for k, v in headers.items() if k != name}


# -- (a) header pre-check ------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        (_without(sign(BODY), "webhook-id"), "unsigned"),
        (_without(sign(BODY), "webhook-timestamp"), "unsigned"),
        (_without(sign(BODY), "webhook-signature"), "unsigned"),
        ({**sign(BODY), "webhook-timestamp": "soon"}, "bad_timestamp"),
        (sign(BODY, ts=int(time.time()) - 3600), "stale_timestamp"),
        (sign(BODY, ts=int(time.time()) + 3600), "stale_timestamp"),
    ],
    ids=["no-id", "no-timestamp", "no-signature", "bad-timestamp", "stale", "future"],
)
def test_precheck_rejects_on_headers_alone(headers, reason):
    result = signature.precheck(headers)
    assert not result.ok
    assert result.reason == reason


def test_precheck_passes_fresh_signed_headers():
    result = signature.precheck(sign(BODY, webhook_id="req_pre"))
    assert result.ok
    assert result.webhook_id == "req_pre"


def test_verify_still_reports_the_header_reasons():
    stale = sign(BODY, ts=int(time.time()) - 3600)
    assert signature.verify([WHSEC], stale, BODY).reason == "stale_timestamp"
    assert signature.verify([WHSEC], {}, BODY).reason == "unsigned"


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ({"content-type": "application/json"}, "unsigned"),
        ({**sign(BODY), "webhook-timestamp": "soon"}, "bad_timestamp"),
        (sign(BODY, ts=int(time.time()) - 3600), "stale_timestamp"),
    ],
    ids=["unsigned", "bad-timestamp", "stale"],
)
async def test_a_request_failing_the_precheck_is_refused_before_its_body_is_read(
        headers, reason, caplog):
    server = _server()
    try:
        caplog.set_level(logging.WARNING)
        status, body, reads = await _call_without_body(server, headers)
        assert (status, body) == (401, {"error": "invalid_signature"})
        assert reads == 0
        assert server.metrics.snapshot()["counters"].get(f"sig_{reason}") == 1
        failed = [r for r in caplog.records if r.getMessage() == "signature verification failed"]
        assert [r.fields["reason"] for r in failed] == [reason]
    finally:
        server.close()


async def test_a_missing_secret_is_refused_before_the_body_is_read():
    server = _server(secrets=[], require_signature=True)
    try:
        status, body, reads = await _call_without_body(server, sign(BODY))
        assert (status, body) == (503, {"error": "no_signing_secret_configured"})
        assert reads == 0
    finally:
        server.close()


async def test_a_request_passing_the_precheck_is_read_and_verified():
    server = _server()
    try:
        status, verdict = await ASGIClient(server).post("/hook", BODY, sign(BODY))
        assert status == 200 and verdict["action"] == "allow"
        status, body = await ASGIClient(server).post(
            "/hook", BODY, sign(BODY, secret="whsec_" + "A" * 43 + "=", webhook_id="req_x"))
        assert (status, body) == (401, {"error": "invalid_signature"})
        assert server.metrics.snapshot()["counters"].get("sig_mismatch") == 1
    finally:
        server.close()


async def test_with_signatures_off_an_unsigned_request_is_still_served():
    server = _server(require_signature=False)
    try:
        status, verdict = await ASGIClient(server).post("/hook", BODY, {})
        assert status == 200 and verdict["action"] == "allow"
    finally:
        server.close()


# -- (b) second factor ---------------------------------------------------------


async def test_required_headers_are_compared_in_constant_time(monkeypatch):
    seen: list[tuple] = []
    real = hmac.compare_digest

    def spy(a, b):
        seen.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    server = _server(required_headers={"X-Forgd-Shared": "hunter2"})
    try:
        headers = {**sign(BODY), "x-forgd-shared": "hunter3"}
        status, body = await ASGIClient(server).post("/hook", BODY, headers)
        assert (status, body) == (401, {"error": "missing_required_header"})
        assert any(b"hunter2" in (a, b) and b"hunter3" in (a, b) for a, b in seen)
    finally:
        server.close()


@pytest.mark.parametrize(
    "supplied", [None, "", "hunter", "hunter22", "hünter2"],
    ids=["missing", "empty", "prefix", "longer", "non-ascii"])
async def test_a_missing_or_wrong_required_header_is_401(supplied):
    server = _server(required_headers={"X-Forgd-Shared": "hunter2"})
    try:
        headers = sign(BODY)
        if supplied is not None:
            headers["x-forgd-shared"] = supplied
        status, body = await ASGIClient(server).post("/hook", BODY, headers)
        assert (status, body) == (401, {"error": "missing_required_header"})
        assert server.metrics.snapshot()["counters"].get("required_header_mismatch") == 1
    finally:
        server.close()


async def test_the_right_required_header_is_accepted():
    server = _server(required_headers={"X-Forgd-Shared": "hunter2"})
    try:
        headers = {**sign(BODY), "x-forgd-shared": "hunter2"}
        status, verdict = await ASGIClient(server).post("/hook", BODY, headers)
        assert status == 200 and verdict["action"] == "allow"
    finally:
        server.close()


# -- (c) signatures off --------------------------------------------------------


def test_signatures_off_logs_an_error_at_startup_and_still_starts(caplog):
    caplog.set_level(logging.INFO)
    server = _server(require_signature=False)
    try:
        errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert len(errors) == 1
        message = errors[0].getMessage()
        assert "require_signature is false" in message
        assert "any caller" in message and "without a signature" in message
        assert any(r.getMessage() == "verdict server ready" for r in caplog.records)
    finally:
        server.close()


def test_signatures_on_logs_no_such_error(caplog):
    caplog.set_level(logging.INFO)
    server = _server()
    try:
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    finally:
        server.close()


_NOW = str(int(time.time()))
_ODD_TIMESTAMPS = {
    "4000-digits": "5" * 4000,
    "5000-digits": "5" * 5000,
    "13-digits": "1" * 13,
    "arabic-indic-now": _NOW.translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")),
    "plus-sign": f"+{_NOW}",
    "spaced": f" {_NOW} ",
    "underscored": f"{_NOW[:5]}_{_NOW[5:]}",
}


@pytest.mark.parametrize("timestamp", _ODD_TIMESTAMPS.values(), ids=_ODD_TIMESTAMPS.keys())
def test_a_timestamp_that_is_not_up_to_12_ascii_digits_is_bad(timestamp):
    result = signature.precheck({**sign(BODY), "webhook-timestamp": timestamp})
    assert (result.ok, result.reason) == (False, "bad_timestamp")


async def test_a_huge_timestamp_is_401_not_500():
    server = _server()
    try:
        status, body, _ = await _call_without_body(
            server, {**sign(BODY), "webhook-timestamp": "5" * 4000})
        assert (status, body) == (401, {"error": "invalid_signature"})
    finally:
        server.close()
