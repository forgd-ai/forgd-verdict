"""A cold reader refuses the request paths; a warm one keeps serving.

With runtime overrides honoured and no verified state held, the verdict
server answers `/hook` as an internal error in enforce would, and intake
and the collector answer 503 without scanning, deciding or storing.
"""

from __future__ import annotations

import json
import logging

import pytest
from conftest import (
    DETECTORS,
    FAKE_AWS_KEY,
    OVERRIDES_KEY,
    OVERRIDES_PUBLIC_TEXT,
    WHSEC,
    ASGIClient,
    frame,
    make_policy,
    sign,
    text_msg,
)

from forgd_verdict import overrides as ov
from forgd_verdict.overrides import ACTION_INIT, ACTION_SET, KEY_MODE, Change, apply_change
from forgd_verdict.store import LocalFileStore

ADMIN = {"issuer": "https://idp/", "subject": "s", "name": "a", "verified": True}
ADMINS = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
          "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}
NOT_INITIALIZED = "runtime overrides are not initialized"

pytestmark = pytest.mark.usefixtures("control_identity")


def _init(store):
    apply_change(store, ADMIN, Change(ACTION_INIT), detectors=DETECTORS,
                 signing_key=OVERRIDES_KEY)


def _break(store):
    (store.root / "state" / "runtime-overrides.json").write_bytes(b"{broken")


def _hold_but_not_ready(reader):
    """Warm, then an object this reader is too old for: it keeps its
    last-known-good and is not ready."""
    reader.reader_version = "0.0.1"
    snap = reader.refresh()
    assert snap.source == ov.SOURCE_LKG and not snap.ready
    return snap


@pytest.fixture(autouse=True)
def _propagate(monkeypatch):
    """The services configure `forgd_verdict` not to propagate; caplog
    listens at the root."""
    from forgd_verdict.applog import configure_logging
    from forgd_verdict.otel import app as otel_app
    from forgd_verdict.server import app as server_app

    def configure(*a, **k):
        logger = configure_logging(*a, **k)
        monkeypatch.setattr(logger, "propagate", True)
        return logger

    for module in (server_app, otel_app):
        monkeypatch.setattr(module, "configure_logging", configure)


def _gate_errors(caplog):
    return [r for r in caplog.records if r.levelno == logging.ERROR
            and "runtime overrides not ready" in r.getMessage()]


# -- verdict server ----------------------------------------------------------


def _server(root, mode="observe", **server):
    from forgd_verdict.server.app import VerdictServer

    return VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": mode, "secrets": [WHSEC], "csv_path": None,
                "store": str(root), "store_flush_s": 3600, **server}, **ADMINS))


async def _hook(server, request_id="req_a"):
    raw = json.dumps(frame([text_msg(f"key {FAKE_AWS_KEY}")], request_id=request_id)).encode()
    return await ASGIClient(server).post("/hook", raw, sign(raw, webhook_id=request_id))


@pytest.mark.parametrize("mode", ["observe", "enforce"])
async def test_a_cold_verdict_server_fails_the_hook_by_default(tmp_path, caplog, mode):
    """In observe the baseline alone would allow. Mutation: gate only in
    enforce, or not at all."""
    server = _server(tmp_path / "store", mode)
    try:
        server._scan = _no_scan
        with caplog.at_level(logging.ERROR, "forgd_verdict"):
            status, body = await _hook(server)
        assert (status, body) == (500, {"error": "scan_failed"})
        [record] = _gate_errors(caplog)
        assert record.fields["reason"] == NOT_INITIALIZED
        assert server.verdicts.get("req_a") is None
    finally:
        server.close()


async def test_a_cold_verdict_server_allows_when_told_to_fail_open(tmp_path, caplog):
    server = _server(tmp_path / "store", "enforce", on_internal_error="allow")
    try:
        server._scan = _no_scan
        with caplog.at_level(logging.ERROR, "forgd_verdict"):
            status, body = await _hook(server)
        assert status == 200 and body["action"] == "allow"
        assert len(_gate_errors(caplog)) == 1
    finally:
        server.close()


async def test_a_cold_verdict_server_still_checks_the_signature_first(tmp_path):
    server = _server(tmp_path / "store")
    try:
        raw = json.dumps(frame([text_msg("hi")], request_id="req_a")).encode()
        status, _ = await ASGIClient(server).post("/hook", raw, {"webhook-id": "req_a"})
        assert status == 401
    finally:
        server.close()


async def test_a_verdict_server_serves_once_initialized(tmp_path):
    root = tmp_path / "store"
    server = _server(root, "enforce")
    try:
        assert (await _hook(server, "req_a"))[0] == 500
        _init(LocalFileStore(root, instance="admin"))
        server.overrides.refresh()
        status, body = await _hook(server, "req_b")
        assert status == 200 and body["action"] == "deny"
    finally:
        server.close()


@pytest.mark.parametrize("damage", ["invalid", "not_ready"])
async def test_a_warm_verdict_server_keeps_serving_on_its_last_known_good(tmp_path, damage):
    root = tmp_path / "store"
    store = LocalFileStore(root, instance="admin")
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS,
                 signing_key=OVERRIDES_KEY)
    server = _server(root)
    try:
        assert server.overrides.refresh().source == ov.SOURCE_OBJECT
        if damage == "invalid":
            _break(store)
            assert server.overrides.refresh().source == ov.SOURCE_LKG
        else:
            _hold_but_not_ready(server.overrides)
        status, body = await _hook(server)
        assert status == 200 and body["action"] == "deny"
    finally:
        server.close()


def _no_scan(*_a, **_k):
    raise AssertionError("a cold reader scanned")


# -- intake ------------------------------------------------------------------


def _intake(store):
    from test_scan_frames import TOKEN

    from forgd_verdict.intake.app import Intake
    from forgd_verdict.policy import Policy, _deep_merge

    raw = _deep_merge(json.loads(json.dumps(make_policy().raw, default=str)), {
        "intake": {"clients": [{"name": "bot", "token": TOKEN,
                                "routes": ["scan", "intake"]}]},
        "privacy": {"hash_salt": "s"}, **ADMINS})
    return Intake(Policy(raw=raw), store=store)


def _intake_line():
    return json.dumps({"request_id": "req_i", "action": "allow", "findings": []}).encode()


@pytest.mark.parametrize("route", ["/scan", "/intake"])
async def test_a_cold_intake_refuses_both_routes_without_scanning_or_storing(
        tmp_path, caplog, route):
    from test_scan_frames import auth, user
    from test_scan_frames import frame as scan_frame

    store = LocalFileStore(tmp_path, instance="t")
    app = _intake(store)
    try:
        app._scan_frame = _no_scan
        body = scan_frame([user(f"deploy with {FAKE_AWS_KEY}")]) if route == "/scan" \
            else _intake_line()
        with caplog.at_level(logging.ERROR, "forgd_verdict"):
            status, answer = await ASGIClient(app).post(route, body, auth())
        assert status == 503
        assert answer == {"error": "not_ready", "reason": NOT_INITIALIZED}
        assert len(_gate_errors(caplog)) == 1
        app.close()
        assert list(store.read_verdicts()) == []
    finally:
        app.close()


@pytest.mark.parametrize("damage", ["invalid", "not_ready"])
async def test_a_warm_intake_keeps_scanning_on_its_last_known_good(tmp_path, damage):
    from test_scan_frames import auth, user
    from test_scan_frames import frame as scan_frame

    store = LocalFileStore(tmp_path, instance="t")
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS,
                 signing_key=OVERRIDES_KEY)
    app = _intake(store)
    try:
        if damage == "invalid":
            _break(store)
            assert app.overrides.refresh().source == ov.SOURCE_LKG
        else:
            _hold_but_not_ready(app.overrides)
        status, body = await ASGIClient(app).post(
            "/scan", scan_frame([user(f"deploy with {FAKE_AWS_KEY}")]), auth())
        assert status == 200 and body["action"] == "deny"
    finally:
        app.close()


# -- collector ---------------------------------------------------------------


def _collector(store):
    from test_otel_collector import make_policy as otel_policy

    from forgd_verdict.otel.app import Collector
    from forgd_verdict.policy import Policy

    raw = json.loads(json.dumps(otel_policy().raw, default=str))
    raw.update(ADMINS)
    raw["privacy"]["hash_salt"] = "test-deployment-salt"
    return Collector(Policy(raw=raw), store=store)


@pytest.mark.parametrize("path", ["/v1/logs", "/v1/traces"])
async def test_a_cold_collector_refuses_exports_without_storing(tmp_path, caplog, path):
    from test_otel_collector import auth, code_batch

    store = LocalFileStore(tmp_path / "findings", instance="t")
    app = _collector(store)
    try:
        with caplog.at_level(logging.ERROR, "forgd_verdict"):
            status, answer = await ASGIClient(app).post(path, code_batch(), auth())
        assert status == 503
        assert answer == {"error": "not_ready", "reason": NOT_INITIALIZED}
        assert len(_gate_errors(caplog)) == 1
        app.sink.close()
        assert list(store.read_verdicts()) == []
    finally:
        app.close()


async def test_a_warm_collector_keeps_ingesting_on_its_last_known_good(tmp_path):
    from test_otel_collector import auth, code_batch

    store = LocalFileStore(tmp_path / "findings", instance="t")
    _init(store)
    app = _collector(store)
    try:
        _break(store)
        assert app.overrides.refresh().source == ov.SOURCE_LKG
        status, _ = await ASGIClient(app).post("/v1/logs", code_batch(), auth())
        assert status == 200
        app.sink.close()
        assert list(store.read_verdicts())
    finally:
        app.close()


# -- the gate ----------------------------------------------------------------


def test_the_gate_is_off_with_overrides_off_and_on_only_while_cold(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    assert ov.cold(None) is None
    assert ov.cold(ov.RuntimeOverrides(None, "verdict")) is None
    reader = ov.RuntimeOverrides(store, "verdict", verify_keys=[OVERRIDES_KEY.public_key()])
    assert ov.cold(reader) == NOT_INITIALIZED
    _init(store)
    reader.refresh()
    assert ov.cold(reader) is None
    _break(store)
    assert reader.refresh().source == ov.SOURCE_LKG and ov.cold(reader) is None
