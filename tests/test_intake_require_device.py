"""`intake.fleet[].require_device`, default true: a fleet request with no
valid device id is refused, since the hook always sends one."""

from __future__ import annotations

import json

import pytest
from conftest import ASGIClient
from test_intake_fleet import (
    ALICE_TOKEN,
    FLEET_TOKEN,
    _app,
    _fleet,
    _headers,
    _ndjson,
    _policy,
    _rec,
    org_env,  # noqa: F401
)

SCAN = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hello",
                   "session_id": "s"}).encode()


async def _both(app, token, device):
    client = ASGIClient(app)
    intake = await client.post("/intake", _ndjson(_rec()), _headers(token, device))
    scan = await client.post("/scan", SCAN, {**_headers(token, device),
                                             "content-type": "application/json"})
    return intake, scan


@pytest.mark.parametrize("device", [None, "", "not-a-device", "D000000000042"])
async def test_a_fleet_request_without_a_valid_device_is_refused(tmp_path, device):
    app = _app(tmp_path, _policy())
    try:
        for status, body in await _both(app, FLEET_TOKEN, device):
            assert status == 403
            assert body == {"error": "device_required"}
        assert app.stats()["counts"]["device_missing"] == 2
    finally:
        app.close()


async def test_a_fleet_request_with_a_device_is_accepted(tmp_path):
    app = _app(tmp_path, _policy())
    try:
        for status, _ in await _both(app, FLEET_TOKEN, "d000000000042"):
            assert status == 200
    finally:
        app.close()


async def test_require_device_false_accepts_and_counts(tmp_path):
    app = _app(tmp_path, _policy(fleet=[_fleet(require_device=False)]))
    try:
        for status, _ in await _both(app, FLEET_TOKEN, None):
            assert status == 200
        assert app.stats()["counts"]["device_missing"] == 2
    finally:
        app.close()


async def test_a_client_token_needs_no_device(tmp_path):
    app = _app(tmp_path, _policy(clients=[{"name": "alice-laptop", "token": ALICE_TOKEN}]))
    try:
        for status, _ in await _both(app, ALICE_TOKEN, None):
            assert status == 200
    finally:
        app.close()


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_a_require_device_that_is_not_a_bool_refuses_to_start(tmp_path, value):
    with pytest.raises(ValueError, match="require_device"):
        _app(tmp_path, _policy(fleet=[_fleet(require_device=value)]))
