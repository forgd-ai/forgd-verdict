"""The intake serves `GET /stats` behind `server.metrics_token`, as the
collector does: 404 with no token configured, 401 on a wrong one."""

from __future__ import annotations

import json

import pytest
from conftest import FAKE_AWS_KEY, ASGIClient
from test_intake_denylist import ADMINS, _change, org_env, store  # noqa: F401
from test_intake_fleet import FLEET_TOKEN, ORG_DEV, ORG_PROD, _headers, _policy

from forgd_verdict.intake.app import Intake
from forgd_verdict.overrides import ACTION_DENY_DEVICE
from forgd_verdict.policy import _deep_merge

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")

METRICS_TOKEN = "intake-metrics-token-0123456789abcdef"
DENIED = "d00000000dead"
SEEN = "d000000000042"


def _app(store, monkeypatch, metrics_token: str | None = METRICS_TOKEN) -> Intake:  # noqa: F811
    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    extra = dict(ADMINS)
    if metrics_token is not None:
        extra["server"] = {"metrics_token": metrics_token}
    return Intake(type(_policy())(raw=_deep_merge(_policy().raw, extra)), store=store)


async def _stats(app, token: str | None = METRICS_TOKEN):
    headers = {} if token is None else {"authorization": f"Bearer {token}"}
    return await ASGIClient(app).get("/stats", headers)


async def _scan(app, device: str | None, text: str = "hello"):
    body = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": text,
                       "session_id": "s"}).encode()
    return await ASGIClient(app).post("/scan", body, _headers(FLEET_TOKEN, device))


# -- who may read it --------------------------------------------------------


async def test_stats_is_served_with_the_metrics_token(store, monkeypatch):  # noqa: F811
    app = _app(store, monkeypatch)
    try:
        status, body = await _stats(app)
    finally:
        app.close()
    assert status == 200
    assert "counts" in body


@pytest.mark.parametrize("token", [None, "wrong-token-0123456789abcdef", ""])
async def test_a_wrong_or_missing_token_is_401(store, monkeypatch, token):  # noqa: F811
    app = _app(store, monkeypatch)
    try:
        status, body = await _stats(app, token)
    finally:
        app.close()
    assert status == 401
    assert body == {"error": "unauthorized"}


@pytest.mark.parametrize("configured", [None, ""])
async def test_with_no_metrics_token_stats_does_not_exist(store, monkeypatch,  # noqa: F811
                                                          configured):
    app = _app(store, monkeypatch, configured)
    try:
        for token in (None, "anything-at-all-0123456789"):
            assert await _stats(app, token) == (404, {"error": "not_found"})
    finally:
        app.close()


# -- the device counters the docs cite ----------------------------------------


async def test_the_device_counters_move(store, monkeypatch):  # noqa: F811
    app = _app(store, monkeypatch)
    try:
        _change(store, ACTION_DENY_DEVICE, DENIED)
        app.overrides.refresh()
        assert (await _scan(app, DENIED))[0] == 403
        assert (await _scan(app, None))[0] == 403
        assert (await _scan(app, SEEN))[0] == 200
        assert (await _scan(app, SEEN))[0] == 200
        _, body = await _stats(app)
    finally:
        app.close()
    counts = body["counts"]
    assert counts["device_denied"] == 1
    assert counts["device_missing"] == 1
    assert counts["device_first_seen"] == 1


async def test_stats_carries_no_content_token_device_or_org(store, monkeypatch):  # noqa: F811
    app = _app(store, monkeypatch)
    try:
        _change(store, ACTION_DENY_DEVICE, DENIED)
        app.overrides.refresh()
        await _scan(app, DENIED)
        assert (await _scan(app, SEEN, f"deploy {FAKE_AWS_KEY}"))[1]["action"] == "deny"
        status, body = await _stats(app)
    finally:
        app.close()
    assert status == 200
    text = json.dumps(body)
    for value in (FAKE_AWS_KEY, FLEET_TOKEN, METRICS_TOKEN, DENIED, SEEN,
                  ORG_PROD, ORG_DEV, "deploy"):
        assert value not in text, value
