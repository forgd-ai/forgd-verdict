"""/scan runs on bounded lanes, and a full lane answers 503 Retry-After.

Every scan used to run on the event loop's default executor with no bound,
so four 8 MiB scans held every thread and an unrelated small /scan waited
past the hook's 1 s remote timeout. The scans here are held open on an
event, so which lane is full is decided by the test and not by timing.
"""

from __future__ import annotations

import asyncio
import json
import threading

import pytest
from conftest import ASGIClient

from forgd_verdict.intake import app as intake_app
from forgd_verdict.intake.app import SCAN_LARGE_BYTES, Intake, ScanLane
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge

TOKEN = "scan-token-0123456789abcdef0123456789"
HEADERS = {"authorization": f"Bearer {TOKEN}", "content-type": "application/json"}


def _app() -> Intake:
    return Intake(Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": "s"},
        "intake": {"clients": [{"name": "agent", "token": TOKEN, "routes": ["scan"],
                                "agent": True}]}})), store=None)


def _small() -> bytes:
    return json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hello"}).encode()


def _large() -> bytes:
    return json.dumps({"hook_event_name": "UserPromptSubmit",
                       "prompt": "a " * (SCAN_LARGE_BYTES // 2 + 10)}).encode()


class Held:
    """Replaces `_hook_verdict`: a large prompt blocks until released."""

    def __init__(self, app: Intake):
        self.real = app._hook_verdict
        self.release = threading.Event()
        self.entered = threading.Semaphore(0)
        app._hook_verdict = self

    def __call__(self, payload, conf, blocks=False):
        if len(payload.get("prompt", "")) > 1000:
            self.entered.release()
            assert self.release.wait(30)
        return self.real(payload, conf, blocks)

    async def entered_once(self):
        assert await asyncio.to_thread(self.entered.acquire, True, 10)


async def test_a_second_large_scan_is_refused_with_retry_after_while_one_runs():
    app = _app()
    held = Held(app)
    client = ASGIClient(app)
    try:
        first = asyncio.create_task(client.post("/scan", _large(), HEADERS))
        await held.entered_once()
        status, _body, headers = await client.request("POST", "/scan", _large(), HEADERS)
        assert status == 503
        assert dict(headers).get("retry-after") == "1"
        held.release.set()
        assert (await first)[0] == 200
        assert app.stats()["counts"]["scan_busy_large"] == 1
    finally:
        held.release.set()
        app.close()


async def test_a_small_scan_answers_while_the_large_lane_is_full():
    app = _app()
    held = Held(app)
    client = ASGIClient(app)
    try:
        first = asyncio.create_task(client.post("/scan", _large(), HEADERS))
        await held.entered_once()
        status, body = await asyncio.wait_for(client.post("/scan", _small(), HEADERS), 5)
        assert status == 200 and body["action"] == "allow"
        held.release.set()
        _ = await first
    finally:
        held.release.set()
        app.close()


async def test_a_declared_large_body_is_refused_before_it_is_read():
    app = _app()
    held = Held(app)
    client = ASGIClient(app)
    try:
        first = asyncio.create_task(client.post("/scan", _large(), HEADERS))
        await held.entered_once()
        read = []

        async def receive():
            read.append(1)
            return {"type": "http.request", "body": b"x", "more_body": True}

        sent = []

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "method": "POST", "path": "/scan", "query_string": b"",
                 "headers": [(k.encode(), v.encode()) for k, v in {
                     **HEADERS, "content-length": str(1024 * 1024)}.items()]}
        await app(scope, receive, send)
        assert sent[0]["status"] == 503
        assert read == []
        held.release.set()
        _ = await first
    finally:
        held.release.set()
        app.close()


async def test_a_small_declared_length_on_a_large_body_takes_the_large_lane():
    app = _app()
    held = Held(app)
    client = ASGIClient(app)
    try:
        first = asyncio.create_task(client.post("/scan", _large(), HEADERS))
        await held.entered_once()
        status, _ = await client.post("/scan", _large(),
                                      {**HEADERS, "content-length": "10"})
        assert status == 503
        held.release.set()
        _ = await first
    finally:
        held.release.set()
        app.close()


@pytest.mark.parametrize("value", ["²", "-1", "1e9", "9" * 40, ""])
def test_a_content_length_that_is_not_ascii_digits_is_ignored(value):
    assert intake_app._content_length({"content-length": value}) is None


async def test_a_disconnected_client_does_not_free_a_slot_that_is_still_scanning():
    lane = ScanLane("t", 1, 0.0, 0)
    release = threading.Event()
    started = threading.Event()

    def work():
        started.set()
        release.wait(30)
        return "done"

    try:
        task = asyncio.create_task(lane.run(work))
        await asyncio.to_thread(started.wait, 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            _ = await task
        assert lane.running == 1
        assert await lane.run(lambda: "second") is ScanLane.BUSY
        release.set()
        for _ in range(200):
            if lane.running == 0:
                break
            await asyncio.sleep(0.01)
        assert await lane.run(lambda: "third") == "third"
    finally:
        release.set()
        lane.close()


async def test_small_lane_callers_past_the_waiting_bound_are_refused_at_once():
    lane = ScanLane("t", 1, 5.0, 2)
    release = threading.Event()
    try:
        running = asyncio.create_task(lane.run(release.wait, 30))
        await asyncio.sleep(0.05)
        waiters = [asyncio.create_task(lane.run(lambda: "w")) for _ in range(2)]
        await asyncio.sleep(0.05)
        assert lane.waiting == 2
        assert await lane.run(lambda: "x") is ScanLane.BUSY
        release.set()
        assert await running is True
        assert [await w for w in waiters] == ["w", "w"]
        assert (lane.running, lane.waiting) == (0, 0)
    finally:
        release.set()
        lane.close()


async def test_a_small_lane_caller_gives_up_after_the_wait():
    lane = ScanLane("t", 1, 0.05, 8)
    release = threading.Event()
    try:
        running = asyncio.create_task(lane.run(release.wait, 30))
        await asyncio.sleep(0.05)
        assert await lane.run(lambda: "late") is ScanLane.BUSY
        assert lane.waiting == 0
        release.set()
        _ = await running
    finally:
        release.set()
        lane.close()


async def test_a_scan_that_raises_releases_its_slot():
    lane = ScanLane("t", 1, 0.0, 0)

    def boom():
        raise RuntimeError("x")

    try:
        with pytest.raises(RuntimeError):
            await lane.run(boom)
        await asyncio.sleep(0.01)
        assert await lane.run(lambda: 1) == 1
    finally:
        lane.close()


async def test_the_lanes_are_in_stats():
    app = _app()
    try:
        assert set(app.stats()["scan_lanes"]) == {"small", "large"}
    finally:
        app.close()


async def test_scans_arriving_together_build_the_detector_set_once(monkeypatch):
    """The first scans after a start each found no detector set and built
    one, and a thread could read the set before its `_left_out` was set."""
    import time

    from forgd_verdict import policy as policy_mod

    app = _app()
    built = []
    real = policy_mod.Policy.build_detectors

    def slow(self, *a, **kw):
        built.append(1)
        time.sleep(0.2)
        return real(self, *a, **kw)

    monkeypatch.setattr(policy_mod.Policy, "build_detectors", slow)
    client = ASGIClient(app)
    try:
        results = await asyncio.gather(*[client.post("/scan", _small(), HEADERS)
                                         for _ in range(4)])
        assert {s for s, _ in results} == {200}
        assert len(built) == 1
    finally:
        app.close()


async def test_a_scan_body_over_the_scan_cap_is_413_before_and_after_reading():
    app = _app()
    client = ASGIClient(app)
    over = json.dumps({"hook_event_name": "UserPromptSubmit",
                       "prompt": "a " * (app.scan_max_body // 2 + 10)}).encode()
    try:
        assert (await client.post("/scan", over, HEADERS))[0] == 413
        assert (await client.post("/scan", over, {**HEADERS, "content-length": "10"}))[0] \
            == 413
        assert app.scan_max_body < app.max_body
    finally:
        app.close()
