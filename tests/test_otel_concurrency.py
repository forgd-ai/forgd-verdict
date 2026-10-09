"""The collector decodes and scans at most `otel.export_workers` exports at
once. Another export past that is answered 503 with Retry-After before its
body is read, and the probes stay responsive.

A laptop holds an OTel token, so without a bound one token holder could
queue any number of 8 MiB exports onto worker threads.
"""

from __future__ import annotations

import asyncio
import threading

import pytest
from conftest import ASGIClient
from test_otel_collector import auth, code_batch, make_policy

from forgd_verdict.otel import app as otel_app
from forgd_verdict.otel.app import Collector
from forgd_verdict.store.local import LocalFileStore


@pytest.fixture
def collector(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    c = Collector(make_policy(export_workers=2),
                  store=LocalFileStore(tmp_path / "f", instance="t"))
    yield c
    c.close()


@pytest.fixture
def gate(monkeypatch):
    """`collect` held until the event is set; entered counts the calls."""
    release = threading.Event()
    entered = []
    real = otel_app.collect

    def held(*args, **kwargs):
        entered.append(1)
        release.wait(10)
        return real(*args, **kwargs)

    monkeypatch.setattr(otel_app, "collect", held)
    yield release, entered
    release.set()


async def _wait_for(cond, timeout=5.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not cond():
        assert loop.time() < end, "timed out"
        await asyncio.sleep(0.01)


def test_exports_past_the_bound_are_503_and_probes_stay_up(collector, gate):
    release, entered = gate
    client = ASGIClient(collector)

    async def go():
        held = [asyncio.create_task(client.post("/v1/logs", code_batch(), auth()))
                for _ in range(2)]
        await _wait_for(lambda: len(entered) == 2)
        status, body, headers = await asyncio.wait_for(
            client.request("POST", "/v1/logs", code_batch(), auth()), 2)
        assert status == 503 and body["error"] == "busy"
        assert any(k.lower() == "retry-after" for k, _ in _pairs(headers))
        status, *_ = await asyncio.wait_for(client.get("/healthz"), 2)
        assert status == 200
        status, *_ = await asyncio.wait_for(client.get("/livez"), 2)
        assert status == 200
        status, *_ = await asyncio.wait_for(client.post("/v1/metrics", b"{}", auth()), 2)
        assert status == 503
        release.set()
        results = await asyncio.wait_for(asyncio.gather(*held), 10)
        assert [s for s, _ in results] == [200, 200]
        status, _ = await asyncio.wait_for(client.post("/v1/logs", code_batch(), auth()), 10)
        assert status == 200

    asyncio.run(go())
    assert collector._counts.get("busy") == 2


def _pairs(headers):
    return headers.items() if isinstance(headers, dict) else headers


def test_a_refused_export_body_is_not_read(collector, gate):
    release, entered = gate
    client = ASGIClient(collector)
    reads = []

    async def go():
        held = [asyncio.create_task(client.post("/v1/logs", code_batch(), auth()))
                for _ in range(2)]
        await _wait_for(lambda: len(entered) == 2)
        scope = {"type": "http", "method": "POST", "path": "/v1/logs", "query_string": b"",
                 "headers": [(k.encode(), v.encode()) for k, v in auth().items()]}
        sent = []

        async def receive():
            reads.append(1)
            return {"type": "http.request", "body": code_batch(), "more_body": False}

        async def send(message):
            sent.append(message)

        await collector(scope, receive, send)
        assert sent[0]["status"] == 503
        release.set()
        await asyncio.gather(*held)

    asyncio.run(go())
    assert reads == []


def test_a_failed_scan_returns_its_slot(collector, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("scan failed")

    monkeypatch.setattr(otel_app, "collect", boom)
    client = ASGIClient(collector)

    async def go():
        for _ in range(5):
            status, _ = await client.post("/v1/logs", code_batch(), auth())
            assert status == 503
        return collector._export_slots_free()

    assert asyncio.run(go()) == 2


def test_refusals_before_the_scan_return_their_slot(collector):
    client = ASGIClient(collector)

    async def go():
        statuses = []
        for body, headers in ((b"x" * 9_000_000, auth()), (b"not json", auth()),
                              (b"\x1f\x8b junk", auth({"content-encoding": "gzip"}))):
            status, _ = await client.post("/v1/logs", body, headers)
            statuses.append(status)
        return statuses, collector._export_slots_free()

    statuses, free = asyncio.run(go())
    assert statuses == [413, 400, 400]
    assert free == 2


def test_a_disconnect_while_reading_returns_its_slot(collector):
    scope = {"type": "http", "method": "POST", "path": "/v1/logs", "query_string": b"",
             "headers": [(k.encode(), v.encode()) for k, v in auth().items()]}

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        pass

    async def go():
        await collector(scope, receive, send)
        return collector._export_slots_free()

    assert asyncio.run(go()) == 2


def test_the_bound_defaults_and_is_at_least_one(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    store = LocalFileStore(tmp_path / "g", instance="t")
    c = Collector(make_policy(), store=store)
    try:
        assert c._export_slots_free() == otel_app.EXPORT_WORKERS
    finally:
        c.close()
    with pytest.raises(ValueError, match="export_workers"):
        Collector(make_policy(export_workers=0), store=store)


def test_a_body_that_never_arrives_gives_its_slot_back(collector, monkeypatch):
    monkeypatch.setattr(otel_app, "BODY_READ_TIMEOUT_S", 0.2)
    scope = {"type": "http", "method": "POST", "path": "/v1/logs", "query_string": b"",
             "headers": [(k.encode(), v.encode()) for k, v in auth().items()]}
    sent = []

    async def receive():
        await asyncio.sleep(60)

    async def send(message):
        sent.append(message)

    async def go():
        await asyncio.wait_for(collector(scope, receive, send), 5)
        return collector._export_slots_free()

    assert asyncio.run(go()) == 2
    assert sent[0]["status"] == 503
