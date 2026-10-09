"""The intake writes its records through one batching StoreSink.

At 900 laptops a store object per /scan call is about 180k objects a day,
and the dashboard reads every one of them. Each test flushes explicitly
rather than waiting on the flush interval. The scans and shipped records
here are denies: a clean allow is counted into a tally row
(test_intake_tally.py), not written as a record."""

from __future__ import annotations

import json

import pytest
from conftest import ASGIClient

from forgd_verdict.intake.app import Intake
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import SOURCE_CODE_HOOK, FindingRow, VerdictRecord

TOKEN = "intake-token-for-alice-0123456789"
METRICS = "intake-metrics-token-0123456789abcdef"
SCAN = {"hook_event_name": "UserPromptSubmit", "prompt": "the key is AKIAIOSFODNN7EXAMPLE",
        "session_id": "550e8400-e29b-41d4-a716-446655440000"}


class CountingStore(LocalFileStore):
    def __init__(self, *a, fail: bool = False, **k):
        super().__init__(*a, **k)
        self.calls: list[int] = []
        self.fail = fail

    def write_verdicts(self, records):
        self.calls.append(len(records))
        if self.fail:
            raise OSError("store unavailable")
        return super().write_verdicts(records)


def _policy(**intake) -> Policy:
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "alice-laptop", "token": TOKEN}], **intake},
        "privacy": {"hash_salt": "s"},
        "server": {"metrics_token": METRICS},
        "detectors": {"gitleaks": {"enabled": False}}}))


@pytest.fixture
def make(tmp_path):
    apps = []

    def make_(fail=False, **intake):
        store = CountingStore(tmp_path / f"store{len(apps)}", instance="t", fail=fail)
        app = Intake(_policy(**intake), store=store)
        apps.append(app)
        return app, store
    yield make_
    for app in apps:
        app.close()


def _auth(content_type="application/json"):
    return {"authorization": f"Bearer {TOKEN}", "content-type": content_type}


async def _scan(app):
    return await ASGIClient(app).post("/scan", json.dumps(SCAN).encode(), _auth())


def _records(n):
    return [VerdictRecord(source=SOURCE_CODE_HOOK, action="deny",
                          findings=[FindingRow("regex:aws-access-key", "block", "p", "h")],
                          findings_count=1,
                          request_id=f"UserPromptSubmit:prompt:r{i}") for i in range(n)]


async def _ship(app, n):
    body = ("\n".join(r.to_json() for r in _records(n)) + "\n").encode()
    return await ASGIClient(app).post("/intake", body, _auth("application/x-ndjson"))


async def _stats(app):
    return await ASGIClient(app).get("/stats", {"authorization": f"Bearer {METRICS}"})


def _flush(app):
    flush = getattr(app, "flush", None)
    if flush is not None:
        flush()


async def test_many_scans_are_one_store_write(make):
    app, store = make()
    for _ in range(25):
        assert (await _scan(app))[0] == 200
    _flush(app)
    assert store.calls == [25]


def _objects(store):
    return [p for p in (store.root / "verdicts").rglob("*") if p.is_file()]


async def test_many_scans_are_one_store_object(make):
    app, store = make()
    for _ in range(25):
        await _scan(app)
    _flush(app)
    assert len(_objects(store)) == 1


async def test_a_shipped_batch_is_written_before_it_is_answered(make):
    """The laptop deletes its spool file on a 2xx, so /intake does not go
    through the sink: the batch is in the store when the 200 is sent."""
    app, store = make()
    await _scan(app)
    assert (await _ship(app, 3))[0] == 200
    assert store.calls == [3]
    await _scan(app)
    _flush(app)
    assert store.calls == [3, 2]


async def test_a_store_failure_on_a_shipped_batch_is_a_503(make):
    app, store = make(fail=True)
    status, body, headers = await ASGIClient(app).request(
        "POST", "/intake",
        ("\n".join(r.to_json() for r in _records(3)) + "\n").encode(),
        _auth("application/x-ndjson"))
    assert status == 503
    assert body == {"error": "unavailable"}
    assert headers.get("retry-after")
    stats = app.stats()
    assert stats["counts"].get("accepted", 0) == 0
    assert stats["counts"]["store_error"] == 1
    assert stats["store"]["queued"] == 0
    _flush(app)
    assert store.calls == [3]
    assert not _objects(store)


async def test_the_batch_size_is_configurable(make):
    app, store = make(store_batch_size=4)
    for _ in range(9):
        await _scan(app)
    _flush(app)
    assert sum(store.calls) == 9 and max(store.calls) <= 4


async def test_shutdown_writes_what_is_queued(make):
    app, store = make()
    for _ in range(3):
        await _scan(app)
    app.close()
    assert store.calls == [3]
    assert len(list(store.read_verdicts("1990-01-01T00:00:00Z", None))) == 3


async def test_a_failing_store_is_counted_and_the_scan_still_answers(make):
    app, store = make(fail=True)
    assert (await _scan(app))[0] == 200
    _flush(app)
    _, stats = await _stats(app)
    assert stats["store"]["errors"] >= 1


async def test_the_store_counters_are_in_stats(make):
    app, _ = make()
    await _scan(app)
    _flush(app)
    status, stats = await _stats(app)
    assert status == 200
    for key in ("written", "dropped", "errors", "queued", "batched", "inflight", "pending",
                "flushes", "last_flush_ms"):
        assert key in stats["store"], key
    assert stats["store"]["written"] == 1


def _wait_for(condition, timeout_s=5.0):
    import time

    deadline = time.monotonic() + timeout_s
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.01)


async def test_records_the_writer_holds_are_pending_in_stats(make):
    """Pulled off the queue into the writer's batch, not yet written."""
    app, store = make(store_flush_s=3600)
    for _ in range(3):
        await _scan(app)
    _wait_for(lambda: app.sink._queue.qsize() == 0)
    store_stats = app.stats()["store"]
    assert store_stats["queued"] == 0
    assert store_stats["batched"] == 3
    assert store_stats["inflight"] == 0
    assert store_stats["pending"] == 3
    _flush(app)
    assert app.stats()["store"]["pending"] == 0
    assert store.calls == [3]


async def test_a_write_in_progress_is_pending_in_stats(tmp_path):
    import threading

    started, release = threading.Event(), threading.Event()

    class Stalled(CountingStore):
        def write_verdicts(self, records):
            started.set()
            release.wait(10)
            return super().write_verdicts(records)

    app = Intake(_policy(store_batch_size=2),
                 store=Stalled(tmp_path / "store", instance="t"))
    try:
        for _ in range(2):
            await _scan(app)
        assert started.wait(5)
        store_stats = app.stats()["store"]
        assert store_stats["inflight"] == 2
        assert store_stats["batched"] == 0
        assert store_stats["pending"] == 2
    finally:
        release.set()
        app.close()
