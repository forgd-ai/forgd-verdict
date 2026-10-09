"""A store write that hangs must not take `/scan` or the intake with it.

`/intake` answers only after its batch is in the store, so a store that
stops answering holds the request. These pin what the intake does then:
the write runs on its own small pool, a full pool refuses rather than
queues, a slow write is answered 503 before the shipper gives up, and a
retry of a batch whose write is still running or has landed is not
written a second time.

The dedupe is per process and bounded. Across a restart, or once the
batch has been evicted from the map, a retry is written again: delivery
is at-least-once, and the last two tests pin that.
"""

from __future__ import annotations

import asyncio
import inspect
import time

import pytest
from _intake_fakes import PROBE, TOKEN, HangingStore, auth, policy
from conftest import ASGIClient

from forgd_verdict.hook import ship
from forgd_verdict.intake import app as intake_app
from forgd_verdict.intake.app import Intake
from forgd_verdict.store.base import SOURCE_CODE_HOOK, FindingRow, VerdictRecord

pytestmark = pytest.mark.serial

# A bound on /scan's latency while writes are stuck, not a comparison.
SCAN_BOUND_S = 2.0
STUCK = 32


@pytest.fixture
def store(tmp_path):
    return HangingStore(tmp_path)


@pytest.fixture
def intake(store):
    app = Intake(policy(), store=store)
    yield app
    store.release.set()
    app.close()


def _batch(tag: str, n: int = 2) -> bytes:
    records = [VerdictRecord(
        source=SOURCE_CODE_HOOK,
        observed_at="2026-10-06T10:00:00Z",
        request_id=f"{PROBE}{tag}:{i}",
        surface="claude-code-local",
        action="deny",
        findings=[FindingRow("regex:aws-access-key", "block", "cmd", "h1")],
        findings_count=1,
    ) for i in range(n)]
    return ("\n".join(r.to_json() for r in records) + "\n").encode()


async def _ship(app, body: bytes):
    return await ASGIClient(app).request("POST", "/intake", body, auth())


async def _until(predicate, timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.01)


async def test_a_scan_completes_while_intake_writes_are_stuck(intake, store):
    stuck = [asyncio.create_task(_ship(intake, _batch(f"a{i}"))) for i in range(STUCK)]
    await _until(lambda: store.entered >= 1)
    await asyncio.sleep(0.3)
    assert not store.release.is_set()

    started = time.monotonic()
    status, body = await asyncio.wait_for(
        ASGIClient(intake).post(
            "/scan", b'{"hook_event_name": "UserPromptSubmit", '
                     b'"user_input": "refactor the parser"}',
            {"authorization": f"Bearer {TOKEN}", "content-type": "application/json"}),
        SCAN_BOUND_S)
    assert time.monotonic() - started < SCAN_BOUND_S
    assert not store.release.is_set()
    assert status == 200, body

    store.release.set()
    await asyncio.gather(*stuck)


async def test_a_full_write_pool_refuses_and_does_not_queue(intake, store):
    workers = intake.writes.workers
    assert 1 <= workers <= 8, "the write pool should be small and fixed"
    # Filled one batch at a time: a burst would also meet the parse slots,
    # whose 503 leaves a write slot free.
    stuck = []
    for i in range(workers):
        stuck.append(asyncio.create_task(_ship(intake, _batch(f"b{i}"))))
        await _until(lambda n=i + 1: store.entered == n)

    # Nothing waits behind a full pool: every further batch is answered at
    # once with a 503 the hook parks and retries.
    burst = [asyncio.create_task(_ship(intake, _batch(f"x{i}")))
             for i in range(STUCK)]
    for status, body, headers in await asyncio.wait_for(
            asyncio.gather(*burst), SCAN_BOUND_S * 5):
        assert status == 503, body
        assert "retry-after" in headers

    status, body, headers = await asyncio.wait_for(
        _ship(intake, _batch("b-next")), SCAN_BOUND_S)
    assert status == 503 and "retry-after" in headers
    assert body["reason"] == "busy"
    assert store.entered == workers

    store.release.set()
    await asyncio.gather(*stuck)


def test_the_write_timeout_is_below_the_shippers_timeout():
    shipper = inspect.signature(ship.ship_to_endpoint).parameters["timeout_s"].default
    assert 0 < intake_app.WRITE_TIMEOUT_S < shipper


async def test_a_write_slower_than_the_timeout_is_answered_503(intake, store, monkeypatch):
    monkeypatch.setattr(intake_app, "WRITE_TIMEOUT_S", 0.2, raising=False)
    status, body, headers = await asyncio.wait_for(_ship(intake, _batch("c")), SCAN_BOUND_S)
    assert status == 503, body
    assert "retry-after" in headers


async def test_a_retry_while_the_first_write_runs_is_not_written_again(
        intake, store, monkeypatch):
    monkeypatch.setattr(intake_app, "WRITE_TIMEOUT_S", 0.2, raising=False)
    body = _batch("d", n=3)

    first, _, _ = await asyncio.wait_for(_ship(intake, body), SCAN_BOUND_S)
    assert first == 503
    retry, _, headers = await asyncio.wait_for(_ship(intake, body), SCAN_BOUND_S)
    assert retry == 503 and "retry-after" in headers
    assert store.entered == 1

    store.release.set()
    await _until(lambda: len(store.landed) == 3)

    status, answer, _ = await asyncio.wait_for(_ship(intake, body), SCAN_BOUND_S)
    assert status == 200
    assert answer["accepted"] == 3
    assert store.entered == 1
    assert sorted(store.landed) == sorted(f"{PROBE}d:{i}" for i in range(3))


async def test_a_retry_after_the_write_landed_answers_the_original_count(intake, store):
    store.release.set()
    body = _batch("e", n=2)
    status, first, _ = await _ship(intake, body)
    assert status == 200 and first["accepted"] == 2

    status, again, _ = await _ship(intake, body)
    assert status == 200
    assert again["accepted"] == 2
    assert store.entered == 1


async def test_a_different_batch_is_still_written(intake, store):
    store.release.set()
    assert (await _ship(intake, _batch("f1")))[0] == 200
    assert (await _ship(intake, _batch("f2")))[0] == 200
    assert store.entered == 2


async def test_a_retry_after_a_restart_is_written_again(store):
    """At-least-once: the dedupe map does not survive the process."""
    store.release.set()
    body = _batch("g")
    for _ in range(2):
        app = Intake(policy(), store=store)
        try:
            assert (await _ship(app, body))[0] == 200
        finally:
            app.close()
    assert store.entered == 2


async def test_a_retry_after_eviction_is_written_again(intake, store, monkeypatch):
    """At-least-once: an entry the bounded map dropped is written again."""
    monkeypatch.setattr(intake_app, "WRITTEN_BATCHES_MAX", 2, raising=False)
    store.release.set()
    first = _batch("h0")
    for tag in ("h0", "h1", "h2"):
        assert (await _ship(intake, _batch(tag)))[0] == 200
    assert (await _ship(intake, first))[0] == 200
    assert store.entered == 4


async def test_a_write_that_lands_after_its_timeout_is_counted(intake, store, monkeypatch):
    monkeypatch.setattr(intake_app, "WRITE_TIMEOUT_S", 0.2, raising=False)
    status, _, _ = await asyncio.wait_for(_ship(intake, _batch("i", n=2)), SCAN_BOUND_S)
    assert status == 503
    assert intake.stats()["counts"].get("records", 0) == 0

    store.release.set()
    await _until(lambda: intake.stats()["counts"].get("late_landed") == 1)
    stats = intake.stats()
    assert stats["counts"]["records"] == 2
    assert stats["by_client"] == {"alice-laptop": 2}
