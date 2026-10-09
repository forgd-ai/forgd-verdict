"""A shipped batch is bounded by its record count, and parsed off the loop.

The body limit bounds bytes, but one byte budget holds hundreds of
thousands of minimal lines, and each is a record to parse, bind and guard.
Above `MAX_RECORDS` the batch is refused with 413 before any line is
parsed; at or below it, parsing runs in a worker thread so the event loop
keeps answering other requests.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest
from _intake_fakes import HangingStore, auth, policy
from conftest import ASGIClient

from forgd_verdict.intake import app as intake_app
from forgd_verdict.intake.app import Intake
from forgd_verdict.store.base import SOURCE_CODE_HOOK, VerdictRecord

HEALTHZ_BOUND_S = 0.5


@pytest.fixture
def store(tmp_path):
    s = HangingStore(tmp_path)
    s.release.set()
    return s


@pytest.fixture
def intake(store):
    app = Intake(policy(), store=store)
    yield app
    app.close()


# A deny, so each line stays a record carrying its probe id: clean allows
# are folded into one tally row.
_DENY = {"action": "deny", "findings_count": 1, "findings": [
    {"detector": "regex:aws-access-key", "severity": "block", "locator": "p",
     "excerpt_hash": "h"}]}


def _lines(n: int) -> bytes:
    line = json.dumps({"source": SOURCE_CODE_HOOK, "request_id": "probe:j", **_DENY})
    return ("\n".join([line] * n) + "\n").encode()


def _counting_parses(monkeypatch) -> list[int]:
    calls = [0]
    real = VerdictRecord.from_json

    def counted(*args, **kwargs):
        calls[0] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(VerdictRecord, "from_json", counted)
    return calls


async def test_one_record_over_the_cap_is_refused_unparsed(intake, store, monkeypatch):
    parses = _counting_parses(monkeypatch)
    status, body = await ASGIClient(intake).post(
        "/intake", _lines(intake_app.MAX_RECORDS + 1), auth())
    assert status == 413
    assert body["error"] == "too_many_records"
    assert body["max_records"] == intake_app.MAX_RECORDS
    assert parses[0] == 0
    assert store.entered == 0


async def test_blank_lines_do_not_count_toward_the_cap(intake, store):
    body = _lines(intake_app.MAX_RECORDS).replace(b"\n", b"\n\n  \n")
    status, answer = await ASGIClient(intake).post("/intake", body, auth())
    assert status == 200, answer
    assert answer["accepted"] == intake_app.MAX_RECORDS


async def test_exactly_the_cap_is_accepted(intake, store):
    status, body = await ASGIClient(intake).post(
        "/intake", _lines(intake_app.MAX_RECORDS), auth())
    assert status == 200, body
    assert body["accepted"] == intake_app.MAX_RECORDS
    assert store.entered == 1


async def test_a_refused_batch_is_not_remembered(intake, store):
    over = _lines(intake_app.MAX_RECORDS + 1)
    for _ in range(2):
        status, _ = await ASGIClient(intake).post("/intake", over, auth())
        assert status == 413
    assert store.entered == 0


@pytest.mark.serial
async def test_healthz_answers_while_a_large_batch_is_handled(intake, store):
    near_limit = intake.max_body - 64 * 1024
    line = json.dumps({"source": SOURCE_CODE_HOOK, "request_id": "probe:k", **_DENY})
    body = _lines(near_limit // (len(line) + 1))
    assert len(body) <= intake.max_body

    client = ASGIClient(intake)
    started = time.monotonic()
    shipping = asyncio.create_task(client.post("/intake", body, auth()))
    # Let the batch start first; it holds the loop until its first await.
    await asyncio.sleep(0)
    status, _ = await asyncio.wait_for(client.get("/healthz"), 30)
    elapsed = time.monotonic() - started
    assert status == 200
    assert elapsed < HEALTHZ_BOUND_S, f"/healthz took {elapsed:.2f}s"
    shipped, _ = await shipping
    assert shipped < 500, shipped


async def test_the_batch_digest_is_computed_off_the_loop(intake, store, monkeypatch):
    loop_thread = threading.get_ident()
    seen: list[int] = []
    real = intake_app.BatchWrites.key

    def recorded(caller, body):
        seen.append(threading.get_ident())
        return real(caller, body)

    monkeypatch.setattr(intake_app.BatchWrites, "key", staticmethod(recorded))
    status, _ = await ASGIClient(intake).post("/intake", _lines(2), auth())
    assert status == 200
    assert seen and loop_thread not in seen


def test_counting_lines_never_builds_a_list_of_the_whole_body():
    """8 MiB of minimal lines is refused after a scan, not after splitting it
    into millions of objects."""
    import tracemalloc

    body = b"{}\n" * (8 * 1024 * 1024 // 3)
    tracemalloc.start()
    try:
        assert intake_app._nonempty_lines(body, intake_app.MAX_RECORDS) is None
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2 * 1024 * 1024, peak


def test_blank_lines_cost_nothing_and_count_for_nothing():
    body = b"\n" * (4 * 1024 * 1024) + b'{"a":1}\n' + b"  \r\n" * 1000
    assert intake_app._nonempty_lines(body, intake_app.MAX_RECORDS) == [b'{"a":1}']


def test_limit_is_exact():
    assert len(intake_app._nonempty_lines(b"x\n" * 5000, 5000)) == 5000
    assert intake_app._nonempty_lines(b"x\n" * 5001, 5000) is None
    assert intake_app._nonempty_lines(b"x", 5000) == [b"x"]


async def test_shipped_bodies_beyond_the_parse_slots_get_503_busy(intake):
    """Each parse holds up to MAX_RECORDS records; more at once are refused
    with Retry-After rather than piling up."""
    for _ in range(intake_app.PARSE_WORKERS):
        await intake._parsing.acquire()
    try:
        line = json.dumps({"source": SOURCE_CODE_HOOK, "request_id": "r1"}).encode() + b"\n"
        status, body = await ASGIClient(intake).post("/intake", line, auth())
        assert status == 503 and body.get("error") == "busy"
        assert intake.stats()["counts"].get("parse_busy") == 1
    finally:
        for _ in range(intake_app.PARSE_WORKERS):
            intake._parsing.release()
