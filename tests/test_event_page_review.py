"""Event Log paging: crafted cursors, writer-chosen request ids, every row
seen once, and the connector's read budget."""

from __future__ import annotations

import base64
import json
import random
import re

import pytest
from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.store import LocalFileStore, VerdictRecord
from forgd_verdict.store.views import EVENT_PAGE, EventCursor, _event_order, event_page


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# --- 1. a nested-JSON cursor ------------------------------------------------

def test_deeply_nested_cursor_is_refused_not_raised():
    raw = _b64(b"[" * 1500)
    assert len(raw) <= 2048
    assert EventCursor.decode(raw) is None


async def test_deeply_nested_cursor_serves_200(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([VerdictRecord(source="inference_hook", surface="claude-ai",
                                        observed_at="2026-09-17T10:00:00Z",
                                        request_id="req00001")])
    client = ASGIClient(Dashboard(store))
    status, _ = await client.get("/events?window=all&before=" + _b64(b"[" * 1500))
    assert status == 200


# --- 2. a record's request_id makes the next-page cursor undecodable --------

@pytest.mark.parametrize("rid", ["evil\x01id", "\U0001F600" * 128])
def test_a_writer_chosen_request_id_stays_out_of_the_cursor(rid):
    guard = MetadataGuard([], "salt")
    rec = guard.record(VerdictRecord(source="code_hook", request_id=rid,
                                     observed_at="2026-09-17T10:00:00Z"), untrusted=True)
    assert rec.request_id == rid  # the guard keeps it
    order = _event_order(rec, "source=code_hook/org=o/date=2026-09-17/t-000001.jsonl", 0)
    cursor = EventCursor.time("2026-09-17", order)
    assert rid not in json.dumps(order)
    assert EventCursor.decode(cursor.encode()) == cursor


async def test_older_link_past_a_crafted_request_id_does_not_restart_at_newest(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    # EVENT_PAGE newer rows, the last of which (position EVENT_PAGE-1) has the
    # crafted id, then older rows that the Older link should reach.
    recs = [VerdictRecord(source="code_hook", surface="claude-code", action="deny",
                          observed_at=f"2026-09-17T10:{n // 60:02d}:{n % 60:02d}Z",
                          request_id=f"new{n:05d}") for n in range(EVENT_PAGE + 5)]
    recs.sort(key=lambda r: r.observed_at, reverse=True)
    recs[EVENT_PAGE - 1].request_id = "evil\x01id"
    store.write_verdicts(recs)
    client = ASGIClient(Dashboard(store))
    _, first = await client.get("/events?window=all")
    m = re.search(r'href="(/events\?[^"]*before=[^"]*)"[^>]*>Older', first)
    assert m, "no Older link"
    _, second = await client.get(m.group(1).replace("&amp;", "&"))
    first_ids = set(re.findall(r"new\d{5}", first))
    second_ids = set(re.findall(r"new\d{5}", second))
    assert not (first_ids & second_ids), "page 2 repeats page 1: the cursor was dropped"
    assert {f"new{n:05d}" for n in range(5)} <= second_ids


# --- 3. fuzz: pages under change, many orgs, odd days, undated objects ------

TIMES = ["2026-10-0{d}T{h:02d}:00:00Z", "2026-10-0{d}T{h:02d}:00:00.5Z",
         "2026-10-0{d}T{h:02d}:00:00+02:00", "2026-10-0{d}T{h:02d}:00:00",
         "2026-10-0{d}", "", None, "garbage{d}"]


def _rand_rec(rng, i, prefix="r"):
    t = rng.choice(TIMES)
    at = None if t is None else t.format(d=rng.randint(4, 6), h=rng.choice([0, 1, 23]))
    return VerdictRecord(source=rng.choice(["code_hook", "inference_hook"]),
                         observed_at=at, request_id=rng.choice([f"{prefix}{i}", None, "dup"]),
                         session_id=f"{prefix}{i}",
                         tenant_hash=rng.choice(["orgA", "orgB"]),
                         action=rng.choice(["allow", "deny"]))


def _undated(store, rng, i):
    path = store.root / "verdicts" / f"loose-{i:04d}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [_rand_rec(rng, f"{i}_{k}", "u") for k in range(rng.randint(1, 4))]
    path.write_text("".join(r.to_json() + "\n" for r in rows))
    return rows


@pytest.mark.parametrize("seed", range(600))
def test_fuzz_every_row_that_existed_is_seen_once(tmp_path, seed):
    rng = random.Random(seed)
    store = LocalFileStore(tmp_path / "s", instance="t")
    existing = []
    for i in range(rng.randint(20, 120)):
        batch = [_rand_rec(rng, f"{i}_{k}") for k in range(rng.randint(1, 5))]
        for r in batch:
            if not r.observed_at:
                r.observed_at = "garbage"
        store.write_verdicts(batch)
        existing += batch
    for i in range(rng.randint(0, 3)):
        existing += _undated(store, rng, i)
    orgs = rng.choice([None, {"orgA"}])
    action = rng.choice(["all", "deny"])
    limit = rng.randint(1, 30)
    budget = rng.choice([3, 10, 50, 20_000])
    want = [r.session_id for r in event_page(store, None, orgs, action, limit=10**6,
                                             budget=10**9).records]
    writers = [LocalFileStore(tmp_path / "s", instance=n) for n in ("a", "m", "z")]
    seen, cursor, added = [], None, 0
    for _ in range(5000):
        page = event_page(store, None, orgs, action, before=cursor, limit=limit, budget=budget)
        assert len(page.records) <= limit
        seen += [r.session_id for r in page.records]
        if page.before is None:
            break
        cursor = EventCursor.decode(page.before.encode())
        assert cursor == page.before
        if rng.random() < 0.5:
            w = rng.choice(writers)
            nr = _rand_rec(rng, added, "n")
            nr.observed_at = nr.observed_at or "garbage"
            w.write_verdicts([nr])
            added += 1
    else:
        raise AssertionError("walk did not end")
    assert len(seen) == len(set(seen)), "duplicate"
    assert set(want) - set(seen) == set(), "missing"


def test_the_connector_scoped_store_keeps_the_read_budget(tmp_path):
    from test_event_log_paging import SINCE, CountingStore, _burst

    from forgd_verdict.connector.tools import ScopedStore

    store = CountingStore(tmp_path / "s", instance="t")
    _burst(store, 600)
    store.fetched = 0
    event_page(store, SINCE, None, limit=50, budget=100)
    direct = store.fetched
    store.fetched = 0
    event_page(ScopedStore(store, None), SINCE, None, limit=50, budget=100)
    assert store.fetched <= direct + 1, (direct, store.fetched)
