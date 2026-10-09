"""Event Log paging when a day is larger than a page's read budget: the day
is read in key order and its cursor is a position in it."""

from __future__ import annotations

import base64
import json

import pytest
from test_event_log_paging import SINCE, CountingStore, _burst, walk

from forgd_verdict.dashboard.render import render_events
from forgd_verdict.store import VerdictRecord
from forgd_verdict.store.views import EventCursor, event_page


@pytest.fixture(scope="module")
def burst_store(tmp_path_factory):
    store = CountingStore(tmp_path_factory.mktemp("burst") / "s", instance="t")
    return store, _burst(store, 5000)


def test_a_burst_larger_than_the_budget_reads_a_bounded_number_of_objects(burst_store):
    store, ids = burst_store
    seen, fetches = walk(store, limit=50, budget=500)
    assert len(seen) == len(set(seen))
    assert sorted(seen) == ids
    assert len(fetches) == 100
    assert max(fetches) <= 500 // 1 + 1
    print(f"\nburst, budget=500: pages={len(fetches)} fetches/page first={fetches[0]} "
          f"max={max(fetches)} min={min(fetches)} total={sum(fetches)}")


def test_a_page_from_a_day_over_budget_says_its_order_is_approximate(burst_store):
    store, _ = burst_store
    page = event_page(store, SINCE, None, limit=50, budget=500)
    assert page.before is not None and page.before.kind == "position"
    assert page.approximate == "2026-09-17"
    exact = event_page(store, SINCE, None, limit=50)
    assert exact.approximate is None
    html = render_events(page.records, approximate=page.approximate)
    assert "order within 2026-09-17 is approximate" in html
    assert "approximate" not in render_events(exact.records)


def test_objects_written_between_pages_lose_or_repeat_nothing_that_existed(tmp_path):
    store = CountingStore(tmp_path / "s", instance="t")
    ids = _burst(store, 300)
    writers = [CountingStore(tmp_path / "s", instance=name) for name in ("a", "m", "z")]
    written = []

    def between():
        n = len(written)
        for i, w in enumerate(writers):
            rid = f"new{n + i:05d}"
            at = "2026-09-17T10:00:00Z" if i % 2 else "2026-09-17T10:00:01Z"
            w.write_verdicts([VerdictRecord(source="inference_hook", observed_at=at,
                                            request_id=rid)])
            written.append(rid)

    seen, fetches = walk(store, limit=40, budget=100, between=between)
    assert len(seen) == len(set(seen)), "a row was shown twice"
    assert set(ids) <= set(seen), "a row that existed was lost"
    assert set(seen) <= set(ids) | set(written)
    assert max(fetches) <= 101


def _two_orgs(store, n):
    for day in ("2026-09-16", "2026-09-17"):
        for i in range(n):
            for org in ("orgA", "orgB"):
                store.write_verdicts([VerdictRecord(source="inference_hook", tenant_hash=org,
                                                    observed_at=f"{day}T10:00:00Z",
                                                    request_id=f"{org}-{day}-{i:04d}")])


@pytest.mark.parametrize("key", [
    "source=inference_hook/org=orgB/date=2026-09-17/t-000001.jsonl",
    "../../../etc/passwd",
    "zzzz",
    "",
])
def test_a_cursor_naming_a_key_out_of_scope_shows_nothing_out_of_scope(tmp_path, key):
    store = CountingStore(tmp_path / "s", instance="t")
    _two_orgs(store, 60)
    fetched = []
    store._object = lambda rel: (fetched.append(rel), CountingStore._object(store, rel))[1]
    cursor = EventCursor.decode(EventCursor.position("2026-09-17", key, 3, None).encode())
    assert cursor is not None
    page = event_page(store, SINCE, {"orgA"}, before=cursor, limit=20, budget=30)
    assert page.records
    assert all(r.tenant_hash == "orgA" for r in page.records)
    assert fetched and all("/org=orgA/" in rel and ".." not in rel for rel in fetched)


def test_a_position_cursor_round_trips_and_a_bad_one_is_refused():
    for cursor in (EventCursor.position("2026-09-17", "k/a.jsonl", 4, None),
                   EventCursor.position(None, "k", 0, ("2026-09-17T10:00:00Z", "k", 2))):
        assert EventCursor.decode(cursor.encode()) == cursor
    for body in (["p", "2026-09-17", "k"], ["p", "2026-09-17", "k", -1],
                 ["p", "2026-09-17", 5, 0], ["p", "2026-09-17", "k", 0, "t", "r", "k"],
                 ["p", "2026-09-17", "k" * 2000, 0]):
        raw = base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip("=")
        assert EventCursor.decode(raw) is None, body
