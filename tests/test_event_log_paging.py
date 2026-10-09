"""Event Log paging: the (observed_at, key, line) cursor, the row cap, and
the cursor's URL form."""

from __future__ import annotations

import base64
import json
import random
import re

import pytest
from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.store import LocalFileStore, VerdictRecord
from forgd_verdict.store.views import (
    EVENT_PAGE,
    EVENT_SCAN_BUDGET,
    EventCursor,
    event_page,
    event_time_key,
)

SINCE = "2026-09-01T00:00:00Z"


class CountingStore(LocalFileStore):
    """A local store that counts the verdict objects it fetches."""

    fetched = 0

    def _object(self, rel: str) -> bytes:
        self.fetched += 1
        return super()._object(rel)


def _order(r: VerdictRecord) -> str:
    return event_time_key(r.observed_at)


def walk(store, *, limit, budget=EVENT_SCAN_BUDGET, orgs=None, between=None):
    """Every page from the newest, the cursor passed through its URL form.
    Returns the request ids in page order and the objects fetched per page."""
    seen, fetches, cursor = [], [], None
    for _ in range(20_000):
        store.fetched = 0
        page = event_page(store, SINCE, orgs, before=cursor, limit=limit, budget=budget)
        fetches.append(store.fetched)
        assert len(page.records) <= limit
        assert page.records == sorted(page.records, key=_order, reverse=True)
        seen += [r.request_id for r in page.records]
        if page.before is None:
            return seen, fetches
        cursor = EventCursor.decode(page.before.encode())
        assert cursor == page.before
        if between is not None:
            between()
    raise AssertionError("the walk did not end")


def _burst(store, n: int, *, at="2026-09-17T10:00:00Z", prefix="r") -> list[str]:
    """`n` records in one second, one object per write."""
    ids = [f"{prefix}{i:05d}" for i in range(n)]
    for rid in ids:
        store.write_verdicts([VerdictRecord(source="inference_hook", observed_at=at,
                                            surface="claude-ai", action="allow",
                                            request_id=rid)])
    return ids


def test_a_burst_in_one_second_pages_at_the_limit_without_loss_or_repeat(tmp_path):
    store = CountingStore(tmp_path / "s", instance="t")
    ids = _burst(store, 5000)
    seen, fetches = walk(store, limit=50)
    assert len(seen) == len(set(seen))
    assert sorted(seen) == ids
    assert len(fetches) == 100
    assert max(fetches) <= EVENT_SCAN_BUDGET + 1
    print(f"\nburst, default budget: pages={len(fetches)} fetches/page max={max(fetches)}")


def test_rows_that_share_a_time_and_have_no_request_id_page_without_loss(tmp_path):
    store = CountingStore(tmp_path / "s", instance="t")
    for n in range(120):
        store.write_verdicts([VerdictRecord(source="code_hook", surface="claude-code",
                                            observed_at="2026-09-17T10:00:00Z",
                                            session_id=f"s{n:03d}")])
    seen, cursor = [], None
    while True:
        page = event_page(store, SINCE, None, before=cursor, limit=50)
        assert len(page.records) <= 50
        seen += [r.session_id for r in page.records]
        if page.before is None:
            break
        cursor = EventCursor.decode(page.before.encode())
    assert sorted(seen) == [f"s{n:03d}" for n in range(120)]


PROBE_CONFIGS = [dict(limit=50), dict(limit=37), dict(limit=1),
                 dict(limit=200, budget=10), dict(orgs={"orgA"}, limit=13)]


@pytest.fixture(scope="module")
def probe_store(tmp_path_factory):
    """Three days, 37 records per timestamp, two sources and two orgs, and
    five more at the midnight edge; one object per write."""
    store = CountingStore(tmp_path_factory.mktemp("probe") / "s", instance="t")
    rng = random.Random(1)
    recs, i = [], 0
    for day in ("2026-10-04", "2026-10-05", "2026-10-06"):
        for hh in range(0, 24, 3):
            for _ in range(37):
                i += 1
                recs.append(VerdictRecord(
                    source=rng.choice(["code_hook", "inference_hook"]),
                    observed_at=f"{day}T{hh:02d}:00:00Z", request_id=f"r{i}",
                    tenant_hash=rng.choice(["orgA", "orgB"])))
    for k in range(5):
        recs.append(VerdictRecord(source="inference_hook", observed_at="2026-10-05T00:00:00Z",
                                  request_id=f"m{k}", tenant_hash="orgA"))
    for r in recs:
        store.write_verdicts([r])
    return store, recs


@pytest.mark.parametrize("config", PROBE_CONFIGS, ids=str)
def test_the_review_probe_finds_every_event_once(probe_store, config):
    store, recs = probe_store
    seen, _ = walk(store, **config)
    orgs = config.get("orgs")
    want = {r.request_id for r in recs if orgs is None or r.tenant_hash in orgs}
    assert len(seen) - len(set(seen)) == 0, "duplicates"
    assert want - set(seen) == set(), "missing"
    assert set(seen) - want == set(), "out of scope"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


MALFORMED = [
    "", "2026-09-17T10:00:00Z", "!!!!", "a" * 5000, _b64(b"not json"), _b64(b"{}"),
    _b64(b"[]"), _b64(json.dumps(["t"]).encode()),
    _b64(json.dumps(["t", "2026-09-17", "2026-09-17T10:00:00Z", "r1"]).encode()),
    _b64(json.dumps(["t", "2026/09/17", "2026-09-17T10:00:00Z", "k", 0]).encode()),
    _b64(json.dumps(["t", "2026-09-17", 7, "k", 0]).encode()),
    _b64(json.dumps(["t", "2026-09-17", "x" * 300, "k", 0]).encode()),
    _b64(json.dumps(["t", "2026-09-17", "2026-09-17T10:00:00Z\n", "k", 0]).encode()),
    _b64(json.dumps(["t", "2026-09-17", "2026-09-17T10:00:00Z", "k", -1]).encode()),
    _b64(json.dumps(["t", "2026-09-17", "2026-09-17T10:00:00Z", "k", True]).encode()),
    _b64(json.dumps(["t", "2026-09-17", "2026-09-17T10:00:00Z", "k", 1.5]).encode()),
    _b64(json.dumps(["t", "2026-09-17", "2026-09-17T10:00:00Z", "\x00", 0]).encode()),
    _b64(json.dumps(["d", "2026-09-17", "extra"]).encode()),
    _b64(json.dumps(["z", "2026-09-17"]).encode()),
    _b64(json.dumps(["d", True]).encode()),
]


@pytest.mark.parametrize("raw", MALFORMED)
def test_a_malformed_cursor_is_refused(raw):
    assert EventCursor.decode(raw) is None


async def test_a_malformed_cursor_serves_the_first_page(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([VerdictRecord(source="inference_hook", surface="claude-ai",
                                        observed_at=f"2026-09-17T10:00:{n:02d}Z",
                                        request_id=f"req{n:05d}") for n in range(5)])
    client = ASGIClient(Dashboard(store))
    _, first = await client.get("/events?window=all")
    want = re.findall(r"req\d{5}", first)
    assert len(want) == 5
    for raw in MALFORMED:
        status, html = await client.get(f"/events?window=all&before={raw}")
        assert status == 200
        assert re.findall(r"req\d{5}", html) == want
        assert ">Newest</a>" not in html


def test_a_cursor_round_trips_through_its_url_form():
    for cursor in (EventCursor.time("2026-09-17", ("2026-09-17T10:00:00Z", "k", 3)),
                   EventCursor.time(None, ("", "", 0)), EventCursor.done("2026-09-17"),
                   EventCursor.done(None)):
        text = cursor.encode()
        assert re.fullmatch(r"[A-Za-z0-9_-]+", text)
        assert EventCursor.decode(text) == cursor


ODD_TIMES = [
    ("utc", "2026-10-06T01:00:00Z"),
    ("frac", "2026-10-06T01:00:00.250Z"),
    ("before", "2026-10-06T00:59:59.9Z"),
    ("offset", "2026-10-06T04:00:00+02:00"),
    ("empty", ""),
    ("missing", None),
    ("garbage", "garbage"),
]
UNTIMED = {"empty", "missing", "garbage"}


def _raw_object(store: LocalFileStore, name: str, rows) -> None:
    """Lines written straight into one dated partition object, as another
    writer or an older version might have left them."""
    path = (store.root / "verdicts/source=inference_hook/org=unattributed/date=2026-10-06"
            / name)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for rid, at in rows:
        body = {"source": "inference_hook", "surface": "claude-ai", "request_id": rid}
        if at is not None:
            body["observed_at"] = at
        lines.append(json.dumps(body))
    path.write_text("\n".join(lines) + "\n")


def _walk_ids(store, limit):
    seen, cursor, pages = [], None, 0
    while True:
        page = event_page(store, None, None, before=cursor, limit=limit)
        assert len(page.records) <= limit
        seen += [r.request_id for r in page.records]
        pages += 1
        assert pages <= 50, "the walk did not end"
        if page.before is None:
            return seen
        assert page.before != cursor, "the cursor did not move"
        cursor = EventCursor.decode(page.before.encode())


@pytest.mark.parametrize("limit", [1, 2, 3])
def test_odd_timestamps_page_in_true_time_order_and_untimed_rows_last(tmp_path, limit):
    store = LocalFileStore(tmp_path / "s", instance="t")
    _raw_object(store, "x-000001.jsonl", ODD_TIMES)
    seen = _walk_ids(store, limit)
    assert len(seen) == len(set(seen)) == len(ODD_TIMES)
    assert seen[:4] == ["offset", "frac", "utc", "before"]
    assert set(seen[4:]) == UNTIMED


def test_rows_tied_to_one_second_with_untimed_rows_page_once_each(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    tied = [(f"t{n}", "2026-10-06T01:00:00Z") for n in range(4)]
    tied += [("tz", "2026-10-06T01:00:00.000Z"), ("toff", "2026-10-06T03:00:00+02:00")]
    _raw_object(store, "x-000001.jsonl", tied + [("empty", ""), ("missing", None)])
    _raw_object(store, "y-000001.jsonl", [("garbage", "garbage")])
    seen = _walk_ids(store, 1)
    assert len(seen) == len(set(seen)) == 9
    assert set(seen[:6]) == {rid for rid, _ in tied}
    assert set(seen[6:]) == UNTIMED


def test_a_page_ending_on_an_untimed_row_names_its_day_not_a_time(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    _raw_object(store, "x-000001.jsonl", ODD_TIMES)
    page = event_page(store, None, None, limit=6)
    assert page.records[-1].request_id in UNTIMED
    assert page.before is not None and page.before.label == "2026-10-06"
    page = event_page(store, None, None, limit=2)
    assert page.before.label == "2026-10-06 01:00:00 UTC"


async def test_the_older_links_walk_past_a_partition_whose_day_is_not_a_date(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([VerdictRecord(source="inference_hook", surface="claude-ai",
                                        observed_at="garbage", request_id=f"req9{n:04d}")
                          for n in range(EVENT_PAGE)])
    store.write_verdicts([VerdictRecord(source="inference_hook", surface="claude-ai",
                                        observed_at=f"2026-10-0{d}T01:00:00Z",
                                        request_id=f"req0000{d}") for d in range(1, 4)])
    client = ASGIClient(Dashboard(store))
    seen, path = [], "/events?window=all"
    for _ in range(10):
        _, html = await client.get(path)
        seen += re.findall(r"req\d{5}", html)
        m = re.search(r'href="(/events\?[^"]*before=[^"]*)"[^>]*>Older', html)
        if m is None:
            break
        path = m.group(1).replace("&amp;", "&")
        assert "00:00:00 UTC" not in html or "garbage" not in html
    else:
        raise AssertionError(f"the Older links never ended: {seen}")
    assert sorted(set(seen)) == ["req00001", "req00002", "req00003"] + [
        f"req9{n:04d}" for n in range(EVENT_PAGE)]
    assert len(seen) == len(set(seen))


def test_a_cursor_may_name_any_partition_day_a_write_can_make():
    assert EventCursor.decode(EventCursor.done("garbage").encode()) == EventCursor.done("garbage")
    assert EventCursor.done("garbage").label == "the date=garbage partition"
    for day in ("", "a/b", "x" * 11, "a\x00"):
        assert EventCursor.decode(EventCursor.done(day).encode()) is None, day
