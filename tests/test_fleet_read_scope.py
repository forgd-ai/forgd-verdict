"""A scoped read reads only the fleet partitions that can hold a row the
reader may see, and rows it may not see do not use up its Event Log page.

Every scoped read used to add every `fleet-*` partition and charge each
row it read to the page's budget before testing visibility. A viewer of
an org in no fleet, or of one org of a fleet whose rows are pending, got
an empty page and a cursor naming the fleet's object key: who has a fleet,
and how busy it is. Now a fleet is read only when the reader holds all of
its orgs (its pending rows are visible), or holds some of them and the
session join attributes a session to one of those. The rows a page reads
and may not show count towards `hidden_budget`, not `budget`.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from forgd_verdict.connector.tools import ScopedStore
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.attribution import AttributedStore, readable_fleets
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_OTEL_COLLECT,
    FindingRow,
    VerdictRecord,
    path_segment,
    visible,
)
from forgd_verdict.store.views import event_page, read_summary

A, B, C, D, E = (f"org_{c * 10}" for c in "abcde")
WEST, EAST = "fleet-west", "fleet-east"
FLEETS = {WEST: frozenset({B, C}), EAST: frozenset({D, E})}
DAY = "2026-10-05"
SINCE = f"{DAY}T00:00:00Z"
FLEET_N = 600
BUDGET = 100


def _sid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def _fleet(partition, orgs, n, prefix, session=lambda i: _sid(10_000 + i % 50)):
    return [VerdictRecord(
        source=SOURCE_CODE_HOOK, observed_at=f"{DAY}T{8 + i % 10:02d}:{i % 60:02d}:00Z",
        device=f"d{i % 900:012x}", client="laptops", tenant_hash=partition,
        fleet_orgs=sorted(orgs), session_id=session(i), request_id=f"{prefix}-{i}",
        action="allow", tally=3) for i in range(n)]


def _own(org, n, prefix):
    return [VerdictRecord(
        source=SOURCE_CODE_HOOK, observed_at=f"{DAY}T23:{i % 60:02d}:00Z",
        device=f"d{i:012x}", client="laptops", tenant_hash=org, request_id=f"{prefix}-{i}",
        action="deny", findings=[FindingRow("regex:aws-access-key", "block", "c", "h")],
        findings_count=1) for i in range(n)]


def _otel(org, session):
    return VerdictRecord(source=SOURCE_OTEL_COLLECT, observed_at=f"{DAY}T07:00:00Z",
                         tenant_hash=org, session_id=session, surface="claude-code",
                         request_id=f"otel-{org}-{session[-4:]}", action="allow")


def _write(store, records):
    for i in range(0, len(records), 100):
        store.write_verdicts(records[i:i + 100])


@pytest.fixture
def store(tmp_path):
    s = LocalFileStore(tmp_path / "s", instance="t")
    _write(s, _fleet(WEST, {B, C}, FLEET_N, "west"))
    _write(s, _fleet(EAST, {D, E}, FLEET_N, "east"))
    for org in (A, B, C, D):
        s.write_verdicts(_own(org, 5, f"{org}-deny"))
    return s


def _ids(page):
    return sorted(r.request_id for r in page.records if r.source == SOURCE_CODE_HOOK)


def _cursor_partition(cursor):
    if cursor is None or cursor.kind == "done":
        return None
    key = cursor.key if cursor.kind == "position" else cursor.order[1]
    return path_segment(key, "org")


def _walk(store, orgs, fleets=FLEETS, **kw):
    """Every page for `orgs`, with the partitions each cursor names."""
    pages, named, before = [], set(), None
    for _ in range(200):
        page = event_page(store, SINCE, orgs, before=before, budget=BUDGET,
                          hidden_budget=BUDGET, fleets=fleets, **kw)
        pages.append(page)
        named.add(_cursor_partition(page.before))
        if page.before is not None:
            # The cursor as the URL carries it, decoded for what it names.
            raw = json.loads(base64.urlsafe_b64decode(page.before.encode() + "=="))
            named.update(path_segment(str(v), "org") for v in raw if isinstance(v, str))
        before = page.before
        if before is None:
            break
    named.discard(None)
    return pages, named


@pytest.fixture
def opened(monkeypatch):
    """Every store object read, by path."""
    seen: list[str] = []
    real = pathlib.Path.read_bytes

    def spy(self):
        seen.append(str(self))
        return real(self)

    monkeypatch.setattr(pathlib.Path, "read_bytes", spy)
    return seen


# -- the reproduction ---------------------------------------------------------


def test_an_org_in_no_fleet_gets_its_rows_on_the_first_page(store):
    page = event_page(store, SINCE, frozenset({A}), budget=BUDGET, fleets=FLEETS)
    assert _ids(page) == sorted(f"{A}-deny-{i}" for i in range(5))
    assert page.before is None


def test_an_org_in_no_fleet_reads_no_fleet_object(store, opened):
    event_page(store, SINCE, frozenset({A}), budget=BUDGET, fleets=FLEETS)
    read_summary(store, SINCE, frozenset({A}), fleets=FLEETS)
    assert opened and not any("org=fleet-" in k for k in opened), opened


def test_one_org_of_a_fleet_with_only_pending_rows_reads_no_fleet_object(store, opened):
    page = event_page(store, SINCE, frozenset({B}), budget=BUDGET, fleets=FLEETS)
    assert _ids(page) == sorted(f"{B}-deny-{i}" for i in range(5))
    assert not any("org=fleet-" in k for k in opened), opened


def test_one_org_of_a_fleet_sees_its_joined_rows_past_the_pending_ones(tmp_path):
    s = LocalFileStore(tmp_path / "s", instance="t")
    joined = _sid(77)
    s.write_verdicts([_otel(B, joined)])
    pending = _fleet(WEST, {B, C}, FLEET_N, "pending")
    mine = _fleet(WEST, {B, C}, 3, "joined", session=lambda i: joined)
    # The joined rows are the oldest, so the pending ones are read first.
    for r in mine:
        r.observed_at = f"{DAY}T01:00:00Z"
    _write(s, pending + mine)
    s.write_verdicts(_own(B, 5, "b-deny"))
    page = event_page(s, SINCE, frozenset({B}), budget=BUDGET, fleets=FLEETS)
    want = sorted([f"b-deny-{i}" for i in range(5)] + [f"joined-{i}" for i in range(3)])
    assert _ids(page) == want
    assert all(visible(r, frozenset({B})) for r in page.records)


def test_the_hidden_budget_bounds_a_page_and_its_cursor_names_a_readable_fleet(tmp_path):
    s = LocalFileStore(tmp_path / "s", instance="t")
    joined = _sid(77)
    s.write_verdicts([_otel(B, joined)])
    _write(s, _fleet(WEST, {B, C}, FLEET_N, "pending"))
    s.write_verdicts(_fleet(WEST, {B, C}, 1, "joined", session=lambda i: joined))
    pages, named = _walk(s, frozenset({B}))
    assert len(pages) > 1
    assert named <= {B, WEST}
    assert [r.request_id for p in pages for r in p.records
            if r.source == SOURCE_CODE_HOOK] == ["joined-0"]


def test_a_viewer_of_every_fleet_org_sees_the_pending_rows(store):
    page = event_page(store, SINCE, frozenset({B, C}), fleets=FLEETS)
    assert len(page.records) == 200
    assert all(r.org in (WEST, B, C) for r in page.records)
    pages, named = _walk(store, frozenset({B, C}))
    shown = [r.request_id for p in pages for r in p.records]
    assert len(shown) == len(set(shown)) == FLEET_N + 10
    assert named <= {B, C, WEST}


@pytest.mark.parametrize("orgs,readable", [
    ({A}, {A}), ({B}, {B, WEST}), ({B, C}, {B, C, WEST}), ({A, D}, {A, D, EAST}),
    ({B, D}, {B, D, WEST, EAST}),
])
def test_cursors_never_name_a_partition_the_viewer_cannot_read(store, orgs, readable):
    store.write_verdicts([_otel(B, _sid(10_001)), _otel(D, _sid(10_002))])
    pages, named = _walk(store, frozenset(orgs))
    assert named <= readable, named
    for page in pages:
        assert all(visible(r, frozenset(orgs)) for r in page.records)


@pytest.mark.parametrize("filters", [{"client": "laptops"}, {"device": "d000000000001"},
                                     {"detector": "regex:aws-access-key"},
                                     {"action": "deny"}])
def test_filtered_pages_scope_the_same_way(store, filters):
    pages, named = _walk(store, frozenset({A}), **filters)
    assert named <= {A}
    assert {r.org for p in pages for r in p.records} <= {A}


def test_without_a_fleet_map_a_scoped_read_reads_no_fleet(store, opened):
    page = event_page(store, SINCE, frozenset({B, C}), budget=BUDGET)
    assert {r.org for r in page.records} == {B, C}
    assert not any("org=fleet-" in k for k in opened)


def test_an_unscoped_reader_reads_every_fleet(store):
    s = read_summary(store, SINCE, None)
    assert s.orgs[WEST] and s.orgs[EAST]


# -- summary and connector ----------------------------------------------------


def test_the_summary_reads_only_the_fleets_it_may_show(store, opened):
    read_summary(store, SINCE, frozenset({D, E}), fleets=FLEETS)
    assert any("org=fleet-east" in k for k in opened)
    assert not any("org=fleet-west" in k for k in opened)


def test_the_connector_reads_only_the_fleets_it_may_show(store, opened):
    scoped = ScopedStore(store, frozenset({A}), FLEETS)
    list(scoped.read_verdicts(SINCE, scoped.orgs))
    for _, records in scoped.read_verdict_days(SINCE, scoped.orgs):
        list(records)
    page = event_page(scoped, SINCE, scoped.orgs, budget=BUDGET)
    assert _ids(page) == sorted(f"{A}-deny-{i}" for i in range(5))
    assert not any("org=fleet-" in k for k in opened), opened


def test_the_connector_counts_rows_its_scope_dropped_as_hidden(tmp_path):
    s = LocalFileStore(tmp_path / "s", instance="t")
    joined = _sid(77)
    s.write_verdicts([_otel(B, joined)])
    _write(s, _fleet(WEST, {B, C}, FLEET_N, "pending"))
    s.write_verdicts(_fleet(WEST, {B, C}, 1, "joined", session=lambda i: joined))
    scoped = ScopedStore(s, frozenset({B}), FLEETS)
    page = event_page(scoped, SINCE, scoped.orgs, budget=BUDGET, hidden_budget=BUDGET)
    assert page.before is not None      # stopped by the hidden budget
    assert _cursor_partition(page.before) in (WEST, None)


# -- which fleets are read ----------------------------------------------------


def test_readable_fleets():
    def joined(orgs):
        return lambda: orgs

    assert readable_fleets({A}, FLEETS, joined({A, B})) == set()
    assert readable_fleets({B}, FLEETS, joined(set())) == set()
    assert readable_fleets({B}, FLEETS, joined({C})) == set()
    assert readable_fleets({B}, FLEETS, joined({B})) == {WEST}
    assert readable_fleets({B, C}, FLEETS, joined(set())) == {WEST}
    assert readable_fleets({B, C, D}, FLEETS, joined({E})) == {WEST}


def test_the_join_is_not_read_for_a_reader_outside_every_fleet(store, monkeypatch):
    calls = []
    a = AttributedStore(store, FLEETS)
    monkeypatch.setattr(a, "joins", lambda since: calls.append(since) or {})
    assert a.partitions(SINCE, {A}) == {A}
    assert a.partitions(SINCE, {B, C}) == {B, C, WEST}
    assert calls == []


def test_the_fleet_map_is_read_at_each_read(store):
    current = {}
    a = AttributedStore(store, lambda: current)
    assert a.partitions(SINCE, {B, C}) == {B, C}
    current[WEST] = frozenset({B, C})
    assert a.partitions(SINCE, {B, C}) == {B, C, WEST}


def test_a_forged_cursor_into_another_fleet_reads_nothing_of_it(store, opened):
    from forgd_verdict.store.views import EventCursor

    east = next(k for k in store._tree("verdicts/") if "org=fleet-east" in k)
    key = east[len("verdicts/"):]
    for cursor in (EventCursor.position(DAY, key, 0, None),
                   EventCursor.time(DAY, (f"{DAY}T23:59:59.000000Z", key, 0))):
        page = event_page(store, SINCE, frozenset({A}), before=cursor, fleets=FLEETS)
        assert {r.org for r in page.records} <= {A}
    assert not any("org=fleet-" in k for k in opened)
