"""The Event Log scoping of `test_fleet_read_scope.py` at the default
budgets, with a fleet day past EVENT_SCAN_BUDGET rows: the reviewers'
reproduction, where a viewer of an org in no fleet, and a viewer of one
org of the fleet, each got an empty first page."""

from __future__ import annotations

import pytest

from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_OTEL_COLLECT,
    FindingRow,
    VerdictRecord,
    path_segment,
)
from forgd_verdict.store.views import EVENT_SCAN_BUDGET, event_page

pytestmark = pytest.mark.serial

A, B, C = "org_aaaaaaaaaa", "org_bbbbbbbbbb", "org_cccccccccc"
FLEETS = {"fleet-west": frozenset({B, C})}
DAY = "2026-10-05"
JOINED = "33333333-3333-3333-3333-333333333333"


def _fleet_rows(n: int, session=None):
    return [VerdictRecord(
        source=SOURCE_CODE_HOOK, observed_at=f"{DAY}T{8 + i % 10:02d}:{i % 60:02d}:00Z",
        device=f"d{i % 900:012x}", client="laptops", tenant_hash="fleet-west",
        fleet_orgs=[B, C], session_id=session or f"00000000-0000-4000-8000-{i % 1800:012d}",
        request_id=f"PreToolUse:{DAY}:{i}", action="allow", tally=3) for i in range(n)]


def _own_rows(org: str, n: int, prefix: str):
    return [VerdictRecord(
        source=SOURCE_CODE_HOOK, observed_at=f"{DAY}T12:{i % 60:02d}:00Z",
        device=f"d{i:012x}", client="laptops", tenant_hash=org,
        request_id=f"{prefix}-{i}", action="deny",
        findings=[FindingRow("regex:aws-access-key", "block", "c", "h")], findings_count=1)
        for i in range(n)]


@pytest.fixture(scope="module")
def store(tmp_path_factory):
    s = LocalFileStore(tmp_path_factory.mktemp("vol") / "s", instance="t")
    fleet = _fleet_rows(EVENT_SCAN_BUDGET + 5_000)
    for i in range(0, len(fleet), 500):
        s.write_verdicts(fleet[i:i + 500])
    for org in (A, B):
        s.write_verdicts(_own_rows(org, 5, f"{org}-deny"))
    return s


def _ids(page):
    return sorted(r.request_id for r in page.records if r.source == SOURCE_CODE_HOOK)


def _names_fleet(page):
    c = page.before
    if c is None or c.kind == "done":
        return False
    key = c.key if c.kind == "position" else c.order[1]
    return path_segment(key, "org") == "fleet-west"


def test_an_org_in_no_fleet_gets_its_rows_on_the_first_page(store):
    page = event_page(store, None, frozenset({A}), fleets=FLEETS)
    assert _ids(page) == sorted(f"{A}-deny-{i}" for i in range(5))
    assert not _names_fleet(page)


def test_one_org_of_the_fleet_gets_its_rows_past_the_pending_ones(store):
    page = event_page(store, None, frozenset({B}), fleets=FLEETS)
    assert _ids(page) == sorted(f"{B}-deny-{i}" for i in range(5))
    assert not _names_fleet(page)


def test_one_org_with_a_joined_session_still_gets_its_rows(store, tmp_path):
    store.write_verdicts([VerdictRecord(
        source=SOURCE_OTEL_COLLECT, observed_at=f"{DAY}T07:00:00Z", tenant_hash=B,
        session_id=JOINED, surface="claude-code", request_id="otel-joined")])
    rows = _fleet_rows(2, session=JOINED)
    for i, r in enumerate(rows):
        r.request_id, r.observed_at = f"joined-{i}", f"{DAY}T01:00:00Z"
    store.write_verdicts(rows)
    page = event_page(store, None, frozenset({B}), fleets=FLEETS)
    assert _ids(page) == sorted([f"{B}-deny-{i}" for i in range(5)] + ["joined-0", "joined-1"])


def test_a_viewer_of_both_fleet_orgs_gets_a_full_page(store):
    page = event_page(store, None, frozenset({B, C}), fleets=FLEETS)
    assert len(page.records) == 200
