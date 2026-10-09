"""For a viewer of a multi-org fleet's orgs, the summary, the Event Log and
the connector show the same rows, and nothing from another org or still
pending leaks to a viewer of one org."""

from __future__ import annotations

from forgd_verdict.connector.tools import ScopedStore
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import SOURCE_CODE_HOOK, SOURCE_OTEL_COLLECT, VerdictRecord
from forgd_verdict.store.tally import weight
from forgd_verdict.store.views import event_page, read_summary

B, C, T = "org_bbbbbbbbbb", "org_cccccccccc", "org_tttttttttt"
S_B = "11111111-1111-1111-1111-111111111111"
S_C = "22222222-2222-2222-2222-222222222222"
S_X = "44444444-0000-0000-0000-000000000000"  # both B and C export it
S_T = "22222222-0000-0000-0000-000000000000"  # only T (outside the fleet) exports it
S_P = "11111111-0000-0000-0000-000000000000"  # nobody exports it
SINCE = "2026-10-01T00:00:00Z"
FLEETS = {"fleet-west": frozenset({B, C})}


def _otel(org, sid):
    return VerdictRecord(source=SOURCE_OTEL_COLLECT, observed_at="2026-10-05T09:00:00Z",
                         tenant_hash=org, session_id=sid, surface="claude-code",
                         request_id=f"otel-{org}-{sid[-1]}", action="allow")


def _fleet(sid, rid, tally=None, action="allow"):
    return VerdictRecord(source=SOURCE_CODE_HOOK, observed_at="2026-10-05T10:00:00Z",
                         tenant_hash="fleet-west", fleet_orgs=[B, C], client="laptops",
                         device="d000000000001", session_id=sid, request_id=rid,
                         surface="claude-code-local", action=action, tally=tally)


def _store(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([_otel(B, S_B), _otel(C, S_C), _otel(B, S_X), _otel(C, S_X),
                          _otel(T, S_T)])
    store.write_verdicts([
        _fleet(S_B, "to-b", tally=7), _fleet(S_B, "to-b-deny", action="deny"),
        _fleet(S_C, "to-c", tally=11), _fleet(S_X, "conflict", tally=3),
        _fleet(S_T, "outside", tally=5), _fleet(S_P, "pending", tally=2),
    ])
    return store


def _pages(store, orgs):
    out, before = [], None
    while True:
        page = event_page(store, SINCE, orgs, before=before, limit=2, fleets=FLEETS)
        out += page.records
        if page.before is None:
            return out
        before = page.before


def test_viewer_of_b_sees_the_same_rows_everywhere_and_nothing_else(tmp_path):
    store = _store(tmp_path)
    summary = read_summary(store, SINCE, frozenset({B}), fleets=FLEETS)
    log = _pages(store, frozenset({B}))
    connector = list(ScopedStore(store, frozenset({B}), FLEETS).read_verdicts(SINCE))
    hook_rows = [r for r in log if r.source == SOURCE_CODE_HOOK]
    assert sorted(r.request_id for r in hook_rows) == ["to-b", "to-b-deny"]
    assert sorted(r.request_id for r in connector if r.source == SOURCE_CODE_HOOK) == \
        ["to-b", "to-b-deny"]
    assert all(r.org == B for r in log + connector)
    assert summary.hook_decisions == sum(weight(r) for r in hook_rows) == 8
    assert set(summary.orgs) == {B}


def test_viewer_of_both_fleet_orgs_sees_pending_and_conflict_rows_as_pending(tmp_path):
    store = _store(tmp_path)
    log = _pages(store, frozenset({B, C}))
    by_id = {r.request_id: r.org for r in log if r.source == SOURCE_CODE_HOOK}
    assert by_id == {"to-b": B, "to-b-deny": B, "to-c": C, "conflict": "fleet-west",
                     "outside": "fleet-west", "pending": "fleet-west"}
    summary = read_summary(store, SINCE, frozenset({B, C}), fleets=FLEETS)
    assert summary.hook_decisions == 7 + 1 + 11 + 3 + 5 + 2


def test_viewer_of_t_sees_no_fleet_row_though_t_exported_its_session(tmp_path):
    store = _store(tmp_path)
    log = _pages(store, frozenset({T}))
    assert [r.request_id for r in log] == [f"otel-{T}-{S_T[-1]}"]
    assert read_summary(store, SINCE, frozenset({T}), fleets=FLEETS).hook_decisions == 0
