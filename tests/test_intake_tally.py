"""Clean Code hook allows are counted into tally rows, not stored one each.

Every deny, finding and partial scan is still a record. A clean allow is
added to a tally row per day, org partition, client, device, session and
surface, and every reader weights the row by its `tally`, so request and
coverage counts stay exact.
"""

from __future__ import annotations

import asyncio
import json
import threading

import pytest
from conftest import ASGIClient
from test_intake_fleet import (
    FLEET_TOKEN,
    SALT,
    _headers,
    _ndjson,
    _policy,
    org_env,  # noqa: F401
)

from forgd_verdict.intake.app import Intake
from forgd_verdict.models import pseudonym
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store import tally as tally_mod
from forgd_verdict.store.attribution import policy_fleets
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_INFERENCE_HOOK,
    SOURCE_OTEL_COLLECT,
    FindingRow,
    VerdictRecord,
)
from forgd_verdict.store.query import build_summary
from forgd_verdict.store.tally import Tally, is_clean_allow, weight
from forgd_verdict.store.views import event_page, read_summary

PROD = pseudonym("org-prod-fixture", SALT, "org")
DEV = pseudonym("org-dev-fixture", SALT, "org")
SCAN_HEADERS = {"content-type": "application/json"}


def _sid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def _app(tmp_path, policy=None, name="t") -> Intake:
    return Intake(policy or _policy(),
                  store=LocalFileStore(tmp_path / "store", instance=name))


def _prompt(session: int, text: str = "hello there") -> bytes:
    return json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": _sid(session),
                       "prompt": text}).encode()


async def _scan(app, body, device="d000000000001"):
    status, out = await ASGIClient(app).post(
        "/scan", body, {**_headers(FLEET_TOKEN, device), **SCAN_HEADERS})
    assert status == 200, out
    return out


def _all(store) -> list[VerdictRecord]:
    return list(store.read_verdicts())


async def test_clean_allows_are_one_tally_row_and_counted_exactly(tmp_path):
    app = _app(tmp_path)
    try:
        for _ in range(25):
            await _scan(app, _prompt(1))
        app.flush()
        rows = _all(app.store)
        assert len(rows) == 1
        assert rows[0].tally == 25 and rows[0].request_id.startswith("tally:")
        s = build_summary(rows)
        assert (s.total_requests, s.hook_decisions) == (25, 25)
        assert s.surfaces[0].requests == s.surfaces[0].code_hook == 25
        assert sum(n for _, n, _ in s.daily) == 25
        assert s.orgs == {PROD: 25}
    finally:
        app.close()


async def test_a_deny_stays_a_record_beside_the_tally(tmp_path):
    app = _app(tmp_path)
    try:
        await _scan(app, _prompt(1))
        out = await _scan(app, _prompt(1, "key AKIAIOSFODNN7EXAMPLE here"))
        assert out["action"] == "deny"
        app.flush()
        rows = _all(app.store)
        assert sorted((r.action, r.tally) for r in rows) == [("allow", 1), ("deny", None)]
        s = build_summary(rows)
        assert (s.hook_decisions, s.would_deny) == (2, 1)
    finally:
        app.close()


def _rec(**kw) -> VerdictRecord:
    base = {"source": SOURCE_CODE_HOOK, "action": "allow"}
    return VerdictRecord(**{**base, **kw})


@pytest.mark.parametrize("kw", [
    {"action": "deny"},
    {"findings": [FindingRow("shell:exfil", "warn", "c", "h")], "findings_count": 1},
    {"tiers_dropped": ["gitleaks"]},
    {"shadow_action": "deny"},
    {"budget_exceeded": True},
    {"source": SOURCE_INFERENCE_HOOK},
    {"tally": 3},
])
def test_only_a_clean_code_hook_allow_is_tallied(kw):
    assert not is_clean_allow(_rec(**kw))
    assert is_clean_allow(_rec())


@pytest.mark.parametrize("kw", [
    {"source": SOURCE_INFERENCE_HOOK}, {"action": "deny"}, {"tally": 0}, {"tally": -4},
    {"findings": [FindingRow("x:y", "block", "c", "h")]},
])
def test_a_reader_weights_only_a_tally_row_on_a_code_hook_allow(kw):
    assert weight(_rec(**{"tally": 9, **kw})) == 1
    assert weight(_rec(tally=9)) == 9


async def test_sessions_devices_and_orgs_are_separate_rows(tmp_path):
    app = _app(tmp_path)
    try:
        await _scan(app, _prompt(1), "d000000000001")
        await _scan(app, _prompt(2), "d000000000001")
        await _scan(app, _prompt(1), "d000000000002")
        app.flush()
        rows = _all(app.store)
        assert sorted((r.device, r.session_id, r.tally) for r in rows) == [
            ("d000000000001", _sid(1), 1), ("d000000000001", _sid(2), 1),
            ("d000000000002", _sid(1), 1)]
    finally:
        app.close()


async def test_two_replicas_and_a_restart_sum_to_every_allow(tmp_path):
    first, second = _app(tmp_path, name="a"), _app(tmp_path, name="b")
    try:
        for _ in range(7):
            await _scan(first, _prompt(1))
        for _ in range(5):
            await _scan(second, _prompt(1))
        first.flush()
        for _ in range(3):
            await _scan(first, _prompt(1))
    finally:
        first.close()
        second.close()
    restarted = _app(tmp_path, name="c")
    try:
        await _scan(restarted, _prompt(1))
        restarted.flush()
        rows = _all(restarted.store)
        assert build_summary(rows).hook_decisions == 7 + 5 + 3 + 1
        assert len(rows) == 4
    finally:
        restarted.close()


async def test_a_refused_flush_keeps_its_counts_for_the_next(tmp_path):
    app = _app(tmp_path)
    try:
        for _ in range(4):
            await _scan(app, _prompt(1))
        real = app.sink.submit_records
        app.sink.submit_records = lambda records: False
        app._flush_tally()
        app.sink.submit_records = real
        assert app.tally.pending() == (1, 4)
        app.flush()
        assert build_summary(_all(app.store)).hook_decisions == 4
        assert app.stats()["counts"]["tally_requeued"] == 1
    finally:
        app.close()


def test_many_distinct_sessions_ask_for_an_early_flush_and_lose_nothing():
    t = Tally(max_keys=10, hard_keys=20)
    asks = [t.add(_rec(observed_at="2026-10-05T10:00:00Z", session_id=_sid(i)))
            for i in range(10)]
    assert asks[-1] is True and not any(asks[:-1])
    drained = t.drain()
    assert len(drained) == 10 and len(t) == 0


def test_past_the_hard_bound_an_allow_is_counted_as_dropped_not_held():
    t = Tally(max_keys=2, hard_keys=3)
    for i in range(5):
        t.add(_rec(observed_at="2026-10-05T10:00:00Z", session_id=_sid(i)))
    assert len(t) == 3 and t.dropped == 2
    t.add(_rec(observed_at="2026-10-05T10:00:01Z", session_id=_sid(0)))
    assert t.pending() == (3, 4)


async def test_a_flood_of_session_ids_is_flushed_early_by_the_intake(tmp_path, monkeypatch):
    app = _app(tmp_path)
    app.tally.max_keys, app.tally.hard_keys = 5, 10_000
    try:
        for i in range(23):
            await _scan(app, _prompt(i))
        await asyncio.sleep(0)
        for _ in range(100):
            if len(app.tally) < 5:
                break
            await asyncio.sleep(0.02)
        assert len(app.tally) < 5
        app.flush()
        assert build_summary(_all(app.store)).hook_decisions == 23
    finally:
        app.close()


def test_concurrent_adds_are_counted_exactly():
    t = Tally()

    def work(n):
        for _ in range(2000):
            t.add(_rec(observed_at="2026-10-05T10:00:00Z", session_id=_sid(n % 3)))

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert sum(r.tally for r in t.drain()) == 16000


def test_allows_either_side_of_midnight_are_two_rows():
    t = Tally()
    t.add(_rec(observed_at="2026-10-05T23:59:59Z", session_id=_sid(1)))
    t.add(_rec(observed_at="2026-10-06T00:00:01Z", session_id=_sid(1)))
    assert sorted((r.day, r.tally) for r in t.drain()) == [
        ("2026-10-05", 1), ("2026-10-06", 1)]


async def test_a_shipped_batch_folds_its_clean_allows_and_reports_every_record(tmp_path):
    app = _app(tmp_path)
    allows = [_rec(session_id=_sid(1)) for _ in range(10)]
    deny = _rec(action="deny", session_id=_sid(1),
                findings=[FindingRow("regex:aws-access-key", "block", "c", "h")],
                findings_count=1)
    try:
        status, body = await ASGIClient(app).post(
            "/intake", _ndjson(*allows, deny), _headers(FLEET_TOKEN, "d000000000001"))
        assert status == 200
        assert body == {"accepted": 11, "rejected": 0}
        rows = _all(app.store)
        assert len(rows) == 2
        assert build_summary(rows).hook_decisions == 11
    finally:
        app.close()


async def test_a_shipped_record_cannot_claim_a_tally(tmp_path):
    app = _app(tmp_path)
    try:
        await ASGIClient(app).post(
            "/intake", _ndjson(_rec(action="deny", tally=2**40, findings=[
                FindingRow("regex:aws-access-key", "block", "c", "h")], findings_count=1),
                _rec(tally=2**40, session_id=_sid(3))),
            _headers(FLEET_TOKEN, "d000000000001"))
        rows = _all(app.store)
        assert build_summary(rows).hook_decisions == 2
    finally:
        app.close()


async def test_the_event_log_hides_tally_rows_until_allows_are_shown(tmp_path):
    from forgd_verdict.dashboard.render import render_events

    app = _app(tmp_path)
    try:
        for _ in range(6):
            await _scan(app, _prompt(1))
        app.flush()
        assert event_page(app.store, None, None, hide_code_hook_allows=True).records == []
        shown = event_page(app.store, None, None).records
        assert [r.tally for r in shown] == [6]
        assert "6 allows" in render_events(shown)
    finally:
        app.close()


async def test_a_multi_org_fleet_tally_joins_its_session_to_one_org(tmp_path):
    policy = _policy(fleet=[{"name": "corp-laptops", "tokens": ["$FORGD_INTAKE_FLEET_TOKEN"],
                             "orgs": ["$FORGD_ORG_ID_PROD", "$FORGD_ORG_ID_DEV"]}])
    app = _app(tmp_path, policy)
    try:
        for _ in range(4):
            await _scan(app, _prompt(1))
        for _ in range(3):
            await _scan(app, _prompt(2))
        app.flush()
        app.store.write_verdicts([VerdictRecord(
            source=SOURCE_OTEL_COLLECT, session_id=_sid(1), tenant_hash=DEV,
            surface="claude-code")])
        # The reader's fleet map comes from the same policy the intake filed under.
        fleets = policy_fleets(policy)
        dev = read_summary(app.store, None, frozenset({DEV}), fleets=fleets)
        prod = read_summary(app.store, None, frozenset({PROD}), fleets=fleets)
        both = read_summary(app.store, None, frozenset({PROD, DEV}), fleets=fleets)
        assert (dev.hook_decisions, prod.hook_decisions, both.hook_decisions) == (4, 0, 7)
    finally:
        app.close()


def test_tally_rows_are_written_compactly():
    row = tally_mod.rows(("2026-10-05", PROD, (), "laptops", "d000000000001", _sid(1),
                          "claude-code-local"), 5, "2026-10-05T10:00:00Z")
    assert len(row.to_json()) < 720


@pytest.mark.parametrize("value", [0, -5, 0.5, 10**6])
def test_a_tally_flush_interval_out_of_range_refuses_to_start(tmp_path, value):
    with pytest.raises(ValueError, match="tally_flush_s"):
        _app(tmp_path, _policy(tally_flush_s=value))
