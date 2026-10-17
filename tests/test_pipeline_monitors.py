"""The pipeline monitors: delivery lag, join rate, per-detector silence,
daily delivery per source, and cursor health. Each test names the mutation
that makes it fail."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from forgd_verdict.store import FindingRow, VerdictRecord
from forgd_verdict.store.base import (
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    SOURCE_MANAGED_SCAN,
    SOURCE_OTEL_COLLECT,
)
from forgd_verdict.store.pipeline import (
    BAD,
    OK,
    UNKNOWN,
    WARN,
    PipelineAccumulator,
    cursor_health,
)

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rec(source=SOURCE_INFERENCE_HOOK, day=16, findings=(), **kw) -> VerdictRecord:
    return VerdictRecord(source=source, observed_at=f"2026-10-{day:02d}T10:00:00Z",
                         surface="claude-ai", findings=list(findings),
                         findings_count=len(findings), **kw)


def _result(records, denials_joined=0, denial_activities=0, window_minutes=None):
    acc = PipelineAccumulator()
    for r in records:
        acc.observe(r)
    return acc.result(denials_joined=denials_joined, denial_activities=denial_activities,
                      window_minutes=window_minutes)


# -- delivery lag ------------------------------------------------------------------

def test_lag_is_the_time_from_the_activity_to_the_stored_record():
    """Mutation: measure from session_started_at, or count a record stored
    before its activity."""
    stored = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
    records = [
        _rec(SOURCE_COMPLIANCE_SCAN, session_started_at=_ts(stored - timedelta(days=3)),
             session_updated_at=_ts(stored - timedelta(hours=2))),
        _rec(SOURCE_COMPLIANCE_SCAN, session_updated_at=_ts(stored - timedelta(hours=4))),
        _rec(SOURCE_COMPLIANCE_SCAN, session_updated_at=_ts(stored + timedelta(hours=1))),
    ]
    lag = {r.source: r for r in _result(records).lag}
    row = lag[SOURCE_COMPLIANCE_SCAN]
    assert (row.samples, row.p50_min, row.max_min, row.state) == (2, 180.0, 240.0, OK)
    assert lag[SOURCE_MANAGED_SCAN].state == UNKNOWN


def test_a_lag_beyond_the_window_marks_the_comparison_incomplete():
    """Mutation: compare the window with p50, or never mark it."""
    stored = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
    records = [_rec(SOURCE_COMPLIANCE_SCAN,
                    session_updated_at=_ts(stored - timedelta(hours=h))) for h in (1, 30)]
    lag = {r.source: r for r in _result(records, window_minutes=24 * 60).lag}
    assert lag[SOURCE_COMPLIANCE_SCAN].state == BAD
    lag = {r.source: r for r in _result(records, window_minutes=7 * 24 * 60).lag}
    assert lag[SOURCE_COMPLIANCE_SCAN].state == OK


# -- join rate ---------------------------------------------------------------------

def test_join_rates_are_ratios_and_unknown_with_nothing_to_match():
    """Mutation: report the matched count without the total, or zero for an
    empty window."""
    records = [_rec(SOURCE_OTEL_COLLECT, tenant_hash="org_a"),
               _rec(SOURCE_OTEL_COLLECT, tenant_hash="org_a"),
               _rec(SOURCE_OTEL_COLLECT)]
    denials, otel = _result(records, denials_joined=3, denial_activities=4).joins
    assert (denials.matched, denials.total, denials.state) == (3, 4, WARN)
    assert (otel.matched, otel.total, otel.state) == (2, 3, WARN)
    assert round(otel.rate, 3) == 0.667
    empty = _result([]).joins
    assert all(j.state == UNKNOWN and j.rate is None for j in empty)


# -- per-detector silence ----------------------------------------------------------

def _aws(day):
    return _rec(day=day, findings=[FindingRow("regex:aws-access-key", "block", "m", "h")])


def test_a_detector_that_stops_while_its_source_delivers_is_silent():
    """Mutation: ignore whether the source delivered on the newest day."""
    records = [_aws(d) for d in (11, 12, 13, 14)] + [_rec(day=15)]
    out = _result(records)
    assert out.silence_state == WARN
    [s] = out.silent
    assert (s.detector, s.last_fired, s.active_days) == ("regex:aws-access-key",
                                                         "2026-10-14", 4)


def test_a_detector_is_not_silent_when_its_source_delivered_nothing():
    """A reader that stopped is the control-point panel's to show."""
    records = [_aws(d) for d in (11, 12, 13, 14)] + [_rec(SOURCE_OTEL_COLLECT, day=15)]
    out = _result(records)
    assert out.silent == [] and out.silence_state == OK


def test_silence_needs_a_baseline():
    """Mutation: judge silence with no history."""
    out = _result([_aws(14), _rec(day=15)])
    assert out.silence_state == UNKNOWN and out.silent == []


# -- daily delivery ----------------------------------------------------------------

def test_a_source_that_stops_while_others_deliver_is_flagged_for_that_day():
    """Mutation: flag a day on which nothing arrived at all."""
    records = [_rec(SOURCE_COMPLIANCE_SCAN, day=13), _rec(day=13),
               _rec(day=14),
               _rec(SOURCE_COMPLIANCE_SCAN, day=16)]
    out = _result(records)
    assert out.daily[0][0] == "2026-10-16"
    assert ("2026-10-14", SOURCE_COMPLIANCE_SCAN) in out.dropped
    assert ("2026-10-16", SOURCE_INFERENCE_HOOK) in out.dropped
    assert all(day != "2026-10-15" for day, _ in out.dropped)


# -- cursor health -----------------------------------------------------------------

class _Store:
    def __init__(self, state):
        self.state = state

    def get_state(self, key):
        value = self.state.get(key)
        if isinstance(value, Exception):
            raise value
        return value


def _cursor(hours_ago):
    return json.dumps({"last_run_started_at": _ts(NOW - timedelta(hours=hours_ago))}).encode()


def test_cursor_states_against_the_limit():
    """Mutation: compare the age with the limit in hours, or report OK with
    no limit."""
    store = _Store({"ok": _cursor(2), "warn": _cursor(24 * 16), "bad": _cursor(24 * 31),
                    "nolimit": _cursor(2), "broken": OSError("denied"), "empty": b"{}"})
    rows = cursor_health(store, [
        ("compliance", "a", "ok", 30), ("compliance", "b", "warn", 30),
        ("managed", "c", "bad", 30), ("compliance", "d", "nolimit", None),
        ("compliance", "e", "broken", 30), ("compliance", "f", "empty", 30),
        ("compliance", "g", "missing", 30)], now=NOW)
    assert [r.state for r in rows] == [OK, WARN, BAD, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN]
    assert rows[0].age_hours == 2.0


# -- on the dashboard --------------------------------------------------------------

def test_the_overview_shows_the_pipeline_with_cursor_health(tmp_path):
    """Mutation: leave cursor health off the summary, or the section off
    the page."""
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.dashboard.topology import CursorReader
    from forgd_verdict.store import LocalFileStore

    store = LocalFileStore(tmp_path, instance="t")
    store.write_verdicts([_rec(day=d) for d in (13, 14, 15, 16)])
    old = datetime.now(UTC) - timedelta(days=40)
    store.put_state("compliance-org.json",
                    json.dumps({"last_run_started_at": _ts(old)}).encode())
    dash = Dashboard(store, cursor_readers=[
        CursorReader("compliance", "Primary", "compliance-org.json", 30, None)])
    html = dash._page("all")
    assert "Delivery lag" in html and "Records per source per" in html
    assert "Cursor health" in html and "Primary" in html and "broken" in html


def test_cursor_readers_come_from_the_policy():
    """Mutation: judge Managed Agents against the compliance retention."""
    from forgd_verdict.dashboard.topology import ComplianceOrg, CompliancePlan, cursor_readers

    class _Policy:
        raw = {"compliance": {"retention_days": 90},
               "managed_agents": {"window_days": 14,
                                  "workspaces": [{"key": "wsk", "label": "Agents"}]}}

        def workspace_pseudonym(self, key):
            return f"workspace_{key}"

    plan = CompliancePlan((ComplianceOrg("compliance-a.json", "org_a", True),))
    readers = cursor_readers(_Policy(), plan, {"org_a": "Primary"})
    assert [(r.reader, r.name, r.state_key, r.limit_days, r.partition) for r in readers] == [
        ("compliance", "Primary", "compliance-a.json", 90, "org_a"),
        ("managed", "Agents", "managed-wsk.json", 14, "workspace_wsk")]


@pytest.mark.parametrize("value", [0, 4000, "30", True])
def test_retention_days_must_be_a_number_of_days(value):
    from forgd_verdict.policy import refuse_unknown_compliance_keys

    with pytest.raises(ValueError, match="retention_days"):
        refuse_unknown_compliance_keys({"retention_days": value})
    refuse_unknown_compliance_keys({"retention_days": 30})
