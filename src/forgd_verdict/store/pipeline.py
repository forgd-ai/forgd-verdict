"""Monitors of the pipeline itself, kept apart from detection counts.

Any reader can stop delivering without reporting a failure, and the
dashboard then shows fewer findings, which reads the same as there being
less to find. These are the checks on delivery: how late records arrive,
how many records of one source are matched by another, how close each
pulling reader's cursor is to losing data, which detectors went quiet while
their source kept delivering, and how many records each source delivered
each day. Counts, timestamps and ids only: none of them reads content.

`PipelineAccumulator` is fed every record `build_summary` reads, in the
same pass, and `cursor_health` reads the pulling readers' cursors from the
store.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .base import (
    ORG_UNATTRIBUTED,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_MANAGED_SCAN,
    SOURCE_OTEL_COLLECT,
    VerdictRecord,
)

# Monitor states. UNKNOWN, never zero, when there is nothing to judge.
OK = "ok"
WARN = "warn"
BAD = "bad"
UNKNOWN = "unknown"

# Sources whose records carry the time the activity happened
# (`session_updated_at`) beside the time they were stored (`observed_at`).
LAG_SOURCES = (SOURCE_COMPLIANCE_SCAN, SOURCE_MANAGED_SCAN)

# A detector is judged silent only with this many days of history in the
# window before the newest one, on at least SILENT_MIN_ACTIVE_DAYS of which
# it fired.
SILENT_MIN_BASELINE_DAYS = 3
SILENT_MIN_ACTIVE_DAYS = 3

# A cursor is at risk once its age passes this share of the period after
# which data is lost.
CURSOR_WARN_SHARE = 0.5


def _parse(ts: Any) -> datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


@dataclass
class LagRow:
    """How long after the activity a source's records were stored, in
    minutes, or UNKNOWN with no record to measure."""

    source: str
    samples: int = 0
    p50_min: float | None = None
    p95_min: float | None = None
    max_min: float | None = None
    state: str = UNKNOWN
    detail: str = ""


@dataclass
class JoinRow:
    """The share of one source's records matched to another's."""

    name: str
    matched: int = 0
    total: int = 0
    state: str = UNKNOWN
    detail: str = ""

    @property
    def rate(self) -> float | None:
        return self.matched / self.total if self.total else None


@dataclass
class SilentDetector:
    detector: str
    last_fired: str
    active_days: int
    baseline_days: int


@dataclass
class CursorRow:
    """A pulling reader's last completed pass against the period after which
    what it has not read is gone."""

    reader: str
    name: str
    last_run: str | None
    age_hours: float | None
    limit_days: int | None
    state: str
    detail: str


@dataclass
class Pipeline:
    lag: list[LagRow] = field(default_factory=list)
    joins: list[JoinRow] = field(default_factory=list)
    silent: list[SilentDetector] = field(default_factory=list)
    silence_state: str = UNKNOWN
    silence_detail: str = ""
    # day -> source -> records, newest day first.
    daily: list[tuple[str, dict[str, int]]] = field(default_factory=list)
    # (day, source) for a source that delivered the day before and nothing on
    # a day the others delivered.
    dropped: list[tuple[str, str]] = field(default_factory=list)
    cursors: list[CursorRow] = field(default_factory=list)


class PipelineAccumulator:
    """Fed every counted record and denial `build_summary` reads."""

    def __init__(self) -> None:
        self._lag: dict[str, list[float]] = defaultdict(list)
        self._otel_total = 0
        self._otel_attributed = 0
        self._detector_days: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._detector_sources: dict[str, set[str]] = defaultdict(set)
        self._source_days: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def observe(self, v: VerdictRecord, weight: int = 1) -> None:
        day = v.day
        self._source_days[day][v.source] += weight
        if v.source in LAG_SOURCES:
            happened, stored = _parse(v.session_updated_at), _parse(v.observed_at)
            if happened is not None and stored is not None and stored >= happened:
                self._lag[v.source].append((stored - happened).total_seconds() / 60)
        if v.source == SOURCE_OTEL_COLLECT:
            self._otel_total += 1
            if v.org != ORG_UNATTRIBUTED:
                self._otel_attributed += 1
        for f in v.findings:
            self._detector_days[f.detector][day] += 1
            self._detector_sources[f.detector].add(v.source)

    def result(self, *, denials_joined: int, denial_activities: int,
               window_minutes: float | None) -> Pipeline:
        out = Pipeline()
        out.lag = [self._lag_row(s, window_minutes) for s in LAG_SOURCES]
        out.joins = [
            _join("Activity Feed denials matched to an inference-hook verdict",
                  denials_joined, denial_activities),
            _join("OTel records attributed to a configured org",
                  self._otel_attributed, self._otel_total),
        ]
        out.silent, out.silence_state, out.silence_detail = self._silence()
        days = sorted(self._source_days, reverse=True)
        out.daily = [(d, dict(self._source_days[d])) for d in days]
        # A day is listed only when something arrived on it, so every day
        # compared here had a source delivering.
        for newer, older in zip(days, days[1:], strict=False):
            today, before = self._source_days[newer], self._source_days[older]
            out.dropped.extend((newer, s) for s in sorted(before)
                               if before[s] and not today.get(s))
        return out

    def _lag_row(self, source: str, window_minutes: float | None) -> LagRow:
        values = self._lag.get(source) or []
        if not values:
            return LagRow(source, detail="no record carries the time of its activity")
        row = LagRow(source, samples=len(values),
                     p50_min=round(_percentile(values, 50), 1),
                     p95_min=round(_percentile(values, 95), 1),
                     max_min=round(max(values), 1))
        if window_minutes is not None and row.p95_min >= window_minutes:
            row.state = BAD
            row.detail = ("p95 lag is longer than the window, so comparisons with the "
                          "live path in this window are incomplete")
        else:
            row.state = OK
        return row

    def _silence(self) -> tuple[list[SilentDetector], str, str]:
        days = sorted(self._source_days)
        if len(days) <= SILENT_MIN_BASELINE_DAYS:
            return [], UNKNOWN, (f"needs more than {SILENT_MIN_BASELINE_DAYS} days of "
                                 "records in the window")
        newest, baseline = days[-1], days[:-1]
        silent = []
        for detector, per_day in sorted(self._detector_days.items()):
            active = sum(1 for d in baseline if per_day.get(d))
            if active < SILENT_MIN_ACTIVE_DAYS or per_day.get(newest):
                continue
            # Silent only if a source it fired on delivered that day.
            if not any(self._source_days[newest].get(s)
                       for s in self._detector_sources[detector]):
                continue
            last = max(d for d, n in per_day.items() if n)
            silent.append(SilentDetector(detector, last, active, len(baseline)))
        return silent, (WARN if silent else OK), ""


def _join(name: str, matched: int, total: int) -> JoinRow:
    row = JoinRow(name, matched, total)
    if not total:
        row.detail = "nothing to match in this window"
    else:
        row.state = OK if matched == total else WARN
    return row


def cursor_health(store: Any, readers: Iterable[tuple[str, str, str, int | None]],
                  now: datetime | None = None) -> list[CursorRow]:
    """Each pulling reader's cursor against its limit.

    `readers` is (reader, name, state key, limit in days or None). The limit
    is the period after which what the reader has not read is gone: the
    Compliance API's retention as `compliance.retention_days` says, or a
    Managed Agents workspace's `window_days`. With no limit the age is shown
    and the state is UNKNOWN.
    """
    moment = now or datetime.now(UTC)
    rows = []
    for reader, name, key, limit in readers:
        last = _last_run(store, key)
        when = _parse(last)
        if when is None:
            rows.append(CursorRow(reader, name, None, None, limit, UNKNOWN,
                                  "no completed pass recorded"))
            continue
        age_h = max(0.0, (moment - when).total_seconds() / 3600)
        if limit is None:
            state, detail = UNKNOWN, "set compliance.retention_days to judge it"
        elif age_h >= limit * 24:
            state, detail = BAD, "older than the limit: activity since then may be lost"
        elif age_h >= limit * 24 * CURSOR_WARN_SHARE:
            state, detail = WARN, "past half the limit"
        else:
            state, detail = OK, ""
        rows.append(CursorRow(reader, name, last, round(age_h, 1), limit, state, detail))
    return rows


def _last_run(store: Any, key: str) -> str | None:
    if store is None:
        return None
    try:
        blob = store.get_state(key)
    except Exception:  # noqa: BLE001 - an unreadable cursor is an unknown one
        return None
    try:
        data = json.loads(blob) if blob else None
    except (ValueError, TypeError, RecursionError):
        return None
    value = data.get("last_run_started_at") if isinstance(data, Mapping) else None
    return value if isinstance(value, str) else None
