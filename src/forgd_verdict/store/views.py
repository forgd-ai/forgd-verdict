"""What a reader of the store is shown: the summary payload and the event log.

Every read-only surface over the store calls these, so each number has one
implementation. The caller decides the window and which orgs the reader may
see; nothing here authenticates or authorizes.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from .attribution import Fleets, attributed
from .base import (
    SOURCE_AGENT_SCAN,
    SOURCE_CODE_HOOK,
    SOURCES,
    VerdictDay,
    VerdictRecord,
    visible,
)
from .query import Summary, build_summary

WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
# The values `event_page` filters on, each with "all" for no filter.
EVENT_SOURCES = frozenset({"all", *SOURCES})
EVENT_ACTIONS = frozenset({"all", "deny"})


def window_to_since(window: str) -> str | None:
    """The start of a named window, or None for "all" and anything unknown."""
    delta = WINDOWS.get(window)
    if delta is None:
        return None  # "all"
    return (datetime.now(UTC) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def excluded_requests(store: Any) -> set[str]:
    """Request ids kept out of the statistics, read from the store now."""
    getter = getattr(store, "get_excluded", None)
    return getter() if callable(getter) else set()


def read_summary(store: Any, since: str | None,
                 orgs: Collection[str] | None, *, fleets: Fleets = None) -> Summary:
    """`build_summary` over the store's verdicts and denials since `since`,
    each multi-org fleet record attributed to its org where it joins.
    `fleets` names the fleet partitions and their orgs (`AttributedStore`)."""
    verdicts = attributed(store, fleets)
    return build_summary(
        verdicts.read_verdicts(since, orgs),
        store.read_denials(since, orgs), since,
        excluded=excluded_requests(store), orgs=orgs,
    )


def _rate(rate: float | None) -> float | None:
    return None if rate is None else round(rate, 4)


def summary_payload(s: Summary, window: str) -> dict[str, Any]:
    """The summary as `/api/summary` returns it."""
    return {
        "generated_at": s.generated_at,
        "window": window,
        "total_requests": s.total_requests,
        "live_requests": s.live_requests,
        "scanned_sessions": s.scanned_sessions,
        "hook_decisions": s.hook_decisions,
        # Inline controls only: a post-hoc scan cannot deny anything, so
        # counting its findings as withheld verdicts would report a block
        # that was never possible.
        "would_deny": s.would_deny,
        "enforced_deny": s.enforced_deny,
        # The inference hook's evaluations only, and null with none.
        # Records shipped with an intake token are counted under
        # `intake_token`.
        "deny_rate": _rate(s.deny_rate),
        "intake_token": {
            "decisions": s.token_decisions,
            "would_deny": s.token_would_deny,
            "deny_rate": _rate(s.token_deny_rate),
        },
        # Post-hoc: an observation, not a verdict.
        "detections": s.detections,
        "detection_rate": round(s.detection_rate, 4),
        "distinct_values": s.distinct_values,
        "device_salted_values": s.device_salted_values,
        "total_findings": s.total_findings,
        "latency_ms": s.latency,
        "cache_hit_rate": round(s.cache_hit_rate, 4),
        "budget_exceeded": s.budget_exceeded,
        # Post-hoc items whose content was not read in whole.
        "deleted_unread": s.deleted_unread,
        "history_partial": s.history_partial,
        "surfaces": [
            {"surface": r.surface, "requests": r.requests,
             "writer": r.writer,
             "would_deny": r.would_deny,
             # null, not 0: adapter 3 records have no round trip.
             "p50_ms": round(r.p50, 1) if r.p50 is not None else None,
             "p95_ms": round(r.p95, 1) if r.p95 is not None else None}
            for r in s.surfaces
        ],
        "detectors": [
            {"detector": d.detector, "severity": d.severity,
             "distinct_values": d.unique, "device_salted_values": d.device_salted,
             "occurrences": d.count,
             "surfaces": sorted(d.surfaces)}
            for d in s.detectors
        ],
        "reconciliation": {
            "live_requests": s.reconciliation.live_requests,
            "live_would_deny": s.reconciliation.live_would_deny,
            "scanned_sessions": s.reconciliation.scanned_sessions,
            "scan_detections": s.reconciliation.scan_detections,
            "code_hook_decisions": s.reconciliation.code_hook_decisions,
            "code_hook_denied": s.reconciliation.code_hook_denied,
            "values_missed_live": s.reconciliation.missed_count,
            "denial_activities": s.reconciliation.denial_activities,
            "joined_by_request_id": s.reconciliation.joined_by_request_id,
            "joined_by_reference": s.reconciliation.joined_by_reference,
            "denials_unmatched": s.reconciliation.denials_unmatched,
            "denials_without_reference": s.reconciliation.denials_without_reference,
            "denials_tool_call": s.reconciliation.denials_tool_call,
        },
    }


# Rows on one Event Log page, and the records a page reads before it stops
# at the next day boundary with fewer rows than that.
EVENT_PAGE = 200
EVENT_SCAN_BUDGET = 20_000
# Bytes of objects a filtered page reads before it stops at the next day
# boundary, or within a day after the object it is reading.
EVENT_BYTE_BUDGET = 256 * 1024 * 1024
# Records a page reads that the reader may not see, before it stops as it
# does at `budget`. They do not count towards `budget`.
EVENT_HIDDEN_BUDGET = 10 * EVENT_SCAN_BUDGET


_CURSOR_MAX = 2048
_CURSOR_TEXT = re.compile(rf"[A-Za-z0-9_-]{{1,{_CURSOR_MAX}}}")
_CURSOR_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_CURSOR_LINE_MAX = 10**9


def _cursor_text(value: object, limit: int) -> bool:
    return (isinstance(value, str) and len(value) <= limit
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _cursor_line(value: object) -> bool:
    return type(value) is int and 0 <= value < _CURSOR_LINE_MAX


def _cursor_day(value: object) -> bool:
    """None, or a `date=` value a write can make: the first ten characters
    of an observed_at, which need not be a date."""
    return value is None or (_cursor_text(value, 10) and value != "" and "/" not in value)


def _is_date(day: str) -> bool:
    if not _CURSOR_DAY.fullmatch(day):
        return False
    try:
        date.fromisoformat(day)
    except ValueError:
        return False
    return True


# A row's place in the newest-first order: (time key, key, line), compared
# as a tuple. The time key is `event_time_key(observed_at)`; `key` is the
# row's object within its day and `line` its index there, so rows that share
# a time still have one order. The order is carried in the Event Log's URL,
# so it holds nothing a record's writer chose.
EventOrder = tuple[str, str, int]


def event_time_key(observed_at: str | None) -> str:
    """`observed_at` in UTC as YYYY-MM-DDTHH:MM:SS.ffffffZ, so that string
    order is time order, or "" when it does not parse, which sorts oldest.
    A time with no offset is taken as UTC."""
    if not observed_at:
        return ""
    try:
        t = datetime.fromisoformat(observed_at)
        if t.tzinfo is not None:
            t = t.astimezone(UTC)
    except (ValueError, OverflowError):
        return ""
    return t.replace(tzinfo=None).isoformat(timespec="microseconds") + "Z"


def _event_order(r: VerdictRecord, key: str, line: int) -> EventOrder:
    return (event_time_key(r.observed_at), key, line)


@dataclass(frozen=True)
class EventCursor:
    """Where the next Event Log page starts, within one partition day.

    `day` is the partition's `date=` value, or None for the objects with no
    date segment, which are walked first as a day of their own. `kind` is
    one of:

    - "time": rows of `day` strictly after `order` in the newest-first order;
    - "position": `day` is read in key order, resuming at the first key >=
      `key` and after line `line` of `key` itself, keeping only rows after
      `bound` when it is set;
    - "done": `day` is finished and the next page starts at the day after.
    """

    kind: str
    day: str | None
    order: EventOrder = ("", "", 0)
    key: str = ""
    line: int = 0
    bound: EventOrder | None = None

    @classmethod
    def time(cls, day: str | None, order: EventOrder) -> EventCursor:
        return cls("time", day, order)

    @classmethod
    def position(cls, day: str | None, key: str, line: int,
                 bound: EventOrder | None) -> EventCursor:
        return cls("position", day, key=key, line=line, bound=bound)

    @classmethod
    def done(cls, day: str | None) -> EventCursor:
        return cls("done", day)

    def encode(self) -> str:
        """The URL form: base64url JSON with no padding."""
        if self.kind == "time":
            body: list[Any] = ["t", self.day, *self.order]
        elif self.kind == "position":
            body = ["p", self.day, self.key, self.line, *(self.bound or ())]
        else:
            body = ["d", self.day]
        raw = json.dumps(body, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @classmethod
    def decode(cls, text: str) -> EventCursor | None:
        """The cursor `encode` wrote, or None for anything else."""
        if not isinstance(text, str) or not _CURSOR_TEXT.fullmatch(text):
            return None
        try:
            body = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None
        if not isinstance(body, list) or len(body) < 2 or not _cursor_day(body[1]):
            return None
        kind, day, rest = body[0], body[1], body[2:]
        if kind == "t" and _cursor_order(rest):
            return cls.time(day, tuple(rest))
        if (kind == "p" and len(rest) in (2, 5) and _cursor_text(rest[0], 1024)
                and _cursor_line(rest[1]) and (len(rest) == 2 or _cursor_order(rest[2:]))):
            return cls.position(day, rest[0], rest[1], tuple(rest[2:]) or None)
        if kind == "d" and not rest:
            return cls.done(day)
        return None

    @property
    def label(self) -> str:
        """Where the page that ends here reads back to, for a reader."""
        if self.kind == "time" and self.order[0]:
            return self.order[0][:19].replace("T", " ") + " UTC"
        if self.day is None:
            return "the undated records"
        if not _is_date(self.day):
            return f"the date={self.day} partition"
        if self.kind == "done":
            return f"{self.day} 00:00:00 UTC"
        return f"part of {self.day}" if self.kind == "position" else self.day


def _cursor_order(value: list[Any]) -> bool:
    return (len(value) == 3 and _cursor_text(value[0], 64)
            and _cursor_text(value[1], 1024) and _cursor_line(value[2]))


@dataclass(frozen=True)
class EventPage:
    """At most `limit` rows, newest first. `before` is where the next page
    starts, or None when the window holds nothing older. `approximate` names
    the day some of these rows came from in key order rather than time
    order, or is None."""

    records: list[VerdictRecord]
    before: EventCursor | None
    approximate: str | None = None


class _OneObject:
    """A day from a store whose days are not VerdictDay: one object, key ""."""

    def __init__(self, records: Any):
        self._records = records

    def keys_from(self, start: str) -> list[str]:
        return [""] if start <= "" else []

    def read(self, key: str) -> list[VerdictRecord]:
        return list(self._records)


def event_page(store: Any, since: str | None, orgs: Collection[str] | None,
               source: str = "all", action: str = "all", *, client: str = "",
               device: str = "", detector: str = "", hide_code_hook_allows: bool = False,
               match: Callable[[VerdictRecord], bool] | None = None,
               before: EventCursor | None = None, limit: int = EVENT_PAGE,
               budget: int = EVENT_SCAN_BUDGET,
               byte_budget: int = EVENT_BYTE_BUDGET,
               hidden_budget: int = EVENT_HIDDEN_BUDGET,
               fleets: Fleets = None) -> EventPage:
    """Verdicts since `since`, filtered by control point, verdict, intake
    client, device, detector and `match`, newest first, reading the store a
    day at a time from the newest and resuming at `before`. An empty
    `client`, `device` or `detector` is no filter. `hide_code_hook_allows`
    drops the Code hook's allow rows.

    Days are walked undated first, then newest to oldest, and the page holds
    at most `limit` rows. A day read whole is ordered by EventOrder, and the
    page stops at the next day boundary once `limit` rows match or `budget`
    records have been read. When `budget` runs out inside a day, the page
    stops after the object it is reading and that day is taken in key order,
    as is the rest of it on the pages that follow; those pages also stop
    after the object that reaches `limit`. An observed_at that is empty or
    does not parse sorts last.

    With a client, device or detector filter, a line that does not hold the
    value is not parsed, so `budget` counts only lines that might match, and
    the page also stops once `byte_budget` bytes of objects have been read.
    A client or device filter reads only the intake's sources.

    A record the reader may not see (`visible`) counts towards
    `hidden_budget` and not `budget`; the page stops as it does at `budget`
    once either runs out. So does a record a scoped day dropped before the
    page saw it (its `dropped` count). Only the fleet partitions
    `AttributedStore` reads for `fleets` are read.
    """
    keep = _event_filter(orgs, source, action, client, device, detector,
                         hide_code_hook_allows)
    store = attributed(store, fleets)
    needles = _needles(client, device, detector)
    walk: list[tuple[VerdictRecord, EventCursor, EventOrder]] = []
    scanned, fetched, hidden, resume = 0, 0, 0, None

    def spent() -> bool:
        return scanned >= budget or fetched >= byte_budget or hidden >= hidden_budget

    until = before.day if before is not None else None
    for day, records in store.read_verdict_days(since, orgs, until,
                                                _event_sources(source, client, device)):
        if before is not None and before.day is not None and day is None:
            continue
        if resume is not None and (len(walk) >= limit or spent()):
            break
        bound, start, skip = None, "", None
        positional = False
        if before is not None and day == before.day:
            if before.kind == "done":
                continue
            if before.kind == "time":
                bound = before.order
            else:
                bound, start, skip = before.bound, before.key, (before.key, before.line)
                positional = True
        objects = records if isinstance(records, VerdictDay) else _OneObject(records)
        pending = objects.keys_from(start)
        rows, stopped_at = [], None
        for i, key in enumerate(pending):
            dropped = getattr(objects, "dropped", 0)
            if needles and hasattr(objects, "read_matching"):
                lines, count, size = objects.read_matching(key, needles)
            else:
                records_ = objects.read(key)
                lines, count, size = list(enumerate(records_)), len(records_), 0
            if skip is None or key != skip[0]:
                # The object a page resumes in was counted by the page that
                # stopped in it; counting it again would stop this page in
                # the same place.
                fetched += size
                hidden += getattr(objects, "dropped", 0) - dropped
            for line, r in lines:
                if skip is not None and key == skip[0] and line <= skip[1]:
                    continue
                if not visible(r, orgs):
                    hidden += 1
                    continue
                scanned += 1
                order = _event_order(r, key, line)
                if (bound is None or order < bound) and keep(r) and (
                        match is None or match(r)):
                    rows.append((order, key, line, r))
            if i + 1 < len(pending) and (spent() or (
                    positional and len(walk) + len(rows) >= limit)):
                stopped_at = (key, max(count - 1, 0))
                break
        if positional or stopped_at is not None:
            walk += [(r, EventCursor.position(day, key, line, bound), order)
                     for order, key, line, r in rows]
            if stopped_at is not None:
                resume = EventCursor.position(day, *stopped_at, bound)
                break
        else:
            rows.sort(key=lambda row: row[0], reverse=True)
            walk += [(r, EventCursor.time(day, order), order) for order, _, _, r in rows]
        resume = EventCursor.done(day)
    else:
        resume = None
    if len(walk) > limit:
        resume = walk[limit - 1][1]
        walk = walk[:limit]
    approximate = next((c.day or "the undated records" for _, c, _ in walk
                        if c.kind == "position"), None)
    shown = [r for r, _, _ in sorted(walk, key=lambda w: w[2], reverse=True)]
    return EventPage(shown, resume, approximate)


# A filter value with only these characters appears verbatim in a stored
# line's JSON, so a line without it cannot match.
_LITERAL = re.compile(r"[A-Za-z0-9_.:\-]+")


def _needles(client: str, device: str, detector: str) -> list[bytes]:
    """The filter values a matching line must hold, as bytes. A value JSON
    would escape is left out, and the line is parsed and tested in full."""
    return [v.encode() for v in (client, device, detector) if v and _LITERAL.fullmatch(v)]


def _event_sources(source: str, client: str, device: str) -> tuple[str, ...] | None:
    """The sources a filtered page can find rows in: the one asked for, or
    the intake's two when a client or device is asked for; None for all."""
    if source != "all":
        return (source,)
    if client or device:
        return (SOURCE_CODE_HOOK, SOURCE_AGENT_SCAN)
    return None


def _event_filter(orgs: Collection[str] | None, source: str, action: str,
                  client: str, device: str, detector: str = "",
                  hide_code_hook_allows: bool = False) -> Callable[[VerdictRecord], bool]:
    def keep(r: VerdictRecord) -> bool:
        # The partition prune is an optimisation; the org test is the
        # authorization, and it runs first. `disposition`, not
        # `effective_action`: an inline control denies and a post-hoc scan
        # detects or flags.
        return (visible(r, orgs)
                and (source == "all" or r.source == source)
                and (not client or r.client == client)
                and (not device or r.device == device)
                and (not detector or any(f.detector == detector for f in r.findings))
                and not (hide_code_hook_allows and r.source == SOURCE_CODE_HOOK
                         and r.disposition == "allow")
                and (action != "deny" or r.disposition in ("deny", "detected", "flagged")))
    return keep

