"""Clean Code hook allows, counted instead of stored one record each.

A managed fleet's hook asks for a verdict on every prompt and tool call,
and nearly all of them are clean allows: 900 laptops wrote about 145,000
records a day, and a week of them was more than the dashboard could read.
The intake keeps every deny, finding and partial scan as a record, and
counts a clean allow into a tally row instead: one record per day, org
partition, client, device, session and surface, with `tally` the number of
allows it stands for. Readers weight a tally row by `tally`, so coverage
and request counts are unchanged.

A tally row is written each time the intake flushes, holding the allows
since the previous flush, so readers sum rows across flushes, replicas and
restarts.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable

from ..models import ACTION_ALLOW, ulid
from .base import SOURCE_CODE_HOOK, VerdictRecord

# Distinct tally rows held between flushes. Reaching it asks for an early
# flush; past TALLY_HARD_KEYS an allow is counted in `dropped` instead.
TALLY_MAX_KEYS = 50_000
TALLY_HARD_KEYS = 2 * TALLY_MAX_KEYS
# The request id prefix of a tally row.
TALLY_PREFIX = "tally:"

Key = tuple[str, str | None, tuple[str, ...], str | None, str | None, str | None,
            str | None]


def is_clean_allow(record: VerdictRecord) -> bool:
    """A Code hook allow with no finding, no dropped tier and no shadow deny:
    the only verdict a tally row stands for."""
    return (record.source == SOURCE_CODE_HOOK and record.action == ACTION_ALLOW
            and record.shadow_action in (None, ACTION_ALLOW)
            and not record.findings and not record.findings_count
            and not record.tiers_dropped and not record.budget_exceeded
            and record.tally is None)


def weight(record: VerdictRecord) -> int:
    """How many verdicts `record` stands for: its `tally` on a Code hook
    allow tally row, else 1."""
    n = record.tally
    if (n is None or isinstance(n, bool) or not isinstance(n, int) or n < 1
            or record.source != SOURCE_CODE_HOOK or record.action != ACTION_ALLOW
            or record.findings):
        return 1
    return n


def _key(record: VerdictRecord) -> Key:
    return (record.day, record.tenant_hash, tuple(record.fleet_orgs or ()),
            record.client, record.device, record.session_id, record.surface)


class Tally:
    """Clean allows counted by tally key, thread-safe."""

    def __init__(self, max_keys: int = TALLY_MAX_KEYS, hard_keys: int = TALLY_HARD_KEYS):
        self.max_keys = max_keys
        self.hard_keys = hard_keys
        self.dropped = 0
        self._lock = threading.Lock()
        self._counts: dict[Key, list] = {}

    def add(self, record: VerdictRecord, n: int = 1) -> bool:
        """Count `n` allows like `record`. True when the tally holds
        `max_keys` rows or more and should be flushed now."""
        key = _key(record)
        with self._lock:
            entry = self._counts.get(key)
            if entry is None:
                if len(self._counts) >= self.hard_keys:
                    self.dropped += n
                    return True
                self._counts[key] = [n, record.observed_at]
            else:
                entry[0] += n
                if record.observed_at > entry[1]:
                    entry[1] = record.observed_at
            return len(self._counts) >= self.max_keys

    def merge(self, records: Iterable[VerdictRecord]) -> None:
        """Count tally rows back in, as when a flush could not be queued."""
        for r in records:
            self.add(r, weight(r))

    def drain(self) -> list[VerdictRecord]:
        """A tally row for every key counted since the last drain, and an
        empty tally."""
        with self._lock:
            counts, self._counts = self._counts, {}
        return [rows(key, n, newest) for key, (n, newest) in counts.items()]

    def pending(self) -> tuple[int, int]:
        """(rows, allows) counted and not yet drained."""
        with self._lock:
            return len(self._counts), sum(e[0] for e in self._counts.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._counts)


def rows(key: Key, n: int, newest: str) -> VerdictRecord:
    _day, org, fleet_orgs, client, device, session, surface = key
    return VerdictRecord(
        source=SOURCE_CODE_HOOK, observed_at=newest, request_id=f"{TALLY_PREFIX}{ulid()}",
        session_id=session, surface=surface, tenant_hash=org,
        fleet_orgs=list(fleet_orgs) or None, client=client, device=device,
        action=ACTION_ALLOW, tally=n)


def tallied(records: list[VerdictRecord]) -> list[VerdictRecord]:
    """`records` with their clean allows folded into tally rows, in one
    pass, for a batch written at once."""
    tally = Tally(max_keys=len(records) + 1, hard_keys=len(records) + 1)
    kept = []
    for r in records:
        if is_clean_allow(r):
            tally.add(r)
        else:
            kept.append(r)
    return kept + tally.drain()
