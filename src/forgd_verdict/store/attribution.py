"""Attributing a multi-org fleet's records to one org, at read time.

A fleet bound to several orgs files each record under `fleet-<name>` with
the fleet's org pseudonyms in `fleet_orgs`, because nothing a laptop says
about its org is trusted. A record is attributed to org O when its
Claude Code session id is the `session.id` of a Claude Code OTel export the
collector filed under O, O is one of the record's `fleet_orgs`, and no
other org's export carries that session id. Otherwise it stays in the
fleet's partition, shown as org pending.

The join is computed from every org's OTel records, not only the reader's,
so the same record lands in the same org whoever is reading. A reader of
one org that saw only its own exports would attribute a session another
org also claims to itself.
"""

from __future__ import annotations

import inspect
import logging
import re
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from ..orgregistry import partition_kind
from .base import (
    SOURCE_OTEL_COLLECT,
    VerdictDay,
    VerdictRecord,
    fleet_partition,
    is_fleet_partition,
)

_log = logging.getLogger("forgd_verdict.attribution")

# OTel records this long before the window's start still attribute
# records inside it: a session's export can land before the window opens
# and its hook records after.
JOIN_SLACK = timedelta(days=1)
# Distinct session ids the join holds. Past this, further sessions are not
# joined and their records stay pending.
MAX_JOINED_SESSIONS = 1_000_000
# The normalised surface of a Claude Code OTel export.
CLAUDE_CODE = "claude-code"

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
# A session id two orgs' exports both carry.
_CONFLICT = ""


def join_since(since: str | None) -> str | None:
    """`since` moved back by JOIN_SLACK, or None for no lower bound."""
    if not since:
        return None
    try:
        start = datetime.fromisoformat(since.replace("Z", "+00:00"))
    except ValueError:
        return None
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    return (start - JOIN_SLACK).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_sources(store: Any, since: str | None, orgs: Collection[str] | None,
                 sources: Collection[str]) -> Iterator[VerdictRecord]:
    """Verdicts from `sources` only: pruned by the backend when its
    `read_verdicts` takes `sources`, else filtered after reading."""
    reader = store.read_verdicts
    records = (reader(since, orgs, sources=sources) if _takes_sources(reader)
               else reader(since, orgs))
    for r in records:
        if r.source in sources:
            yield r


def read_days(store: Any, since: str | None, orgs: Collection[str] | None,
              until: str | None, sources: Collection[str] | None = None
              ) -> Iterator[tuple[str | None, Any]]:
    """`store.read_verdict_days`, pruned to `sources` when the backend takes
    them. A backend that does not is read whole; the caller still filters
    each row by source."""
    reader = store.read_verdict_days
    if sources is not None and _takes_sources(reader):
        return reader(since, orgs, until, sources=sources)
    return reader(since, orgs, until)


def _takes_sources(reader: Any) -> bool:
    try:
        return "sources" in inspect.signature(reader).parameters
    except (TypeError, ValueError):
        return False


def session_orgs(store: Any, since: str | None) -> dict[str, str]:
    """`{session id: org pseudonym}` from Claude Code OTel records since
    `join_since(since)`. A session id two orgs' records carry maps to ""."""
    from .query import normalize_surface

    out: dict[str, str] = {}
    for r in read_sources(store, join_since(since), None, (SOURCE_OTEL_COLLECT,)):
        session = r.session_id
        if (not session or not _UUID.match(session)
                or partition_kind(r.org) != "org"
                or normalize_surface(r.surface) != CLAUDE_CODE):
            continue
        current = out.get(session)
        if current is None:
            if len(out) < MAX_JOINED_SESSIONS:
                out[session] = r.org
        elif current != r.org:
            out[session] = _CONFLICT
    return out


def attribute(record: VerdictRecord,
              joins: dict[str, str] | Callable[[], dict[str, str]]) -> VerdictRecord:
    """`record` filed under the org its session joins to, when it is in a
    fleet's partition and the join names exactly one of its `fleet_orgs`.
    `joins` may be a function returning the join, called only for such a
    record."""
    if not is_fleet_partition(record.tenant_hash) or not record.session_id:
        return record
    org = (joins() if callable(joins) else joins).get(record.session_id)
    if org and org in (record.fleet_orgs or ()):
        return replace(record, tenant_hash=org)
    return record


# `{fleet partition: the org pseudonyms the fleet is bound to}`, or a
# function returning it, called at each read.
FleetMembers = Mapping[str, Collection[str]]
Fleets = FleetMembers | Callable[[], FleetMembers] | None


def fleet_members(fleets: Fleets) -> FleetMembers:
    """`fleets` as a mapping; empty for None."""
    if fleets is None:
        return {}
    return fleets() if callable(fleets) else fleets


def readable_fleets(orgs: Collection[str], members: FleetMembers,
                    joined: Callable[[], Collection[str]]) -> set[str]:
    """The fleet partitions that can hold a row `visible` to a reader of
    `orgs`.

    A fleet whose orgs are all among `orgs` can show its pending rows. A
    fleet bound to some of `orgs` and not all can show only rows attributed
    to one of them, so it is read only when `joined()`, the orgs some
    session joins to, holds one of those. A fleet bound to none of `orgs`
    is not read."""
    held_orgs = set(orgs)
    out: set[str] = set()
    joined_orgs: set[str] | None = None
    for partition, bound in members.items():
        bound = set(bound)
        held = bound & held_orgs
        if not held:
            continue
        if bound <= held_orgs:
            out.add(partition)
            continue
        if joined_orgs is None:
            joined_orgs = set(joined())
        if held & joined_orgs:
            out.add(partition)
    return out


def policy_fleets(policy: Any) -> Callable[[], dict[str, frozenset[str]]]:
    """A `Fleets` function for `policy`: `{fleet partition: org pseudonyms}`
    for each `intake.fleet` entry whose `orgs` names two or more distinct
    orgs, as the intake files its records. Each id is resolved at each call
    (`Policy.org_pseudonym`); one that does not resolve is left out of its
    fleet's set."""
    def members() -> dict[str, frozenset[str]]:
        out: dict[str, frozenset[str]] = {}
        for name, ids in policy.fleet_org_ids():
            distinct = {i for i in ids if i}
            if len(distinct) >= 2:
                resolved = (policy.org_pseudonym(i) for i in distinct)
                out[fleet_partition(name)] = frozenset(p for p in resolved if p)
        return out
    return members


def warn_unresolved_fleets(policy: Any, reader: str) -> list[str]:
    """Log a warning naming each multi-org fleet with an org this reader
    cannot resolve, and return the names. A viewer of such an org is shown
    none of that fleet's records."""
    names = policy.unresolved_fleet_orgs()
    if names:
        _log.warning(
            "an intake.fleet entry names an org this %s cannot resolve, so a viewer "
            "of that org is shown none of the fleet's records; set the org id "
            "variable on this service, or list the org under `orgs` or "
            "`otel.orgs` so the org registry carries it", reader,
            extra={"fields": {"fleets": names}})
    return names


class _AttributedDay(VerdictDay):
    """A VerdictDay whose records are attributed as they are read."""

    def __init__(self, day: VerdictDay, joins: Callable[[], dict[str, str]]):
        super().__init__((), day._fetch, day._root)
        self.keys = day.keys
        self._day = day
        self._joins = joins

    def read(self, key: str) -> list[VerdictRecord]:
        return [attribute(r, self._joins) for r in self._day.read(key)]

    def read_matching(self, key: str, needles: Sequence[bytes]
                      ) -> tuple[list[tuple[int, VerdictRecord]], int, int]:
        rows, lines, size = self._day.read_matching(key, needles)
        return [(i, attribute(r, self._joins)) for i, r in rows], lines, size


class AttributedStore:
    """`store` with every fleet record attributed as it is read.

    A read for some orgs also reads the fleet partitions `readable_fleets`
    names from `fleets`, so a record attributed to one of the orgs is found;
    whether the reader may see a row is still decided by `visible`. With no
    `fleets`, such a read reads no fleet partition. A read for every org
    reads every partition. The join is read from the store when a fleet
    record is met, or when a fleet bound to some of the reader's orgs and
    not all is considered, once per window start, and kept for this
    object's life, which is one request.
    """

    attributed = True

    def __init__(self, store: Any, fleets: Fleets = None):
        self._store = store
        self._fleets = fleets
        self._joins: dict[str | None, dict[str, str]] = {}

    @property
    def store(self) -> Any:
        return self._store

    def joins(self, since: str | None) -> dict[str, str]:
        if since not in self._joins:
            self._joins[since] = session_orgs(self._store, since)
        return self._joins[since]

    def partitions(self, since: str | None,
                   orgs: Collection[str] | None) -> Collection[str] | None:
        """What a read for `orgs` asks the backend for: `orgs` and the fleet
        partitions that can hold a row visible to them, or None for every
        partition."""
        if orgs is None:
            return None
        return {*orgs, *readable_fleets(orgs, fleet_members(self._fleets),
                                        lambda: self.joins(since).values())}

    def read_verdicts(self, since: str | None = None,
                      orgs: Collection[str] | None = None) -> Iterator[VerdictRecord]:
        def joins() -> dict[str, str]:
            return self.joins(since)

        for r in self._store.read_verdicts(since, self.partitions(since, orgs)):
            yield attribute(r, joins)

    def read_verdict_days(self, since: str | None = None,
                          orgs: Collection[str] | None = None,
                          until: str | None = None,
                          sources: Collection[str] | None = None,
                          ) -> Iterator[tuple[str | None, Any]]:
        def joins() -> dict[str, str]:
            return self.joins(since)

        for day, records in read_days(self._store, since, self.partitions(since, orgs),
                                      until, sources):
            if isinstance(records, VerdictDay):
                yield day, _AttributedDay(records, joins)
            else:
                yield day, (attribute(r, joins) for r in records)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)


def attributed(store: Any, fleets: Fleets = None) -> Any:
    """`store` as an AttributedStore reading `fleets`, unless it already
    attributes its records."""
    if getattr(store, "attributed", False) is True:
        return store
    return AttributedStore(store, fleets)
