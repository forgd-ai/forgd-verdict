"""OTel records -> VerdictRecords, via the same scan core as everything else.

Grouping: one record per user turn, keyed on `prompt.id` -- the attribute
Anthropic sets to correlate every event arising from a single prompt. That
is the closest analogue to what the other adapters call a request, and it
keeps the dashboard's "requests" column meaning the same thing across all
four.

Falling back to `session.id` and then to the batch matters, because the
alternative is one VerdictRecord per OTel record. A single turn emits a
prompt event, a response event and one event per tool call, so counting
those as requests would report a surface as five times busier than it is
and quietly skew every rate on the page.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from collections import OrderedDict
from collections.abc import Callable

from .. import build_id
from ..applog import exc_fields
from ..budget import Budget
from ..core import _DECODED_SUFFIX, decide, gitleaks_left_out, scan, with_left_out
from ..metadata import MetadataGuard
from ..models import (
    ACTION_DENY,
    FINDINGS_CAPPED,
    TAIL_SUFFIX,
    UNSCANNED_CAPPED,
    Finding,
    ScanUnit,
)
from ..store.base import (
    SOURCE_OTEL_COLLECT,
    FindingRow,
    VerdictRecord,
    pseudonym,
    utcnow,
)
from . import SURFACE_UNKNOWN
from .extract import (
    attribution_hint,
    batch_unrecognised_keys,
    records_units,
    surface_of,
)
from .payload import OtelRecord

_log = logging.getLogger("forgd_verdict.otel.collect")


def group_key(record: OtelRecord,
              agents: frozenset[str] = frozenset()) -> tuple[str, str]:
    """(surface, turn). See the module docstring for why not per-record."""
    turn = record.get("prompt.id") or record.get("session.id") or ""
    return surface_of(record, agents), turn


_DERIVED_SUFFIXES = ("", _DECODED_SUFFIX, TAIL_SUFFIX, TAIL_SUFFIX + _DECODED_SUFFIX)


def matched_texts(units: list[ScanUnit], findings: list[Finding]) -> set[str]:
    """The text of each of `units` a finding is on: at its locator, at a
    unit derived from it, or at one of its `seam_others`."""
    at = {f.raw_locator or f.locator for f in findings}
    at.update(o for f in findings for o in f.seam_others)
    return {u.text for u in units if any(u.locator + s in at for s in _DERIVED_SUFFIXES)}


class SeenFindings:
    """Which findings each session has already recorded, bounded.

    Claude Code's raw API bodies (`OTEL_LOG_RAW_API_BODIES`) are the whole
    cumulative conversation, re-sent with every request and every retry.
    Scanning each one is right -- it is the only OTel path that carries
    what an agent read -- but recording each one would report one card
    number once per retry and per later turn, and counts would grow with
    session length. Adapter 1 avoids this with its session cache; this is the
    equivalent for a stream that has no message boundaries to resume from.

    Keyed on a digest of (org, session.id) and remembers a digest of
    (detector, excerpt_hash), so a long session id is not held. At most
    `max_sessions` sessions, `per_session` marks each and `max_marks` in
    all; past either of the last two bounds the least recently used
    sessions are dropped. In memory, like the rest of the collector's
    state: a restart may record a repeat once more, which is the cheap side
    of the trade.
    """

    def __init__(self, max_sessions: int = 10_000, per_session: int = 1_000,
                 max_marks: int = 200_000) -> None:
        self._sessions: OrderedDict[bytes, set[bytes]] = OrderedDict()
        self._max_sessions = max_sessions
        self._per_session = per_session
        self._max_marks = max_marks
        self._marks = 0
        self._lock = threading.Lock()

    def new(self, org: str, session: str | None, findings: list[Finding],
            added: list | None = None) -> list[Finding]:
        """The findings this session has not recorded before; remembers them.
        Each mark remembered is appended to `added` as (key, mark), so a
        caller whose record is then not accepted can `forget` them."""
        if not session:
            return list(findings)
        key = _digest(org, session)
        with self._lock:
            seen = self._sessions.get(key)
            if seen is None:
                seen = self._sessions[key] = set()
            self._sessions.move_to_end(key)
            out = []
            for f in findings:
                mark = _digest(f.detector, f.excerpt_hash)
                if mark in seen:
                    continue
                out.append(f)
                if len(seen) < self._per_session:
                    seen.add(mark)
                    self._marks += 1
                    if added is not None:
                        added.append((key, mark))
            while len(self._sessions) > 1 and (len(self._sessions) > self._max_sessions
                                               or self._marks > self._max_marks):
                _, dropped = self._sessions.popitem(last=False)
                self._marks -= len(dropped)
            return out

    def forget(self, added: list) -> None:
        """Drop marks `new` appended to `added`."""
        with self._lock:
            for key, mark in added:
                marks = self._sessions.get(key)
                if marks is not None and mark in marks:
                    marks.discard(mark)
                    self._marks -= 1


def _digest(*parts: str) -> bytes:
    """16 bytes standing for `parts`, as SeenFindings keys and marks."""
    h = hashlib.blake2b(digest_size=16)
    for part in parts:
        data = str(part).encode("utf-8", "surrogatepass")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.digest()


def collect(
    records: list[OtelRecord],
    detectors,
    *,
    budget_ms: float,
    salt: str = "",
    org_id: str = "",
    # Adapter 5. Called once per group with the RAW records and the
    # in-memory Findings -- which still carry spans, unlike the FindingRows
    # that go to the store. Forwarding cannot re-scan: a second pass would
    # be a second implementation of what is scannable, and the way that
    # drifts is a value the scanner reads and the redactor does not.
    #
    # A callback rather than a third return value, so a caller that does
    # not forward is unchanged and cannot pay for this.
    on_group: (
        Callable[[list[OtelRecord], list[Finding], str, list[str]], None] | None
    ) = None,
    # Called once after every group has been handed to `on_group`.
    on_done: Callable[[], None] | None = None,
    seen: SeenFindings | None = None,
    # Receives every mark `seen` remembers during this call, for the caller
    # to `seen.forget` when the records are not accepted.
    seen_added: list | None = None,
    agents: frozenset[str] = frozenset(),
    meta: MetadataGuard | None = None,
    # The policy `decide` reads, for `server.on_tier_dropped` and detector
    # severities. None decides as the shipped default, `allow`.
    policy=None,
) -> tuple[list[VerdictRecord], list[str]]:
    """Scan a decoded batch. Returns (records to store, unrecognised keys).

    The org is the one the bearer token resolved to, NOT the one the payload
    claims. `organization.id` on the wire is an assertion by the sender; the
    token is the thing we issued. They are cross-checked in the receiver.
    """
    meta = meta if meta is not None else MetadataGuard(
        detectors, salt, allow_subprocess=True)
    groups: dict[tuple[str, str], list[OtelRecord]] = {}
    unknown = batch_unrecognised_keys(records, detectors)
    unattributed: list[str] = []
    for record in records:
        key = group_key(record, agents)
        groups.setdefault(key, []).append(record)
        # What an unattributable record called itself. Reported as an
        # unrecognised key so it reaches /stats without a second channel:
        # otherwise "records arrived, surface is otel-unknown" is a dead
        # end with the answer sitting in the payload.
        if key[0] == SURFACE_UNKNOWN:
            unattributed.append(attribution_hint(record))
    unknown.update(f"unattributed:{hint}" for hint in
                   meta.many(unattributed, where="otel:unattributed"))
    # Each group's attribution hints, cleaned in one call for the batch.
    hints = [attribution_hint(m) for members in groups.values() for m in members]
    cleaned = iter(meta.many(hints, where="otel:reported_as"))
    reported = [[next(cleaned) for _ in members] for members in groups.values()]

    left_out = (["gitleaks"] if policy is not None and gitleaks_left_out(policy, detectors)
                else [])
    out: list[VerdictRecord] = []
    # Every unit text the scan placed a finding on, across the batch.
    matched_all: set[str] = set()
    replaced = 0
    for ((surface, turn), members), claims in zip(groups.items(), reported, strict=True):
        units = records_units(members)
        # A per-group budget, not a per-batch one. A batch can hold hundreds
        # of turns, and a single shared budget would mean whichever turns
        # were scanned last got nothing -- silently, and always the same
        # ones, because dict order follows arrival order.
        budget = Budget(budget_ms)
        result = scan(units, detectors, budget)
        result.detectors_skipped = with_left_out(result.detectors_skipped, left_out)
        # A payload value written to the record is replaced when the scan
        # matched it, whichever tier did; `meta.records` probes only the
        # guard's own detectors.
        matched = matched_texts(units, result.findings)
        matched_all |= matched

        def unmatched(value, matched=matched):
            nonlocal replaced
            if value not in matched:
                return value
            replaced += 1
            return meta.placeholder(value)

        if on_group is not None:
            # Never let a forwarding failure break ingest. A non-200 to
            # Anthropic is an export failure and sustained failures trip
            # the circuit breaker, so a broken sink must cost telemetry
            # downstream and nothing upstream.
            # `redact_events` masks every value whole on UNSCANNED_CAPPED.
            # Over the findings cap, findings it would place were dropped,
            # so it is given that marker too.
            skipped = list(result.detectors_skipped)
            if FINDINGS_CAPPED in skipped and UNSCANNED_CAPPED not in skipped:
                skipped.append(UNSCANNED_CAPPED)
            try:
                on_group(members, result.findings, surface, skipped)
            except Exception as exc:  # pragma: no cover - defensive
                _log.warning("sink hook failed", extra={"fields": exc_fields(exc)})

        session_id = next(
            (m.get("session.id") for m in members if m.get("session.id")), None
        )
        # AFTER the sink hook, which is handed every finding: a forwarded
        # event must be masked even when its secret was recorded already.
        # Only what is stored is de-duplicated.
        stored = (seen.new(org_id, session_id, result.findings, seen_added)
                  if seen is not None else list(result.findings))
        verdict = decide(stored,
                         policy if policy is not None else _POLICY_FOR_DECIDE,
                         dropped=list(result.detectors_skipped))
        actor = next(
            (
                m.get("user.email", "user.account_uuid", "user.id")
                for m in members
                if m.get("user.email", "user.account_uuid", "user.id")
            ),
            None,
        )
        model = next((m.get("model") for m in members if m.get("model")), None)
        out.append(
            VerdictRecord(
                source=SOURCE_OTEL_COLLECT,
                observed_at=utcnow(),
                session_id=unmatched(session_id or (turn or None)),
                surface=surface,
                # The input to the surface decision, kept alongside the
                # decision.
                #
                # EVERY distinct claim in the group, not the first one. The
                # group key is (surface, turn) and not the service name, so
                # two senders that resolve to one surface in one turn --
                # `excel-agent` and `sheet_agent` both mean office-excel --
                # land in the same group. Taking members[0] would record
                # whichever arrived first and silently drop the other,
                # which is the same shape of loss this field exists to
                # stop. Almost always one value.
                reported_as=", ".join(sorted({unmatched(c) for c in claims})) or None,
                tenant_hash=pseudonym(org_id, salt, "org"),
                actor_hash=pseudonym(actor, salt, "user"),
                model=unmatched(model),
                messages_total=len(members),
                messages_scanned=len(members),
                # `decide` says what an inline control WOULD have done. This
                # adapter cannot block, so it is recorded as a detection and
                # never as an enforced deny -- `is_inline` is false for this
                # source, which is what keeps the two apart on the dashboard.
                action=ACTION_DENY if verdict.action == ACTION_DENY else "allow",
                scan_ms=round(budget.elapsed_ms, 3),
                findings_count=len(stored),
                findings=[FindingRow.from_finding(f) for f in stored],
                budget_exceeded=result.budget_exceeded,
                tiers_dropped=list(result.detectors_skipped),
                build=build_id(),
            )
        )
    if on_done is not None:
        try:
            on_done()
        except Exception as exc:  # pragma: no cover - defensive
            _log.warning("sink hook failed", extra={"fields": exc_fields(exc)})
    prefix = "unattributed:"
    hints = {k for k in unknown if k.startswith(prefix) and k[len(prefix):] in matched_all}
    unknown = (unknown - hints) | {f"{prefix}{meta.placeholder(k[len(prefix):])}"
                                   for k in hints}
    meta.count(replaced + len(hints))
    return meta.records(out), sorted(unknown)


class _DecideOnlyPolicy:
    """What `decide` reads when `collect` is given no policy.

    `on_tier_dropped` is `allow`, the same default as `server.on_tier_dropped`.
    It knows no detector severities, so `unscanned:capped` and
    `unscanned:oversize` allow under it.
    """

    contact_line = ""
    on_tier_dropped = "allow"

    def detector_configs(self) -> dict:
        return {}

    def plugin_phrases(self) -> dict[str, str]:
        return {}


_POLICY_FOR_DECIDE = _DecideOnlyPolicy()
