"""Aggregations for the dashboard.

Deliberately pure Python over an iterable of records rather than SQL: one
implementation serves every backend, it is trivially testable with no
fixtures, and at small volume a full scan costs milliseconds. The
tradeoff is honest and documented -- past a few million records this wants a
real analytical store, and `Store` is the seam for that.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from ..models import (
    FINDINGS_CAPPED,
    NO_CONTENT_READ,
    UNSCANNED,
    UNSCANNED_ARTIFACT,
    UNSCANNED_CAPPED,
    UNSCANNED_PARTIAL,
    UNSCANNED_PREFIX,
)
from .base import (
    EVENT_TOOL_CALL,
    SOURCE_AGENT_SCAN,
    SOURCE_CODE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    SOURCE_MANAGED_SCAN,
    SOURCE_OTEL_COLLECT,
    TOKEN_SOURCES,
    WRITER_ADAPTER,
    WRITER_INTAKE_TOKEN,
    DenialRecord,
    VerdictRecord,
    visible,
)
from .pipeline import Pipeline, PipelineAccumulator
from .pipeline import _parse as _parse_iso
from .tally import weight

# `source.application` (adapter 1) and `product_surface` (adapter 3) name
# the same surfaces with different conventions -- `claude-code` vs
# `claude_code`, `cowork` vs `cowork_remote`. Left unnormalized, the
# dashboard reports one surface twice and overstates coverage, which is
# exactly the number the coverage view exists to get right.
SURFACE_ALIASES = {
    "claude_code": "claude-code",
    "claude_science": "claude-science",
    "claude_in_chrome": "claude-in-chrome",
    "cowork_remote": "cowork",
    # Claude for Microsoft 365 arrives under a THIRD convention. The
    # Compliance API reports `office_agents` and `office_agents/<app>`; the
    # inference hook sends `sheet_agent`, which appears in no documentation
    # and uses an underscore where every documented source.application value
    # uses hyphens. Both must land on one surface or the dashboard reports
    # the same product twice.
    # Adapter 4 names the application when it can and the product when it
    # cannot; all of them are one product. Without these the dashboard
    # reports Claude for M365 twice -- once from the hook and once from
    # OTel -- which reads as two surfaces with partial coverage each.
    "office-excel": "claude-for-m365",
    "office-word": "claude-for-m365",
    "office-powerpoint": "claude-for-m365",
    "office-outlook": "claude-for-m365",
    "office_agents": "claude-for-m365",
    "sheet_agent": "claude-for-m365",
    # Claude Code is ONE surface seen by two control points. The local hook
    # records `claude-code-local` because that is honest provenance -- the
    # decision happened on a laptop, not server-side -- but as a separate row
    # the coverage matrix reads as though the code hook covered a different
    # product, when the real story is one surface with two controls on it.
    # Which control saw it is already carried by `source`.
    "claude-code-local": "claude-code",
    # Not yet observed. Included on the symmetry of `sheet_agent`, so a Word
    # or Outlook session does not silently open a fourth row. Remove any
    # that turn out not to exist rather than leaving a guess in place.
    "doc_agent": "claude-for-m365",
    "slide_agent": "claude-for-m365",
    "mail_agent": "claude-for-m365",
}


# Surfaces that are not products and must not appear as one.
#
# `config-test` is Anthropic's own endpoint validation: it fires when an
# admin saves the inference hook URL, and again as the CIRCUIT-BREAKER
# RECOVERY PROBE -- so it recurs, and it recurs precisely when something is
# already wrong. Left in, the dashboard grows a surface nobody uses, with
# traffic that spikes during an incident, and its trivial frames drag the
# latency percentiles down.
#
# The records are still written. What the probe did is worth keeping; it is
# only the reporting that treats it as a product.
SYNTHETIC_SURFACES = frozenset({"config-test"})


def is_synthetic(surface: str | None) -> bool:
    """True for probes that are traffic but not a product surface."""
    return normalize_surface(surface) in SYNTHETIC_SURFACES


def normalize_surface(surface: str | None) -> str:
    if not surface:
        return "unknown"
    value = surface.strip()
    # Claude for M365 arrives as office_agents/excel and friends.
    if value.startswith("office_agents"):
        return "claude-for-m365"
    # An agent's name is the deployment's own, so it is shown as configured:
    # folding `_` into `-` merged `a_b` and `a-b` into one row.
    if value.startswith("agent:"):
        return value
    return SURFACE_ALIASES.get(value, value.replace("_", "-"))


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * (pct / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


# `utcnow()` emits exactly this, and it is what almost every record
# carries.
_CANONICAL_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def newer(candidate: str, current: str) -> bool:
    """Is `candidate` a later instant than `current`?

    Lexical for the canonical shape, which is the whole hot path: same
    length, same zone, so string order IS instant order, and parsing
    every record on a full scan to take a maximum is what turns it slow.

    Parsed otherwise, because lexical order is NOT instant order across
    shapes and the store is append-only -- a reader meets records from
    every writer that ever wrote, including a laptop. Measured:

        2026-09-21T14:00:00Z  vs  2026-09-21T15:00:00+02:00  (= 13:00Z)
            lexical says the second is newer. It is an hour older.
        2026-09-21T14:00:00Z  vs  2026-09-21T14:00:00.500Z
            lexical says the first is newer. It is half a second older.

    Either one picks the wrong "last seen", and the panel then reports a
    live surface as late or a late one as live.
    """
    if not current:
        return bool(candidate)
    if _CANONICAL_TS.match(candidate) and _CANONICAL_TS.match(current):
        return candidate > current
    a, b = _instant(candidate), _instant(current)
    if a is None or b is None:
        # An unparseable timestamp must not win. A record we cannot
        # place in time is not evidence that anything arrived recently.
        return b is None and a is not None
    return a > b


def _instant(ts: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


@dataclass
class SurfaceRow:
    surface: str
    requests: int = 0
    would_deny: int = 0
    findings: int = 0
    total_ms: list[float] = field(default_factory=list)
    # Which control points saw this surface. The most useful fact in the
    # whole view: a surface seen only post-hoc is one the inline control
    # never evaluated, and summing the two hides that entirely.
    live: int = 0
    post_hoc: int = 0
    code_hook: int = 0
    otel: int = 0
    agent: int = 0
    managed: int = 0
    detections: int = 0
    # The newest `observed_at` on this surface, for the topology panel.
    # There was no timestamp on this row at all, so "is anything still
    # reaching us" could not be answered from a Summary -- a control point
    # that stopped delivering looked exactly like a quiet week.
    #
    # Per SOURCE as well as overall, because the adapters have completely
    # different expected cadences and one number cannot say whether any of
    # them is late. Adapter 3 is a six-hourly cron; adapter 1 is
    # continuous while people work.
    last_seen: str = ""
    last_seen_by_source: dict[str, str] = field(default_factory=dict)

    @property
    def seen_by(self) -> list[str]:
        out = []
        if self.live:
            out.append("inference hook")
        if self.agent:
            out.append("agent check")
        if self.code_hook:
            out.append("code hook")
        if self.post_hoc:
            out.append("compliance scan")
        if self.otel:
            out.append("otel")
        if self.managed:
            out.append("managed scan")
        return out

    @property
    def writer(self) -> str:
        """`WRITER_INTAKE_TOKEN` when every request on this surface was
        shipped with an intake token, else `WRITER_ADAPTER`."""
        token = self.code_hook + self.agent
        return WRITER_INTAKE_TOKEN if self.requests and token == self.requests \
            else WRITER_ADAPTER

    @property
    def inline_coverage(self) -> bool:
        """True when an inline control evaluated this surface at all."""
        return bool(self.live or self.code_hook or self.agent)

    @property
    def deny_rate(self) -> float:
        return (self.would_deny / self.requests) if self.requests else 0.0

    @property
    def has_latency(self) -> bool:
        """Adapter 3 records carry no round-trip time -- there is no round
        trip. Reporting 0 ms for them would read as "instant" rather than
        "not applicable"."""
        return bool(self.total_ms)

    @property
    def p50(self) -> float | None:
        return percentile(self.total_ms, 50) if self.total_ms else None

    @property
    def p95(self) -> float | None:
        return percentile(self.total_ms, 95) if self.total_ms else None


@dataclass
class DetectorRow:
    detector: str
    count: int = 0
    severity: str = "block"
    surfaces: set[str] = field(default_factory=set)
    # Hashes made with the deployment salt only.
    distinct_values: set[str] = field(default_factory=set)
    # (salt_namespace, excerpt_hash) for hashes made with a device's own
    # salt, which compare with nothing outside that namespace.
    device_values: set[tuple[str, str]] = field(default_factory=set)

    @property
    def unique(self) -> int:
        """Distinct matched values, by excerpt_hash, among the hashes made
        with the deployment salt.

        A single leaked key pasted into forty prompts is one problem, not
        forty. Raw counts overstate exposure; this is the number to lead on.
        """
        return len(self.distinct_values)

    @property
    def device_salted(self) -> int:
        """Distinct values among device-salted hashes, counted once per
        salt namespace: one key on 900 laptops is 900."""
        return len(self.device_values)


# Detectors that only ever run post-hoc. A hash these produced cannot be a
# miss by the inline control, because the inline control does not run the
# tier: `compliance.detectors` enables it for adapter 3 alone, on latency
# grounds. Counting them as misses would put thousands of NER hits against a
# handful of real secrets and make the one number this view exists for
# useless.
POST_HOC_ONLY_PREFIXES = ("presidio:", "llmguard:")


def is_post_hoc_only(detector: str) -> bool:
    return detector.startswith(POST_HOC_ONLY_PREFIXES)


@dataclass
class Reconciliation:
    """Live enforcement versus post-hoc scanning.

    The view nothing else provides: what the inline control did not catch,
    counted rather than asserted.
    """

    live_requests: int = 0
    live_would_deny: int = 0
    scanned_sessions: int = 0
    scan_detections: int = 0
    # Adapter 2. Counted separately rather than folded into the live
    # figures: the Code hook blocks BEFORE a tool runs, so a value it
    # stopped never reaches the inference hook at all. Adding its hashes to
    # the "seen live" set would make a successful local block look like an
    # inference-hook detection.
    code_hook_decisions: int = 0
    code_hook_denied: int = 0
    # A PostToolUse deny: the tool had already run, so it withheld the
    # output from the model rather than stopping anything.
    code_hook_withheld: int = 0
    # Anthropic's denial records, each matched to an inference-hook verdict
    # by Anthropic's request id, else by the reference id the verdict
    # returned. A match by neither is unmatched.
    denial_activities: int = 0
    joined_by_request_id: int = 0
    joined_by_reference: int = 0
    denials_unmatched: int = 0
    denials_without_reference: int = 0
    # Denials of a tool call frame: tool calls stopped, not a prompt.
    denials_tool_call: int = 0
    # Findings from tiers the inline path does not run at all. Reported
    # separately so the coverage the post-hoc scan adds stays visible without
    # being miscounted as an inline failure.
    post_hoc_only_findings: int = 0
    # Hashes seen by the post-hoc scan that the live path never reported,
    # restricted to detectors the inline path actually runs.
    missed_value_hashes: set[str] = field(default_factory=set)
    live_value_hashes: set[str] = field(default_factory=set)

    @property
    def missed_count(self) -> int:
        return len(self.missed_value_hashes - self.live_value_hashes)


@dataclass
class Summary:
    generated_at: str = ""
    since: str | None = None
    total_requests: int = 0
    # Connection tests and circuit-breaker recovery probes, excluded from
    # everything above. Counted rather than discarded silently: "no traffic"
    # and "only Anthropic's own probe" are different answers, and during an
    # incident the second one is the interesting one.
    synthetic_probes: int = 0
    # The inference hook's verdicts on tool call frames, also excluded from
    # everything above but findings: one model response that calls tools is
    # a prompt frame and then a tool call frame, and counting both as
    # requests doubles the request totals and mixes the latencies.
    tool_call_checks: int = 0
    tool_call_would_deny: int = 0
    tool_call_denied: int = 0
    # Split out, because a post-hoc session is not a request and summing
    # the two produces a headline number with no meaning.
    live_requests: int = 0
    scanned_sessions: int = 0
    hook_decisions: int = 0
    # Checks agents ran themselves via /scan. Inline, so in the deny
    # rate's denominator: an agent deny counted in the numerator with no
    # matching evaluation below it pushed the rate past 100%.
    agent_checks: int = 0
    # Managed Agents sessions read post-hoc. Not `scanned_sessions`,
    # which the reconciliation compares against the inference hook.
    managed_sessions: int = 0
    total_findings: int = 0
    # Inline controls only. A post-hoc scan cannot deny anything -- by the
    # time it reads a transcript, inference has already happened -- so
    # counting its findings here would report a block that was never
    # possible.
    would_deny: int = 0
    # The part of `would_deny` from records shipped with an intake token
    # (`TOKEN_SOURCES`).
    token_would_deny: int = 0
    enforced_deny: int = 0
    # Post-hoc only: sessions where the scan found blocking-severity
    # content. An observation, not a withheld verdict.
    detections: int = 0
    distinct_values: int = 0
    # Device-salted hashes, once per salt namespace; never in
    # `distinct_values`.
    device_salted_values: int = 0
    surfaces: list[SurfaceRow] = field(default_factory=list)
    detectors: list[DetectorRow] = field(default_factory=list)
    reconciliation: Reconciliation = field(default_factory=Reconciliation)
    # The monitors of delivery itself (store/pipeline.py), from this pass
    # over the same records; cursor health is added by the caller, which
    # holds the store.
    pipeline: Pipeline | None = None
    daily: list[tuple[str, int, int]] = field(default_factory=list)  # day, req, deny
    # INLINE latency only -- the inference hook, where somebody is waiting
    # and the 5,000 ms end-to-end budget applies. A post-hoc scan has no
    # round trip, so putting its duration in the same percentile makes the
    # number mean nothing.
    #
    # Filtered by source rather than taken from every record with a
    # `total_ms`: whether adapter 3 and adapter 4 set the field is a
    # property of the data rather than of the code, and the card is
    # labelled "round trip".
    latency: dict[str, float] = field(default_factory=dict)
    # Post-hoc scan duration, per session or chat. Nobody is waiting on
    # these; the number says how long an audit pass costs.
    post_hoc_latency: dict[str, float] = field(default_factory=dict)
    # Enough about the slowest frame to interpret it. A bare maximum invites
    # alarm: the worst frame is almost always a cold session start on a large
    # transcript, which is expected behaviour rather than a problem.
    slowest: dict[str, Any] = field(default_factory=dict)
    # Which orgs this summary covers. None means every org in the store,
    # which is correct when no entitlement map is configured -- most
    # deployments serve one customer who is entitled to all of their own
    # orgs.
    scoped_to: list[str] | None = None
    # `{pseudonym: requests}`, so a reader can see whether a store holds one
    # org or several without naming any of them.
    orgs: dict[str, int] = field(default_factory=dict)
    cache_hits: int = 0
    cache_misses: int = 0
    budget_exceeded: int = 0
    # Inline frames whose verdict was recorded but not applied. Derived
    # rather than configured: a record carries `shadow_action` only when the
    # control decided one thing and did another, which is what shadow means.
    shadow_frames: int = 0
    # Frames named in the exclusion marker and kept out of the rates above.
    # Counted and displayed rather than silently dropped: a statistic that
    # quietly omits records is worse than one that is noisy.
    excluded_frames: int = 0
    # Frames where the budget actually cost coverage. `budget_exceeded`
    # counts frames that ran long, which is a latency signal and is true even
    # when there was no droppable tier configured. A frame whose only entry
    # is UNSCANNED or UNSCANNED_CAPPED is counted in `oversize_unscanned`
    # instead, one whose only entry is UNSCANNED_ARTIFACT in
    # `artifacts_unscanned`, UNSCANNED_DELETED in `deleted_unread`,
    # UNSCANNED_PARTIAL in `history_partial`, and FINDINGS_CAPPED in none.
    tiers_dropped: int = 0
    # Frames holding a value over the scan size limit whose middle was not
    # scanned.
    oversize_unscanned: int = 0
    # Chats holding an artifact that could not be fetched, so was not scanned.
    artifacts_unscanned: int = 0
    # Chats deleted before any of their messages could be read.
    deleted_unread: int = 0
    # Managed sessions whose history could be read only in part.
    history_partial: int = 0

    @property
    def adapter_would_deny(self) -> int:
        """`would_deny` less the records shipped with an intake token."""
        return self.would_deny - self.token_would_deny

    @property
    def token_decisions(self) -> int:
        """Inline evaluations shipped with an intake token: Code hook
        decisions, tally rows weighted, and agent checks."""
        return self.hook_decisions + self.agent_checks

    @property
    def deny_rate(self) -> float | None:
        """Share of the inference hook's evaluations that would have been
        blocked, or None with none to measure. Records shipped with an
        intake token are in `token_deny_rate` instead."""
        return (self.adapter_would_deny / self.live_requests) if self.live_requests \
            else None

    @property
    def token_deny_rate(self) -> float | None:
        """Share of the inline evaluations shipped with an intake token that
        would have been blocked, or None with none to measure."""
        inline = self.token_decisions
        return (self.token_would_deny / inline) if inline else None

    @property
    def detection_rate(self) -> float:
        """Share of post-hoc scanned sessions containing blocking content.

        Both session scans are in the denominator, because both are in
        `detections`: a Platform-only deployment otherwise read "N
        detected, 0.0% of scanned sessions".
        """
        audited = self.scanned_sessions + self.managed_sessions
        return (self.detections / audited) if audited else 0.0

    @property
    def cache_hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total) if total else 0.0


def latest_per_session(records: Iterable[VerdictRecord]) -> list[VerdictRecord]:
    """Collapse repeated scans of the same session to the one that says most.

    The ingest job re-walks sessions active since its last pass, and the
    store is append-only, so a session still in use accumulates one record
    per run. Every one of those is a legitimate historical observation --
    the session grew -- but counting them all would report one session as
    five and inflate the coverage numbers that this view exists to get
    right.

    The record kept is the one `session_preference` ranks first, so a later
    record that read less never replaces one that found something: a chat
    deleted after a detection stays detected. When the newest record says
    the chat was deleted, the kept record carries its `deleted_at`.

    Only applies to records carrying a session_id from a post-hoc session
    scan: the Compliance API's, and adapter 6's, which rescans a managed
    session each time its history grows. Inference-hook records are one per request and
    must never be collapsed.
    """
    return list(_latest_per_session(records))


def session_preference(record: VerdictRecord) -> tuple:
    """The order the observations of one session are preferred in, highest
    first: a blocking finding, then any finding, then content read at all,
    then the history read whole, then the most messages read, then the
    latest observation."""
    dropped = record.tiers_dropped
    return (
        record.detected,
        record.flagged,
        not any(m in dropped for m in NO_CONTENT_READ),
        UNSCANNED_PARTIAL not in dropped,
        record.messages_scanned or record.messages_total or 0,
        record.observed_at or "",
    )


def preferred_observation(records: Iterable[VerdictRecord]) -> VerdictRecord | None:
    """The observation of one session `latest_per_session` keeps, or None
    for no records."""
    best: dict[tuple[str, str], VerdictRecord] = {}
    newest: dict[tuple[str, str], VerdictRecord] = {}
    for record in records:
        _observe(best, newest, ("", ""), record)
    return next(_kept(best, newest), None)


def _observe(best: dict, newest: dict, key: tuple[str, str], record: VerdictRecord) -> None:
    current = best.get(key)
    if current is None or session_preference(record) > session_preference(current):
        best[key] = record
    latest = newest.get(key)
    if latest is None or (record.observed_at or "") > (latest.observed_at or ""):
        newest[key] = record


def _kept(best: dict, newest: dict):
    for key, record in best.items():
        latest = newest[key]
        if latest.deleted_at and not record.deleted_at:
            record = replace(record, deleted_at=latest.deleted_at)
        yield record


def _latest_per_session(records: Iterable[VerdictRecord]):
    """`latest_per_session` as a generator: every other record as it
    arrives, then the kept record of each collapsed session."""
    best: dict[tuple[str, str], VerdictRecord] = {}
    newest: dict[tuple[str, str], VerdictRecord] = {}
    for record in records:
        if record.source in (SOURCE_COMPLIANCE_SCAN, SOURCE_MANAGED_SCAN) and record.session_id:
            _observe(best, newest, (record.source, record.session_id), record)
        else:
            yield record
    yield from _kept(best, newest)


def effective_since(since: str | None, reset_at: str | None) -> str | None:
    """The later of the window start and the statistics reset marker.

    A reset does not delete anything -- it moves the floor. That keeps the
    records for audit while giving a clean slate to whoever is reading the
    numbers, which matters after a period of testing has polluted them.
    """
    candidates = [c for c in (since, reset_at) if c]
    return max(candidates) if candidates else None


def build_summary(
    verdicts: Iterable[VerdictRecord],
    denials: Iterable[DenialRecord] = (),
    since: str | None = None,
    excluded: set[str] | None = None,
    orgs: Collection[str] | None = None,
) -> Summary:
    from .base import utcnow

    out = Summary(
        generated_at=utcnow(), since=since,
        scoped_to=None if orgs is None else sorted(orgs),
    )

    def kept(stream: Iterable[VerdictRecord]):
        # One pass, holding only the post-hoc session records
        # `latest_per_session` collapses: materialising a fleet's week of
        # records here held them all in memory at once. The window applies
        # before the collapse, so a session is judged on what was observed
        # of it inside the window.
        for v in stream:
            # A second filter, after the store has already pruned by
            # partition. The partition is an optimisation a backend could
            # implement wrongly; this decides whether a viewer sees an org
            # they are not entitled to.
            if orgs is not None and not visible(v, orgs):
                continue
            if since and v.observed_at < since:
                continue
            if excluded and v.request_id and v.request_id in excluded:
                out.excluded_frames += 1
                continue
            yield v

    verdicts = _latest_per_session(kept(verdicts))
    surfaces: dict[str, SurfaceRow] = {}
    detectors: dict[str, DetectorRow] = {}
    per_day: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    all_latency: list[float] = []
    post_hoc_latency: list[float] = []
    slowest_rec: VerdictRecord | None = None
    pipe = PipelineAccumulator()
    recon = out.reconciliation
    seen_values: set[str] = set()
    # The ids of the inference-hook verdicts, for matching Anthropic's denials.
    live_request_ids: set[str] = set()
    live_reference_ids: set[str] = set()
    device_values: set[tuple[str, str]] = set()

    def count_findings(v: VerdictRecord, key: str) -> None:
        for f in v.findings:
            det = detectors.setdefault(f.detector, DetectorRow(f.detector))
            det.count += 1
            det.severity = f.severity
            det.surfaces.add(key)
            if v.salt_namespace:
                det.device_values.add((v.salt_namespace, f.excerpt_hash))
                device_values.add((v.salt_namespace, f.excerpt_hash))
            else:
                det.distinct_values.add(f.excerpt_hash)
                seen_values.add(f.excerpt_hash)

    for v in verdicts:
        # Before the totals, not just the surface rows: a connection test
        # counted in total_requests and in the latency percentiles reports
        # coverage and performance nobody exercised.
        if is_synthetic(v.surface):
            out.synthetic_probes += 1
            continue
        if v.source == SOURCE_INFERENCE_HOOK and v.event == EVENT_TOOL_CALL:
            pipe.observe(v, 1)
            out.tool_call_checks += 1
            if v.effective_action == "deny":
                out.tool_call_would_deny += 1
            if v.action == "deny":
                out.tool_call_denied += 1
            out.total_findings += v.findings_count
            key = normalize_surface(v.surface)
            if key in surfaces:
                surfaces[key].findings += v.findings_count
            count_findings(v, key)
            recon.live_value_hashes.update(f.excerpt_hash for f in v.findings)
            continue
        # A tally row stands for `n` clean Code hook allows (store/tally.py).
        n = weight(v)
        pipe.observe(v, n)
        out.total_requests += n
        out.total_findings += v.findings_count
        effective = v.effective_action
        if v.is_inline:
            if effective == "deny":
                out.would_deny += 1
                if v.source in TOKEN_SOURCES:
                    out.token_would_deny += 1
            if v.action == "deny":
                out.enforced_deny += 1
        elif v.detected:
            out.detections += 1
        if v.cache_hit:
            out.cache_hits += 1
        else:
            out.cache_misses += n
        if v.is_inline and v.shadow_action and v.shadow_action != v.action:
            out.shadow_frames += 1
        if v.budget_exceeded:
            out.budget_exceeded += 1
        if any(not t.startswith(UNSCANNED_PREFIX) and t != FINDINGS_CAPPED
               for t in v.tiers_dropped):
            out.tiers_dropped += 1
        if UNSCANNED in v.tiers_dropped or UNSCANNED_CAPPED in v.tiers_dropped:
            out.oversize_unscanned += 1
        if UNSCANNED_ARTIFACT in v.tiers_dropped:
            out.artifacts_unscanned += 1
        if any(m in v.tiers_dropped for m in NO_CONTENT_READ):
            out.deleted_unread += 1
        if UNSCANNED_PARTIAL in v.tiers_dropped:
            out.history_partial += 1

        out.orgs[v.org] = out.orgs.get(v.org, 0) + n

        key = normalize_surface(v.surface)
        row = surfaces.setdefault(key, SurfaceRow(key))
        row.requests += n
        if v.observed_at:
            if newer(v.observed_at, row.last_seen):
                row.last_seen = v.observed_at
            if newer(v.observed_at, row.last_seen_by_source.get(v.source, "")):
                row.last_seen_by_source[v.source] = v.observed_at
        row.findings += v.findings_count
        if not v.is_inline and v.detected:
            row.detections += 1
        if v.source == SOURCE_INFERENCE_HOOK:
            row.live += 1
        elif v.source == SOURCE_COMPLIANCE_SCAN:
            row.post_hoc += 1
        elif v.source == SOURCE_CODE_HOOK:
            row.code_hook += n
        elif v.source == SOURCE_OTEL_COLLECT:
            row.otel += 1
        elif v.source == SOURCE_AGENT_SCAN:
            row.agent += 1
        elif v.source == SOURCE_MANAGED_SCAN:
            row.managed += 1
        if v.is_inline and effective == "deny":
            row.would_deny += 1
        if v.total_ms is not None:
            row.total_ms.append(v.total_ms)
            if v.is_inline:
                all_latency.append(v.total_ms)
                if slowest_rec is None or v.total_ms > (slowest_rec.total_ms or 0):
                    slowest_rec = v
        # Adapter 3 sets `scan_ms`, not `total_ms`: there is no round trip
        # to measure, only how long the detectors took.
        if not v.is_inline and v.scan_ms is not None:
            post_hoc_latency.append(v.scan_ms)

        day = per_day[v.day]
        day[0] += n
        if v.is_inline and effective == "deny":
            day[1] += 1

        count_findings(v, key)

        if v.source == SOURCE_INFERENCE_HOOK:
            out.live_requests += 1
            recon.live_requests += 1
            if v.request_id:
                live_request_ids.add(v.request_id)
            if v.reference_id:
                live_reference_ids.add(v.reference_id)
            if effective == "deny":
                recon.live_would_deny += 1
            recon.live_value_hashes.update(f.excerpt_hash for f in v.findings)
        elif v.source == SOURCE_AGENT_SCAN:
            out.agent_checks += 1
        elif v.source == SOURCE_MANAGED_SCAN:
            out.managed_sessions += 1
        elif v.source == SOURCE_CODE_HOOK:
            out.hook_decisions += n
            recon.code_hook_decisions += n
            if effective == "deny":
                if (v.request_id or "").startswith("PostToolUse:"):
                    recon.code_hook_withheld += 1
                else:
                    recon.code_hook_denied += 1
        elif v.source == SOURCE_COMPLIANCE_SCAN:
            out.scanned_sessions += 1
            recon.scanned_sessions += 1
            if v.detected:
                recon.scan_detections += 1
            recon.missed_value_hashes.update(
                f.excerpt_hash
                for f in v.findings
                if not is_post_hoc_only(f.detector)
            )
            recon.post_hoc_only_findings += sum(
                1 for f in v.findings if is_post_hoc_only(f.detector)
            )

    for d in denials:
        if since and d.created_at < since:
            continue
        recon.denial_activities += 1
        if d.event == "tool_call":
            recon.denials_tool_call += 1
        if not d.reference_id:
            recon.denials_without_reference += 1
        if d.request_id and d.request_id in live_request_ids:
            recon.joined_by_request_id += 1
        elif d.reference_id and d.reference_id in live_reference_ids:
            recon.joined_by_reference += 1
        else:
            recon.denials_unmatched += 1

    out.distinct_values = len(seen_values)
    out.device_salted_values = len(device_values)
    out.surfaces = sorted(surfaces.values(),
                          key=lambda r: (r.writer == WRITER_INTAKE_TOKEN, -r.requests))
    out.detectors = sorted(detectors.values(), key=lambda r: (-r.unique, -r.count))
    out.daily = sorted((d, c[0], c[1]) for d, c in per_day.items())
    out.latency = _percentiles(all_latency)
    window = None
    if since:
        start = _parse_iso(since)
        if start is not None:
            window = max(0.0, (datetime.now(UTC) - start).total_seconds() / 60)
    joined = recon.joined_by_request_id + recon.joined_by_reference
    out.pipeline = pipe.result(denials_joined=joined,
                               denial_activities=recon.denial_activities,
                               window_minutes=window)
    out.post_hoc_latency = _percentiles(post_hoc_latency)
    if slowest_rec is not None:
        out.slowest = {
            "total_ms": round(slowest_rec.total_ms or 0, 1),
            "body_bytes": slowest_rec.body_bytes or 0,
            "messages": slowest_rec.messages_total or 0,
            "cache_hit": bool(slowest_rec.cache_hit),
            "surface": normalize_surface(slowest_rec.surface),
            "observed_at": slowest_rec.observed_at,
        }
    return out


def _percentiles(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "p50": round(percentile(values, 50), 1),
        "p95": round(percentile(values, 95), 1),
        "p99": round(percentile(values, 99), 1),
        "max": round(max(values), 1) if values else 0.0,
    }


def detector_family(detector: str) -> str:
    """Group `regex:aws-access-key` and `gitleaks:aws-access-token` together.

    Both tiers fire on the same value, so counting by raw detector id
    double-counts every finding. The family is what a reviewer cares about.
    """
    tail = detector.split(":", 1)[-1]
    for family in ("aws", "github", "gitlab", "slack", "stripe", "google", "azure",
                   "anthropic", "openai", "ssn", "pan", "credit", "jwt",
                   "private-key", "privatekey", "npm", "twilio", "sendgrid"):
        if family in tail:
            return family.replace("privatekey", "private-key")
    return tail


def family_severities(summary: Summary) -> dict[str, str]:
    """Strictest severity per detector family.

    Families genuinely mix: `aws` is `regex:aws-access-key` at block while
    `access_key` is `entropy:access_key` at warn, and a family carrying one
    block-severity value is a block finding regardless of what else landed
    in it.
    """
    out: dict[str, str] = {}
    for det in summary.detectors:
        family = detector_family(det.detector)
        if det.severity == "block" or out.get(family) != "block":
            out[family] = det.severity if det.severity == "block" else out.get(
                family, det.severity
            )
    return out


def families(summary: Summary) -> list[tuple[str, int]]:
    """Distinct values per detector family, newest-largest first.

    Unions the value hashes rather than summing each detector's unique
    count. T0 and T1 both fire on the same secret, so summing would report
    one leaked AWS key as two -- which is the same double-count the
    deny-reason wording had to solve, in a different place.
    """
    grouped: dict[str, set[str]] = {}
    for det in summary.detectors:
        grouped.setdefault(detector_family(det.detector), set()).update(
            det.distinct_values
        )
    return sorted(
        ((family, len(values)) for family, values in grouped.items()),
        key=lambda kv: (-kv[1], kv[0]),
    )


def family_device_values(summary: Summary) -> dict[str, int]:
    """Device-salted values per detector family, counted once per laptop.

    The union is over (salt_namespace, excerpt_hash), so both tiers firing
    on one laptop's value count once and the same value on two laptops
    counts twice, as in a detector's `device_salted`. Families with none
    are left out.
    """
    grouped: dict[str, set[tuple[str, str]]] = {}
    for det in summary.detectors:
        if det.device_values:
            grouped.setdefault(detector_family(det.detector), set()).update(
                det.device_values
            )
    return {family: len(values) for family, values in grouped.items()}


__all__ = [
    "DetectorRow",
    "Reconciliation",
    "Summary",
    "SurfaceRow",
    "build_summary",
    "detector_family",
    "effective_since",
    "latest_per_session",
    "preferred_observation",
    "session_preference",
    "normalize_surface",
    "families",
    "family_device_values",
    "family_severities",
    "percentile",
]
