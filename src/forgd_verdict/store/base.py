"""Records and the store protocol for the findings pipeline.

Two producers write here and one consumer reads:

    adapter 1 (inference hooks, live)  ┐
                                       ├─> store ─> dashboard
    adapter 3 (compliance scan, cron)  ┘

Storage is append-only, time-partitioned JSONL. That is a deliberate choice
over a database:

  * Two independent writers need no coordination, because each writes its own
    immutable objects. No locking, no shared filesystem, no SQLite-over-SMB
    corruption risk.
  * No migrations, no connection pooling, no credentials on the read path.
  * The dashboard is stateless and can be redeployed or scaled freely.

The cost is that aggregation is a full scan in Python. At small volume
(thousands to low millions of records) that is fine and measured in
milliseconds; past that this wants a real analytical store, and the Store
protocol is where that swap happens.

PRIVACY: this store never holds prompt content. It holds findings --
detector, locator, and a one-way digest -- exactly as Finding does. In
verdict and denial rows, organization and person identifiers are hashed on
the way in, so the store supports "group by user" without naming anyone;
the intake's rows are the exception, filed under the client's configured
name. `session_id` is kept in the clear deliberately: it is an opaque
handle needed to fetch the transcript back through the Compliance API
during review. State, audit and control objects are not rows and carry raw
identifiers: the org registry's org ids and workspace keys, cursors'
session ids, and admin identities. docs/PRIVACY.md lists each.
"""

from __future__ import annotations

import json
import math
import re
from bisect import bisect_left
from collections.abc import Callable, Collection, Iterable, Iterator, Sequence
from dataclasses import MISSING, asdict, dataclass, field, fields
from datetime import UTC, date, datetime
from typing import Any, Protocol

# compliance/ingest, otel/collect, managed/scanner and hook/cli import
# `pseudonym` from this module.
from ..models import (
    ORG_UNATTRIBUTED,
    Finding,
    pseudonym,
)

SOURCE_INFERENCE_HOOK = "inference_hook"
# An inference-hook record's `event`: the frame was a tool call frame, or
# of a type the server did not recognise. A prompt frame leaves it None.
EVENT_TOOL_CALL = "tool_call"
EVENT_OTHER = "other"
SOURCE_COMPLIANCE_SCAN = "compliance_scan"
# Adapter 2. Kept distinct from `inference_hook` because the two see the
# same tool call at different moments: the Code hook sees it BEFORE
# execution, the inference hook only on the next request, after it has
# already run. Comparing them is the interesting part.
SOURCE_CODE_HOOK = "code_hook"
# Adapter 4. OTel arrives after the work has happened and there is nothing
# waiting on a verdict, so it is deliberately NOT in `is_inline` below: it
# can detect and it cannot prevent. It is kept distinct from
# `compliance_scan` because the two cover different products -- the
# Compliance API is Enterprise-only, while Cowork and office agent
# telemetry reach Team plans too.
SOURCE_OTEL_COLLECT = "otel_collect"
# A check an agent's own code runs before each model call, by posting its
# messages array to /scan. Inline, like the inference hook, but a
# separate source: the builder assembled the frame, not Anthropic, so it
# must never be counted as inference-hook coverage of a surface.
SOURCE_AGENT_SCAN = "agent_scan"
# Adapter 6: Claude Managed Agents session histories, read after the fact
# from the Managed Agents API. Post-hoc like the Compliance scan, but a different API and a
# different product: a managed agent's traffic never passes an inference
# hook, so its findings are not "missed live" in the reconciliation sense.
SOURCE_MANAGED_SCAN = "managed_scan"
SOURCES = (
    SOURCE_INFERENCE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_CODE_HOOK,
    SOURCE_OTEL_COLLECT,
    SOURCE_AGENT_SCAN,
    SOURCE_MANAGED_SCAN,
)
# Sources whose records arrive through an intake token, which every laptop
# in a fleet holds. Every other source is written by an adapter that
# Anthropic authenticates or that reads Anthropic's own API.
TOKEN_SOURCES = frozenset({SOURCE_CODE_HOOK, SOURCE_AGENT_SCAN})
# Readers that pick one record among several prefer the earlier source here.
SOURCE_PRECEDENCE = (
    SOURCE_INFERENCE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_MANAGED_SCAN,
    SOURCE_OTEL_COLLECT,
    SOURCE_AGENT_SCAN,
    SOURCE_CODE_HOOK,
)
WRITER_ADAPTER = "adapter"
WRITER_INTAKE_TOKEN = "intake_token"


def writer_class(source: str | None) -> str:
    """`WRITER_INTAKE_TOKEN` for a source in `TOKEN_SOURCES`, else
    `WRITER_ADAPTER`. An unknown source is classed with the tokens."""
    return WRITER_ADAPTER if source in SOURCES and source not in TOKEN_SOURCES \
        else WRITER_INTAKE_TOKEN


def source_rank(source: str | None) -> int:
    """`source`'s index in `SOURCE_PRECEDENCE`; an unknown source ranks last."""
    try:
        return SOURCE_PRECEDENCE.index(source)
    except ValueError:
        return len(SOURCE_PRECEDENCE)


SCHEMA_VERSION = 1

# The partition a fleet bound to several orgs files its records under
# until each is attributed to one of them: `fleet-<name>`. No org or
# workspace pseudonym has this prefix.
FLEET_PARTITION_PREFIX = "fleet-"
# In `orgs` to a read: every fleet's partition, whatever its name.
ANY_FLEET = "fleet-*"


def fleet_partition(name: str) -> str:
    """The partition fleet `name`'s records file under until attributed."""
    return f"{FLEET_PARTITION_PREFIX}{name}"


def is_fleet_partition(org: str | None) -> bool:
    return (isinstance(org, str) and org.startswith(FLEET_PARTITION_PREFIX)
            and org != ANY_FLEET)


def visible(record, orgs: Collection[str] | None) -> bool:
    """Whether a reader entitled to `orgs` (None: every org) may see `record`.

    A record in its own org's partition is visible to that org's readers. A
    record still in a fleet's partition is visible only to a reader of
    every org in its `fleet_orgs`, or to one who asked for that partition
    by name, which only a reader with no entitlement map can do.
    """
    if orgs is None:
        return True
    org = record.org
    if org in orgs:
        return True
    fleet_orgs = getattr(record, "fleet_orgs", None)
    return (is_fleet_partition(org) and bool(fleet_orgs)
            and all(o in orgs for o in fleet_orgs))


def utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class FindingRow:
    detector: str
    severity: str
    locator: str
    excerpt_hash: str
    tool_name: str | None = None

    @classmethod
    def from_finding(cls, f: Finding) -> FindingRow:
        return cls(f.detector, f.severity, f.locator, f.excerpt_hash, f.tool_name)


@dataclass
class VerdictRecord:
    """One evaluated request, from either adapter."""

    source: str
    observed_at: str = field(default_factory=utcnow)
    # Correlation. request_id is the inference hook's webhook-id;
    # session_id is the Compliance API's session handle.
    request_id: str | None = None
    session_id: str | None = None
    # When the underlying session itself was active. Distinct from
    # observed_at, which is when WE looked: a post-hoc scan run today can
    # observe a session that finished last week, and conflating the two makes
    # every time window and the statistics reset behave wrongly.
    session_started_at: str | None = None
    session_updated_at: str | None = None
    # Adapter 3 only: when the chat was deleted in claude.ai, as the
    # listing reported it.
    deleted_at: str | None = None
    # `source_application` for adapter 1, `product_surface` for adapter 3.
    surface: str | None = None
    tenant_hash: str | None = None
    actor_hash: str | None = None
    # Which salt hashed this record's findings, as a stable id and NEVER the
    # salt itself. Adapter 2 hashes with a PER-DEVICE salt -- the deployment
    # secret must not reach a laptop -- so its excerpt_hash values are not
    # comparable with the server's, or with another laptop's. Without this
    # marker a reader silently unions them and reports one leaked key as
    # several. Empty means the deployment salt, which is every server-side
    # writer.
    salt_namespace: str | None = None
    # Adapter 2 only. The intake credential that wrote the record (a fleet
    # or a client name, never an org) and the device it named, both set by
    # the intake and never taken from the record.
    client: str | None = None
    device: str | None = None
    # Adapter 2 only, set by the intake: the org pseudonyms of a fleet bound
    # to several orgs, on a record filed under that fleet's partition until
    # an OTel export attributes its session to one of them.
    fleet_orgs: list[str] | None = None
    # What the sender called itself, for adapter 4 only. `service.name`, or
    # the agent/app attribute, or the event-name prefix -- a service
    # identifier and never content. Comma-joined when one group carried
    # more than one claim.
    #
    # Stored because `surface` is resolved at collect time. Without the
    # input to that decision, a record attributed to otel-unknown cannot be
    # repaired later: /stats holds only a counter, and nothing per record
    # says what the sender claimed to be.
    #
    # Written on EVERY adapter-4 record, not only unattributed ones. The
    # tokens that resolve a surface are substring matches and some are very
    # loose -- `doc` claims any name containing it -- so the failure this
    # has to survive is a future product being silently attributed to the
    # WRONG surface, which an only-on-unknown field cannot see.
    reported_as: str | None = None
    model: str | None = None
    body_bytes: int | None = None
    messages_total: int | None = None
    messages_scanned: int | None = None
    action: str = "allow"
    # What we WOULD have returned, when observe mode collapsed a deny.
    shadow_action: str | None = None
    reference_id: str | None = None
    # The frame type, for the inference hook: EVENT_TOOL_CALL, EVENT_OTHER,
    # or None for a prompt frame and for every record written before it.
    event: str | None = None
    scan_ms: float | None = None
    total_ms: float | None = None
    cache_hit: bool | None = None
    budget_exceeded: bool | None = None
    # Which detectors the budget dropped. Distinct from `budget_exceeded`,
    # which latches on elapsed time alone and is true even when no droppable
    # tier was configured. This is the coverage signal: a dropped tier means
    # the scan was shallower than the policy asked for, and on a findings
    # page that is indistinguishable from a clean scan unless it is recorded.
    tiers_dropped: list[str] = field(default_factory=list)
    # The build whose rules produced these findings. `schema_version` covers
    # the record's shape; this covers its meaning. A finding from before the
    # NHS rule was label-gated is not the same claim as one from after, and
    # without this the only way to tell them apart was to delete and rescan.
    build: str = ""
    # Adapter 2 only, set by the intake: on a clean allow tally row, the
    # number of clean Code hook allows the row stands for (store/tally.py).
    tally: int | None = None
    findings_count: int = 0
    findings: list[FindingRow] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    @property
    def org(self) -> str:
        """The partition this record belongs in. Never the real org id."""
        return self.tenant_hash or ORG_UNATTRIBUTED

    @property
    def is_inline(self) -> bool:
        """True when this control ran BEFORE the model saw the content.

        Only an inline control can deny: the inference hook holds the request
        until it answers, and the Code hook runs before a tool executes. The
        Compliance API reads transcripts after inference has already
        happened, so it has nothing left to prevent.
        """
        return self.source in (SOURCE_INFERENCE_HOOK, SOURCE_CODE_HOOK,
                               SOURCE_AGENT_SCAN)

    @property
    def effective_action(self) -> str:
        """The verdict an inline control reached, ignoring enforcement.

        A shadow deny is a deny for analysis: the policy decided to block and
        only enforcement differed. Meaningless for a post-hoc scan -- use
        `disposition` for anything that spans both.
        """
        return self.shadow_action or self.action

    @property
    def detected(self) -> bool:
        """Whether anything blocking-severity was found, regardless of what
        the control could do about it. A warning is a signal for the
        operator, not an exposure, so it is not a detection."""
        return any(f.severity == "block" for f in self.findings)

    @property
    def flagged(self) -> bool:
        """Whether anything was found at all, at any severity.

        Distinct from `detected` because the two answer different questions
        and conflating them produced a bad label: a post-hoc row carrying a
        hundred warn-severity NER findings rendered as CLEAN, which says the
        scan looked and found nothing when it looked and found plenty.
        `detected` stays the exposure question and drives the headline
        detection metric; this one drives the row label.
        """
        return bool(self.findings)

    @property
    def disposition(self) -> str:
        """What this control actually did, in its own terms.

        An inline control returns a verdict -- it allowed or it blocked. A
        post-hoc scan returns an observation, and it has three of them, not
        two: it found blocking-severity content, it found something worth a
        look, or it found nothing. Two states forced warn-only sessions into
        CLEAN and hid the entire NER tier behind a label that said the
        opposite of what happened.

        Collapsing post-hoc into the inline allow/deny column would separately
        imply the scan declined to block something, which it was never in a
        position to do.

        A deleted chat with nothing found is `deleted`, whether or not its
        messages could still be read: `tiers_dropped` says which.
        """
        if self.is_inline:
            return self.effective_action
        if self.detected:
            return "detected"
        if self.flagged:
            return "flagged"
        return "deleted" if self.deleted_at else "clean"

    @property
    def day(self) -> str:
        return self.observed_at[:10]

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str | bytes, *, strict: bool = False,
                  untimed: bool = False) -> VerdictRecord:
        """Parse one stored or shipped line.

        `strict` raises ValueError on any field whose JSON type does not
        match its declaration. Otherwise a mistyped field is repaired: a
        string field becomes `str(value)`, a list of strings has each item
        made a string, and a number or bool falls back to its default.
        A line with no observed_at is stamped with the current time, or with
        "" when `untimed` is set.
        """
        raw = _record_json(line)
        if not isinstance(raw, dict):
            raise ValueError("a record is a JSON object")
        if untimed:
            raw.setdefault("observed_at", "")
        findings_raw = raw.pop("findings", []) or []
        if not isinstance(findings_raw, list):
            if strict:
                raise ValueError("findings is not a list")
            findings_raw = []
        findings = [_finding_from_raw(f, strict) for f in findings_raw]
        # Tolerate unknown fields from a newer writer rather than crash the
        # dashboard: the store is append-only and old objects are immutable,
        # so readers will always meet records they were not compiled against.
        known = {k: _typed(cls, k, v, strict) for k, v in raw.items()
                 if k in cls.__dataclass_fields__}
        return cls(findings=findings, **known)


# The largest magnitude a stored number may have: every int up to it is
# exact as a float, so formatting one never raises OverflowError.
_NUMBER_LIMIT = 2**53


def _is_int(value) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            and -_NUMBER_LIMIT <= value <= _NUMBER_LIMIT)


def _is_number(value) -> bool:
    return (_is_int(value)
            or (isinstance(value, float) and math.isfinite(value)
                and -_NUMBER_LIMIT <= value <= _NUMBER_LIMIT))


_CHECKS = {
    "str": lambda v: isinstance(v, str),
    "int": _is_int,
    "float": _is_number,
    "bool": lambda v: isinstance(v, bool),
    "list[str]": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
}


def _field_kinds(cls) -> dict[str, tuple[str, bool]]:
    """Each field's base type name, and whether it accepts None."""
    kinds = {}
    for f in fields(cls):
        if f.name == "findings":
            continue
        kind, _, rest = str(f.type).partition(" | ")
        if kind not in _CHECKS or rest not in ("", "None"):
            raise TypeError(f"{cls.__name__}.{f.name} has no type check for {f.type}")
        kinds[f.name] = (kind, rest == "None")
    return kinds


_KINDS = {VerdictRecord: _field_kinds(VerdictRecord),
          FindingRow: _field_kinds(FindingRow)}


def _typed(cls, name: str, value, strict: bool):
    """`value` if it fits field `name` of `cls`, else repaired or refused.

    The ValueError names the field and never carries the value."""
    kind, optional = _KINDS[cls][name]
    if (value is None and optional) or _CHECKS[kind](value):
        return value
    if strict:
        raise ValueError(f"{cls.__name__}.{name} is not {kind}")
    if kind == "str":
        if value is None:
            raise ValueError(f"{cls.__name__}.{name} is required")
        return str(value)
    if kind == "list[str]":
        return [str(x) for x in value] if isinstance(value, list) else []
    default = cls.__dataclass_fields__[name]
    if default.default is not MISSING:
        return default.default
    if default.default_factory is not MISSING:
        return default.default_factory()
    raise ValueError(f"{cls.__name__}.{name} is required")


def _finding_from_raw(raw, strict: bool) -> FindingRow:
    if not isinstance(raw, dict):
        raise ValueError("a finding is a JSON object")
    return FindingRow(**{k: _typed(FindingRow, k, v, strict) for k, v in raw.items()
                         if k in FindingRow.__dataclass_fields__})


_ISO_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")


def _iso_day(value) -> str | None:
    """`value[:10]` if it is a real YYYY-MM-DD date, else None."""
    head = value[:10] if isinstance(value, str) else ""
    if not _ISO_DAY.fullmatch(head):
        return None
    try:
        date.fromisoformat(head)
    except ValueError:
        return None
    return head


@dataclass
class DenialRecord:
    """An `inference_hooks_request_denied` activity from the Activity Feed.

    Stored separately because it comes from Anthropic's records rather than
    ours, and the join to our own verdicts is the interesting part.
    """

    activity_id: str
    created_at: str
    reference_id: str | None = None
    actor_hash: str | None = None
    # Anthropic's id for the denied request, the frame's own `request_id`,
    # and the frame type that was denied, `prompt` or `tool_call`. None on
    # a denial stored before they were read; a None `event` is a prompt.
    request_id: str | None = None
    event: str | None = None
    # Added with the org partition so denials land beside the verdicts they
    # join to. Populated when adapter 3 knows which org it scanned;
    # otherwise a denial partitions as unattributed.
    tenant_hash: str | None = None
    observed_at: str = field(default_factory=utcnow)
    schema_version: int = SCHEMA_VERSION

    @property
    def day(self) -> str:
        """The date of `created_at`; if that is not a date, of `observed_at`;
        failing both, today in UTC."""
        return (_iso_day(self.created_at) or _iso_day(self.observed_at)
                or datetime.now(UTC).strftime("%Y-%m-%d"))

    @property
    def org(self) -> str:
        return self.tenant_hash or ORG_UNATTRIBUTED

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str | bytes) -> DenialRecord:
        raw = _record_json(line)
        known = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
        return cls(**known)


RESET_MARKER = "markers/stats_reset"
# Request ids omitted from the statistics, one per line. A reset moves the
# floor and hides everything before it, including real findings; this omits
# named frames and nothing else. Deliberate bait pasted during a demo is the
# case it exists for: it is a real record of a real evaluation, it belongs in
# the event log, and it has no business in a deny rate someone reads as the
# organization's.
EXCLUDE_MARKER = "markers/excluded_requests"


class Store(Protocol):
    """Append-only record store.

    Writes are batched and must never raise into a caller on the verdict
    path -- adapter 1 calls this from a background thread and a storage
    outage must not become a webhook failure.
    """

    def write_verdicts(self, records: Sequence[VerdictRecord]) -> int: ...
    def write_denials(self, records: Sequence[DenialRecord]) -> int: ...
    # `orgs` holds pseudonyms, and None means every org. A set rather than
    # one value because a viewer can be entitled to several. A backend is
    # expected to prune on the partition rather than filter after reading:
    # filtering afterwards still downloads another org's data, which is the
    # difference between a partition and a WHERE clause.
    # `sources`, where given, limits the read to those `source=` partitions.
    # Readers call it through `store.attribution.read_sources`, which filters
    # after reading for a backend that does not take it.
    def read_verdicts(
        self, since: str | None = None, orgs: Collection[str] | None = None,
        sources: Collection[str] | None = None,
    ) -> Iterator[VerdictRecord]: ...
    def read_denials(
        self, since: str | None = None, orgs: Collection[str] | None = None
    ) -> Iterator[DenialRecord]: ...
    # Verdicts grouped by partition day, newest day first, from `since` to
    # `until` (both days, inclusive). Each group's objects are fetched only
    # when its records are iterated, so a reader that stops between groups
    # fetches nothing more. A day of None holds objects with no `date=`.
    def read_verdict_days(
        self, since: str | None = None, orgs: Collection[str] | None = None,
        until: str | None = None,
    ) -> Iterator[tuple[str | None, Iterator[VerdictRecord]]]: ...
    def describe(self) -> dict[str, Any]: ...

    # Statistics reset. Writes a timestamp marker; readers ignore anything
    # observed before it. Deliberately not a delete: the records stay, so a
    # reset is reversible and an audit trail is never destroyed by someone
    # wanting a clean dashboard.
    def set_reset_marker(self, when: str) -> None: ...
    def get_reset_marker(self) -> str | None: ...
    def set_excluded(self, request_ids: Sequence[str]) -> None: ...
    def get_excluded(self) -> set[str]: ...

    # Small named blobs that must outlive a process. The ingest cursor is
    # the reason: it was written to the container filesystem, and a
    # scheduled job's replica is destroyed when the pass finishes, so every
    # run re-walked the same window.
    #
    # Deliberately not a third pair of marker methods. A cursor is not a
    # marker: it is per-org, it is read back as bytes the caller parses,
    # and a second org needing its own is normal rather than exceptional.
    #
    # `name` is a flat key, not a path. A backend must reject anything that
    # could escape its own namespace -- see `safe_state_name`.
    def put_state(self, name: str, blob: bytes) -> None: ...
    def get_state(self, name: str) -> bytes | None: ...

    # The runtime overrides object (docs/design/overrides.md). `read_control`
    # returns absent only for an object that is not there and raises
    # StoreReadError for anything else. `write_control` creates the object
    # when `if_etag` is None and otherwise replaces it only while it still
    # has that etag; a lost race raises StoreConflict.
    def read_control(self) -> ControlRead: ...
    def write_control(self, body: bytes, if_etag: str | None) -> None: ...

    # Audit records under AUDIT_PREFIX. `put_audit` creates and never
    # replaces: a name that exists raises StoreConflict. `list_audit()`
    # lists every record; with `day`, only that day's, and with `leaf` too,
    # only those whose file name starts with it (`audit_scope`).
    # `audit_days` lists the YYYY-MM-DD partitions, oldest first.
    # `audit_modified` is the store's last-modified time of a record, and
    # raises StoreReadError for one that is absent or has none.
    def put_audit(self, name: str, body: bytes) -> None: ...
    def get_audit(self, name: str) -> bytes | None: ...
    def audit_modified(self, name: str) -> datetime: ...
    def list_audit(self, day: str | None = None, leaf: str = "") -> list[str]: ...
    def audit_days(self) -> list[str]: ...


STATE_PREFIX = "state"
AUDIT_PREFIX = "audit/runtime-overrides"

_AUDIT_NAME = re.compile(r"\d{4}-\d{2}-\d{2}/[0-9A-Za-z][0-9A-Za-z._-]{0,127}\.json")
AUDIT_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_AUDIT_LEAF = re.compile(r"(?:[0-9A-Za-z][0-9A-Za-z._-]{0,127})?")


class StoreReadError(Exception):
    """A read that failed for any reason other than the object being absent."""


class StoreConflict(Exception):
    """A conditional write refused because the object changed or exists."""


class StoreForbidden(Exception):
    """A write the store's credentials are not allowed to make: a 403."""


@dataclass(frozen=True)
class ControlRead:
    """What `read_control` found: `absent`, or `ok` with the bytes and etag."""

    status: str
    body: bytes | None = None
    etag: str | None = None


ABSENT = ControlRead("absent")


def safe_audit_name(name: str) -> str:
    """`YYYY-MM-DD/<file>.json`, and nothing that could leave AUDIT_PREFIX."""
    if not isinstance(name, str) or not _AUDIT_NAME.fullmatch(name) or ".." in name:
        raise ValueError(f"audit name must be YYYY-MM-DD/<file>.json, got {name!r}")
    return name


def audit_scope(day: str | None, leaf: str = "") -> str:
    """`day/leaf`, the part of an audit name a scoped `list_audit` lists
    under; "" for every record. ValueError for a day that is not YYYY-MM-DD,
    a leaf that could not begin an audit file name, or a leaf with no day."""
    if day is None:
        if leaf:
            raise ValueError("an audit leaf needs a day")
        return ""
    if not isinstance(day, str) or not AUDIT_DAY.fullmatch(day):
        raise ValueError(f"audit day must be YYYY-MM-DD, got {day!r}")
    if not isinstance(leaf, str) or not _AUDIT_LEAF.fullmatch(leaf):
        raise ValueError(f"audit leaf {leaf!r} cannot begin an audit file name")
    return f"{day}/{leaf}"


def audit_names(store: Store, leaf: str | Callable[[str], str] = "", *,
                newest_first: bool = False) -> Iterator[str]:
    """Audit names day by day, each day listed only when reached. `leaf`
    is a leaf prefix, or a function of the day giving one."""
    days = store.audit_days()
    for day in reversed(days) if newest_first else days:
        names = store.list_audit(day, leaf(day) if callable(leaf) else leaf)
        yield from reversed(names) if newest_first else names


def verdict_from_log_row(row: dict[str, Any], salt: str = "") -> VerdictRecord:
    """Build a record from adapter 1's existing timing/log row.

    Reuses the row the server already assembles for the CSV and the
    structured log, so the sink adds no new extraction logic and cannot
    drift from what is logged.
    """
    return VerdictRecord(
        source=SOURCE_INFERENCE_HOOK,
        request_id=row.get("request_id") or None,
        surface=row.get("source_application") or None,
        tenant_hash=pseudonym(row.get("tenant_id"), salt, "org"),
        model=row.get("model") or None,
        body_bytes=_int(row.get("body_bytes")),
        messages_total=_int(row.get("messages_total")),
        messages_scanned=_int(row.get("messages_scanned")),
        action=row.get("action") or "allow",
        shadow_action=row.get("shadow_action"),
        reference_id=row.get("reference_id"),
        event=row.get("event") or None,
        scan_ms=_float(row.get("scan_ms")),
        total_ms=_float(row.get("total_ms")),
        cache_hit=bool(row.get("cache_hit")),
        budget_exceeded=bool(row.get("budget_exceeded")),
        tiers_dropped=[str(x) for x in (row.get("tiers_dropped") or [])],
        build=str(row.get("build") or ""),
        findings_count=_int(row.get("findings_count")) or 0,
    )


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return None


def partition_path(
    prefix: str,
    source: str,
    day: str,
    instance: str,
    seq: int,
    org: str | None = None,
) -> str:
    """`verdicts/source=.../org=.../date=.../<instance>-<seq>.jsonl`

    Hive-style partitioning so a reader can prune by source, org and date
    without opening anything, and each writer instance owns its own objects.

    `org` is the pseudonym, never the real organization id: the store stays
    readable by someone who should not learn which customers exist, and the
    path is as public as the object it names.

    Raises ValueError for a component that could name a different path:
    empty, `.` or `..`, containing `/`, `\\` or a control character, or
    with leading or trailing whitespace.
    """
    org = org or ORG_UNATTRIBUTED
    for what, value in (("prefix", prefix), ("source", source), ("org", org),
                        ("day", day), ("instance", instance)):
        _check_component(what, value)
    return (
        f"{prefix}/source={source}/org={org}"
        f"/date={day}/{instance}-{seq:06d}.jsonl"
    )


def _check_component(what: str, value: str) -> None:
    if (not isinstance(value, str) or value in ("", ".", "..")
            or "/" in value or "\\" in value or value != value.strip()
            or any(ord(c) < 0x20 or ord(c) == 0x7f for c in value)):
        raise ValueError(f"partition {what} {value!r} is not a single path component")


def path_segment(name: str, key: str) -> str | None:
    """Read a Hive-style `key=value` segment out of a partition path.

    Returns None when the segment is absent, which is how a pre-multi-org
    object reports its org -- the caller decides what that means rather than
    this silently inventing a value.
    """
    prefix = f"{key}="
    for segment in name.split("/"):
        if segment.startswith(prefix):
            return segment[len(prefix):]
    return None


def _is_component(value) -> bool:
    try:
        _check_component("org", value)
    except ValueError:
        return False
    return True


Level = Callable[[str], tuple[Sequence[str], Sequence[str]]]
Tree = Callable[[str], Iterable[str]]


def partition_keys(
    list_level: Level,
    list_tree: Tree,
    root: str,
    since: str | None = None,
    orgs: Collection[str] | None = None,
    until: str | None = None,
    sources: Collection[str] | None = None,
) -> Iterator[str]:
    """The keys under `root` that a read for `since` and `orgs` needs, sorted.
    With `until`, only `date=` partitions on or before its day.

    `list_level(prefix)` returns `(prefixes, keys)` one level below
    `prefix`, each child prefix ending in `/`; `list_tree(prefix)` returns
    every key below it. Names are full, starting with `root`.

    Walks `source=`, then `org=`, then `date=`: an org-scoped read lists
    only under `org=<o>/` for each entitled org, and a read with `since`
    lists recursively only the `date=` partitions on or after it. Without
    `orgs` the org values come from a delimited listing of each source;
    without `since` an org's partition is listed whole. A `date=` directly
    under a source is the layout from before the org partition and reads as
    ORG_UNATTRIBUTED. Anything outside this shape is listed whole and kept
    by its name segments, as every key emitted is.

    ANY_FLEET in `orgs` adds every fleet's pending partition (`org=fleet-*`),
    found by listing each source. With `sources`, only those `source=`
    partitions are walked.
    """
    fleets = orgs is not None and ANY_FLEET in orgs
    if orgs is not None:
        orgs = {o for o in orgs if o != ANY_FLEET and _is_component(o)}
        if not orgs and not fleets:
            return
    day = since[:10] if since else None
    last = until[:10] if until else None
    legacy = orgs is None or ORG_UNATTRIBUTED in orgs

    def org_wanted(value: str) -> bool:
        return orgs is None or value in orgs or (fleets and is_fleet_partition(value))

    def wanted(key: str) -> bool:
        rel = key[len(root):]
        when = path_segment(rel, "date")
        if when and ((day and when < day) or (last and when > last)):
            return False
        if sources is not None and path_segment(rel, "source") not in sources:
            return False
        return org_wanted(path_segment(rel, "org") or ORG_UNATTRIBUTED)

    def tree(prefix: str) -> Iterator[str]:
        yield from (k for k in sorted(list_tree(prefix)) if wanted(k))

    def visit(parent: str, child: Callable[[str, str, str], Iterator[str]]) -> Iterator[str]:
        prefixes, keys = list_level(parent)
        rolled = {p for p in prefixes if p != parent}
        for name in sorted(rolled | set(keys)):
            if name in rolled:
                segment, _, value = name[len(parent):-1].partition("=")
                yield from child(name, segment, value)
            elif wanted(name):
                yield name

    def dated(prefix: str, value: str) -> Iterator[str]:
        if (day is None or value >= day) and (last is None or value <= last):
            yield from tree(prefix)

    def in_org(prefix: str) -> Iterator[str]:
        if day is None and last is None:
            yield from tree(prefix)
            return
        yield from visit(prefix, lambda name, segment, value: (
            dated(name, value) if segment == "date" else tree(name)))

    def in_source(prefix: str) -> Iterator[str]:
        if not legacy:
            named = set(orgs or ())
            if fleets:
                prefixes, _ = list_level(prefix)
                for name in prefixes:
                    segment, _, value = name[len(prefix):-1].partition("=")
                    if segment == "org" and is_fleet_partition(value):
                        named.add(value)
            for org in sorted(named):
                yield from in_org(f"{prefix}org={org}/")
            return

        def child(name: str, segment: str, value: str) -> Iterator[str]:
            if segment == "org":
                return in_org(name) if org_wanted(value) else iter(())
            if segment == "date":
                return dated(name, value)
            return tree(name)
        yield from visit(prefix, child)

    def top(name: str, segment: str, value: str) -> Iterator[str]:
        if segment != "source":
            return tree(name)
        return in_source(name) if sources is None or value in sources else iter(())

    yield from visit(root, top)


def by_day_newest_first(keys: Iterable[str], root: str) -> list[tuple[str | None, list[str]]]:
    """`keys` grouped by their `date=` segment, newest day first. Keys with
    no date segment come first, under None: they can hold any day."""
    groups: dict[str | None, list[str]] = {}
    for key in keys:
        groups.setdefault(path_segment(key[len(root):], "date"), []).append(key)
    days = sorted((d for d in groups if d is not None), reverse=True)
    return [(d, sorted(groups[d])) for d in ([None] if None in groups else []) + days]


class VerdictDay:
    """One partition day's verdict objects in key order, each fetched only
    when it is read. Iterating yields the day's records, as
    `read_verdict_days` always has; `objects(start)` yields (key, records)
    for each object from the first key >= `start`. Keys are relative to
    `root`, and a record's index in its object's list is its line."""

    def __init__(self, keys: Iterable[str], fetch: Callable[[str], bytes], root: str = ""):
        self.keys = sorted(k[len(root):] for k in keys)
        self._fetch = fetch
        self._root = root

    def __iter__(self) -> Iterator[VerdictRecord]:
        for _, records in self.objects():
            yield from records

    def objects(self, start: str = "") -> Iterator[tuple[str, list[VerdictRecord]]]:
        for key in self.keys_from(start):
            yield key, self.read(key)

    def keys_from(self, start: str) -> list[str]:
        """The keys from the first one >= `start`. `start` is only compared,
        so a key that is gone, or never existed, places the same way."""
        return self.keys[bisect_left(self.keys, start):]

    def read(self, key: str) -> list[VerdictRecord]:
        """The records of `key`, which must be one of `keys`."""
        return verdict_lines(self._fetch(self._root + key))

    def read_matching(self, key: str, needles: Sequence[bytes]
                      ) -> tuple[list[tuple[int, VerdictRecord]], int, int]:
        """`(rows, lines, size)` for `key`: each record on a line holding
        every one of `needles` with its line's index, the object's number of
        non-empty lines, and its size in bytes. A line without a needle is
        not parsed. A subclass that overrides `read` and not this gets every
        record of `read`, unfiltered, with size 0."""
        if type(self).read is not VerdictDay.read:
            records = self.read(key)
            return list(enumerate(records)), len(records), 0
        blob = self._fetch(self._root + key)
        return matching_lines(blob, needles), _line_count(blob), len(blob)


def verdict_lines(blob: bytes | str) -> list[VerdictRecord]:
    """The verdicts in one object. A line that does not parse, such as a
    torn final line, is skipped; one with no observed_at has "" there."""
    out = []
    for line in iter_json_lines(blob):
        try:
            out.append(VerdictRecord.from_json(line, untimed=True))
        except (ValueError, TypeError):
            continue
    return out


def matching_lines(blob: bytes | str, needles: Sequence[bytes]
                   ) -> list[tuple[int, VerdictRecord]]:
    """`(index, record)` for each non-empty line of `blob` holding every one
    of `needles`, indexed among the non-empty lines. A line that does not
    parse is skipped."""
    raw = blob if isinstance(blob, bytes) else blob.encode("utf-8")
    if any(n not in raw for n in needles):
        return []
    out = []
    for index, line in enumerate(ln for ln in raw.splitlines() if ln.strip()):
        if all(n in line for n in needles):
            try:
                out.append((index, VerdictRecord.from_json(line.decode("utf-8", "replace"),
                                                           untimed=True)))
            except (ValueError, TypeError):
                continue
    return out


def _line_count(blob: bytes | str) -> int:
    raw = blob if isinstance(blob, bytes) else blob.encode("utf-8")
    return sum(1 for ln in raw.splitlines() if ln.strip())


def iter_json_lines(blob: bytes | str) -> Iterable[str]:
    text = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield line


def _record_json(line: str | bytes) -> Any:
    """`json.loads(line)`, raising ValueError for nesting past the recursion
    limit."""
    try:
        return json.loads(line)
    except RecursionError:
        raise ValueError("a record nested too deeply") from None
