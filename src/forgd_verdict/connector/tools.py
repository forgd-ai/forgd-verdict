"""The connector's tools: read-only views over the findings store.

Every number comes from `store.views` and `dashboard.topology`, the code the
dashboard renders from. Each call re-derives the caller from its verified
token, takes the orgs they may read from `Entitlements.allowed`, and reads
through `ScopedStore`, which drops any row outside those orgs whatever the
backend returned.

Nothing returned is matched content. Findings carry a detector, a locator
and the first `DIGEST_CHARS` of the salted digest.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from ..dashboard.auth import AuthConfig, AuthError
from ..dashboard.topology import (
    Watch,
    compliance_view,
    control_points,
    heartbeats,
    infer_configured,
    surface_states,
)
from ..entitlements import Entitlements, Forbidden, GroupsUnavailable, Principal
from ..orgregistry import partition_kind
from ..policy import is_intake_client_name
from ..store.attribution import Fleets, attributed, policy_fleets, warn_unresolved_fleets
from ..store.base import (
    ORG_UNATTRIBUTED,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    SOURCE_MANAGED_SCAN,
    SOURCES,
    DenialRecord,
    FindingRow,
    VerdictDay,
    VerdictRecord,
    is_fleet_partition,
    source_rank,
    visible,
    writer_class,
)
from ..store.query import effective_since, normalize_surface, preferred_observation
from ..store.views import (
    WINDOWS,
    event_page,
    read_summary,
    summary_payload,
    window_to_since,
)

Window = Literal["24h", "7d", "30d"]
Action = Literal["all", "deny"]

FINDINGS_LIMIT_DEFAULT = 50
FINDINGS_LIMIT_MAX = 200
DENIALS_LIMIT_DEFAULT = 50
DENIALS_LIMIT_MAX = 200
SUMMARY_DETECTORS_MAX = 50
COVERAGE_SURFACES_MAX = 100
SURFACES_MAX = 100
ORGS_MAX = 100
ROW_FINDINGS_MAX = 20
RECORD_FINDINGS_MAX = 100
DIGEST_CHARS = 12
RECORD_WINDOW = "30d"
TOPOLOGY_WINDOW = "24h"
ARG_MAX_CHARS = 128

_ORG = re.compile(r"^(org|workspace)_[0-9a-f]{10}\Z")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}\Z")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

TOOL_NAMES = ("summary", "coverage", "findings", "record", "reconciliation", "topology")


class _ScopedDay(VerdictDay):
    """`day` holding only the rows visible to `orgs`, each object still
    fetched only when it is read. `dropped` counts the rows left out."""

    def __init__(self, day: VerdictDay, orgs: frozenset[str]):
        self.keys = day.keys
        self._day = day
        self._orgs = orgs
        self.dropped = 0

    def read(self, key: str) -> list[VerdictRecord]:
        rows = self._day.read(key)
        kept = [r for r in rows if visible(r, self._orgs)]
        self.dropped += len(rows) - len(kept)
        return kept

    def read_matching(self, key: str, needles):
        rows, lines, size = self._day.read_matching(key, needles)
        kept = [(i, r) for i, r in rows if visible(r, self._orgs)]
        self.dropped += len(rows) - len(kept)
        return kept, lines, size


class ScopedStore:
    """A store whose reads hold only rows visible to `orgs`. None means
    every org.

    Multi-org fleet records are attributed first (`store.attribution`), and
    only the fleet partitions `fleets` makes readable for `orgs` are read.
    The backend is asked to prune by partition and the rows are filtered
    again here, so a backend that prunes wrongly still cannot hand over
    another org's rows.
    """

    attributed = True

    def __init__(self, store: Any, orgs: frozenset[str] | None, fleets: Fleets = None):
        self._store = attributed(store, fleets)
        self.orgs = orgs

    def read_verdicts(self, since: str | None = None,
                      orgs: Collection[str] | None = None) -> Iterator[VerdictRecord]:
        for r in self._store.read_verdicts(since, self.orgs):
            if visible(r, self.orgs):
                yield r

    def read_verdict_days(self, since: str | None = None,
                          orgs: Collection[str] | None = None, until: str | None = None,
                          sources: Collection[str] | None = None,
                          ) -> Iterator[tuple[str | None, Iterator[VerdictRecord]]]:
        for day, records in self._store.read_verdict_days(since, self.orgs, until,
                                                          sources):
            if self.orgs is None:
                yield day, records
            elif isinstance(records, VerdictDay):
                yield day, _ScopedDay(records, self.orgs)
            else:
                yield day, (r for r in records if visible(r, self.orgs))

    def read_denials(self, since: str | None = None,
                     orgs: Collection[str] | None = None) -> Iterator[DenialRecord]:
        for d in self._store.read_denials(since, self.orgs):
            if self.orgs is None or d.org in self.orgs:
                yield d

    def describe(self) -> dict[str, Any]:
        return self._store.describe()

    def get_excluded(self) -> set[str]:
        getter = getattr(self._store, "get_excluded", None)
        return getter() if callable(getter) else set()


@dataclass
class Reader:
    """What the tools read from and whom they answer to."""

    store: Any
    auth: AuthConfig
    entitlements: Entitlements = field(default_factory=Entitlements)
    org_labels: Mapping[str, str] = field(default_factory=dict)
    configured: dict[str, bool] | None = None
    watch: Watch = field(default_factory=Watch)
    scan_state_keys: list[str] = field(default_factory=list)
    # The runtime overrides reader, or None when they are off.
    overrides: Any = None
    # Adapter 3's orgs and partitions (topology.CompliancePlan), or None.
    compliance: Any = None
    # The fleet partitions and their orgs (store.attribution.Fleets). With
    # none, a scoped read reads no fleet partition.
    fleets: Fleets = None


def reader_from_policy(policy: Any, cfg: Any, store: Any) -> Reader:
    from ..dashboard.topology import compliance_plan, configured_from_policy, watch_from_policy
    from ..overrides import OverlaidStore, honoured_in, reader_for
    from ..overrides_signing import refuse_signing_key

    refuse_signing_key(policy.raw, "connector")

    configured = configured_from_policy(policy)
    policy.use_org_registry(store)
    warn_unresolved_fleets(policy, "connector")
    overrides = None
    if honoured_in(policy.raw, "connector"):
        overrides = reader_for(policy.raw, store, "connector")
        overrides.refresh()
        store = OverlaidStore(store, overrides)
    return Reader(
        store=store, overrides=overrides, auth=cfg.auth, entitlements=cfg.entitlements,
        org_labels=policy.partition_labels(), configured=configured,
        watch=watch_from_policy(policy),
        scan_state_keys=policy.compliance_state_keys()
        if configured.get(SOURCE_COMPLIANCE_SCAN) else [],
        compliance=compliance_plan(policy),
        fleets=policy_fleets(policy),
    )


# --- argument checks ---------------------------------------------------------

def _tool_error(message: str) -> Exception:
    from mcp.server.mcpserver.exceptions import ToolError

    return ToolError(message)


def check_window(window: Any) -> str:
    if window not in WINDOWS:
        raise _tool_error(f"window must be one of {sorted(WINDOWS)}")
    return window


def _since(store: Any, window: str) -> str | None:
    return effective_since(window_to_since(check_window(window)),
                           store.describe().get("reset_at"))


def _limit(value: Any, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise _tool_error(f"limit must be an integer from 1 to {maximum}")
    return value


def _text(name: str, value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 0 < len(value) <= ARG_MAX_CHARS \
            or not value.isprintable():
        raise _tool_error(f"{name} must be printable text of 1 to {ARG_MAX_CHARS} "
                          "characters")
    return value


def _identifier(name: str, value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _IDENTIFIER.match(value):
        raise _tool_error(f"{name} must be 1 to 128 of A-Z a-z 0-9 _ . : -")
    return value


def _org_arg(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not (_ORG.match(value) or value == ORG_UNATTRIBUTED
                                          or is_intake_client_name(value)):
        raise _tool_error("org must be an org or workspace pseudonym (org_ or "
                          "workspace_, then ten hex digits), an intake client's name, "
                          f"or {ORG_UNATTRIBUTED!r}")
    return value


# --- the caller ---------------------------------------------------------------

class Caller:
    def __init__(self, reader: Reader, principal: Principal):
        self.reader = reader
        self.principal = principal

    def orgs(self, org: str | None) -> frozenset[str] | None:
        """The orgs this call reads: the caller's entitlement, narrowed to
        `org` when one is asked for."""
        ent = self.reader.entitlements
        try:
            allowed = ent.allowed(self.principal)
            if org is None:
                return allowed
            ent.check(self.principal, org)
        except GroupsUnavailable:
            raise _tool_error(
                "groups_unavailable: your sign-in token left out your group "
                "memberships, so which organizations you may read cannot be decided. "
                "Ask the operator to emit only the groups assigned to this "
                "application, or to use app roles.") from None
        except Forbidden:
            raise _tool_error("forbidden: you are not entitled to that organization") \
                from None
        return frozenset({org})

    def scoped(self, org: str | None) -> ScopedStore:
        return ScopedStore(self.reader.store, self.orgs(_org_arg(org)), self.reader.fleets)

    def org(self, pseudonym: str) -> dict[str, Any]:
        kind = partition_kind(pseudonym) or (
            "fleet_pending" if is_fleet_partition(pseudonym) else
            "client" if is_intake_client_name(pseudonym) else None)
        return {"org": pseudonym, "kind": kind,
                "label": self.reader.org_labels.get(pseudonym)}


async def current_caller(reader: Reader) -> Caller:
    """The caller, re-derived from the token the request was admitted with."""
    from mcp.server.auth.middleware.auth_context import get_access_token

    access = get_access_token()
    if access is None:
        raise _tool_error("unauthenticated")
    try:
        principal = await asyncio.to_thread(
            reader.auth.authenticate, {"authorization": f"Bearer {access.token}"})
    except AuthError:
        raise _tool_error("unauthenticated") from None
    if principal is None:  # pragma: no cover - config refuses every mode without one
        raise _tool_error("unauthenticated")
    return Caller(reader, principal)


# --- rows ---------------------------------------------------------------------

def _finding(f: FindingRow) -> dict[str, Any]:
    return {"detector": f.detector, "severity": f.severity, "locator": f.locator,
            "digest": (f.excerpt_hash or "")[:DIGEST_CHARS], "tool_name": f.tool_name}


def _record(caller: Caller, r: VerdictRecord, findings_max: int) -> dict[str, Any]:
    return {
        "observed_at": r.observed_at, "source": r.source, "writer": writer_class(r.source),
        "surface": normalize_surface(r.surface), **caller.org(r.org),
        "disposition": r.disposition, "action": r.action,
        "shadow_action": r.shadow_action, "reference_id": r.reference_id,
        "request_id": r.request_id, "session_id": r.session_id,
        "actor": r.actor_hash, "deleted_at": r.deleted_at,
        "tiers_dropped": list(r.tiers_dropped), "findings_count": r.findings_count,
        "findings": [_finding(f) for f in r.findings[:findings_max]],
        "findings_truncated": len(r.findings) > findings_max,
    }


def _capped(rows: list, limit: int) -> dict[str, Any]:
    return {"rows": rows[:limit], "truncated": len(rows) > limit, "limit": limit}


# --- tools --------------------------------------------------------------------

async def summary(caller: Caller, window: str = "7d", org: str | None = None) -> dict[str, Any]:
    store = caller.scoped(org)
    s = read_summary(store, _since(store, window), store.orgs)
    out = summary_payload(s, window)
    detectors = out["detectors"]
    out["detectors"] = [dict(d, surfaces=d["surfaces"][:SURFACES_MAX]) if isinstance(
        d.get("surfaces"), list) else d for d in detectors[:SUMMARY_DETECTORS_MAX]]
    out["truncated"] = len(detectors) > SUMMARY_DETECTORS_MAX
    out["limit"] = SUMMARY_DETECTORS_MAX
    surfaces = out["surfaces"]
    out["surfaces"] = surfaces[:SURFACES_MAX]
    out["surfaces_truncated"] = len(surfaces) > SURFACES_MAX
    orgs = [dict(caller.org(o), requests=n) for o, n in sorted(s.orgs.items())]
    out["orgs"] = orgs[:ORGS_MAX]
    out["orgs_truncated"] = len(orgs) > ORGS_MAX
    return out


async def coverage(caller: Caller, window: str = "7d", org: str | None = None) -> dict[str, Any]:
    store = caller.scoped(org)
    s = read_summary(store, _since(store, window), store.orgs)
    rows = [{
        "surface": r.surface, "requests": r.requests, "seen_by": r.seen_by,
        "inline": r.inline_coverage, "audit_only": not r.inline_coverage,
        "by_control_point": {
            "inference_hook": r.live, "compliance_scan": r.post_hoc,
            "code_hook": r.code_hook, "otel_collect": r.otel,
            "agent_scan": r.agent, "managed_scan": r.managed},
        "would_deny": r.would_deny, "detections": r.detections, "last_seen": r.last_seen,
    } for r in s.surfaces]
    return {"window": window, "surfaces": _capped(rows, COVERAGE_SURFACES_MAX)}


async def findings(caller: Caller, window: str = "7d", org: str | None = None,
                   surface: str | None = None, detector: str | None = None,
                   source: str | None = None, action: str = "all",
                   since: str | None = None,
                   limit: int = FINDINGS_LIMIT_DEFAULT) -> dict[str, Any]:
    limit = _limit(limit, FINDINGS_LIMIT_MAX)
    surface = _text("surface", surface)
    detector = _text("detector", detector)
    if source is not None and source not in SOURCES:
        raise _tool_error(f"source must be one of {list(SOURCES)}")
    if action not in ("all", "deny"):
        raise _tool_error("action must be 'all' or 'deny'")
    store = caller.scoped(org)
    start = _since(store, window)
    if since is not None:
        if not isinstance(since, str) or not _TIMESTAMP.match(since):
            raise _tool_error("since must be a UTC timestamp, YYYY-MM-DDTHH:MM:SSZ")
        if start and since < start:
            raise _tool_error("since is before the start of the window")
    def match(r: VerdictRecord) -> bool:
        return ((surface is None or normalize_surface(r.surface) == surface)
                and (detector is None or any(f.detector == detector for f in r.findings))
                and (since is None or (r.observed_at or "") >= since))

    page = event_page(store, since or start, store.orgs, source or "all", action,
                      match=match, limit=limit)
    records = page.records[:limit]
    rows = [_record(caller, r, ROW_FINDINGS_MAX) for r in records]
    out = {"window": window, "rows": rows,
           "truncated": len(page.records) > limit or page.before is not None,
           "limit": limit}
    out["next_since"] = records[0].observed_at if records else since
    return out


async def record(caller: Caller, reference_id: str | None = None,
                 session_id: str | None = None) -> dict[str, Any]:
    if (reference_id is None) == (session_id is None):
        raise _tool_error("give exactly one of reference_id or session_id")
    reference_id = _identifier("reference_id", reference_id)
    session_id = _identifier("session_id", session_id)
    store = caller.scoped(None)
    since = _since(store, RECORD_WINDOW)
    matches = [r for r in store.read_verdicts(since, store.orgs)
               if (reference_id and r.reference_id == reference_id)
               or (session_id and r.session_id == session_id)]
    if not matches:
        return {"found": False, "searched_window": RECORD_WINDOW}
    # By source precedence, then newest first within a source.
    matches.sort(key=lambda r: r.observed_at or "", reverse=True)
    matches.sort(key=lambda r: source_rank(r.source))
    top = matches[0]
    if session_id and top.source in (SOURCE_COMPLIANCE_SCAN, SOURCE_MANAGED_SCAN):
        # The observation the summary keeps for this session, so a later
        # scan that read less does not stand in for an earlier detection.
        top = preferred_observation(r for r in matches if r.source == top.source) or top
    newest: dict[str, VerdictRecord] = {}
    for r in matches:
        if r.source != top.source:
            newest.setdefault(r.source, r)
    out: dict[str, Any] = {
        "found": True, "searched_window": RECORD_WINDOW,
        "record": _record(caller, top, RECORD_FINDINGS_MAX),
        "other_sources": [_record(caller, r, ROW_FINDINGS_MAX) for r in newest.values()],
        "earlier_observations": len(matches) - 1,
    }
    if reference_id:
        denial = next((d for d in store.read_denials(since, store.orgs)
                       if d.reference_id == reference_id), None)
        out["denial"] = None if denial is None else {
            "activity_id": denial.activity_id, "created_at": denial.created_at,
            **caller.org(denial.org)}
    return out


async def reconciliation(caller: Caller, window: str = "7d", org: str | None = None,
                         limit: int = DENIALS_LIMIT_DEFAULT) -> dict[str, Any]:
    limit = _limit(limit, DENIALS_LIMIT_MAX)
    store = caller.scoped(org)
    since = _since(store, window)
    s = read_summary(store, since, store.orgs)
    counts = dict(summary_payload(s, window)["reconciliation"],
                  code_hook_withheld=s.reconciliation.code_hook_withheld,
                  post_hoc_only_findings=s.reconciliation.post_hoc_only_findings)
    references = {r.reference_id for r in store.read_verdicts(since, store.orgs)
                  if r.reference_id and r.source == SOURCE_INFERENCE_HOOK}
    denials = sorted((d for d in store.read_denials(since, store.orgs)
                      if not since or d.created_at >= since),
                     key=lambda d: d.created_at, reverse=True)
    rows = [{"activity_id": d.activity_id, "created_at": d.created_at,
             "reference_id": d.reference_id, **caller.org(d.org),
             "verdict_found": bool(d.reference_id and d.reference_id in references)}
            for d in denials]
    return {"window": window, "counts": counts, "denials": _capped(rows, limit)}


async def topology(caller: Caller, org: str | None = None) -> dict[str, Any]:
    store = caller.scoped(org)
    s = read_summary(store, _since(store, TOPOLOGY_WINDOW), store.orgs)
    reader = caller.reader
    # The scan cursors are per org and keyed by org id, which cannot be
    # matched to a pseudonym here, so a caller who sees only some orgs gets
    # no compliance heartbeat rather than one another org's cursor decides.
    configured = reader.configured
    if reader.compliance is not None:
        reason, beats, intervals = compliance_view(reader.compliance, reader.store, store.orgs)
        configured = {**(configured if configured is not None else infer_configured(s)),
                      SOURCE_COMPLIANCE_SCAN: reason}
    else:
        keys = reader.scan_state_keys if store.orgs is None else []
        beats, intervals = heartbeats(reader.store, keys)
    kw = {"watch": reader.watch, "heartbeats": beats, "intervals": intervals}
    points = control_points(s, configured, **kw)
    surfaces = surface_states(s, configured, **kw)
    return {
        "window": TOPOLOGY_WINDOW,
        "control_points": [{
            "source": p.source, "label": p.label, "state": p.state,
            "requests": p.requests, "last_seen": p.last_seen, "detail": p.detail,
            "overdue": p.overdue} for p in points],
        "surfaces": [{
            "surface": x.surface, "label": x.label, "state": x.state,
            "requests": x.requests, "detail": x.detail, "periodic": x.periodic}
            for x in surfaces[:SURFACES_MAX]],
        "surfaces_truncated": len(surfaces) > SURFACES_MAX,
    }


# --- registration ---------------------------------------------------------------

def _strict(arg_model: type) -> type:
    """The SDK's argument model, refusing names the tool does not take and
    values of the wrong type rather than coercing them."""
    from pydantic import ConfigDict

    return type(arg_model.__name__, (arg_model,), {
        "model_config": ConfigDict(**arg_model.model_config, extra="forbid", strict=True)})


def build_tools(reader: Reader) -> list[Any]:
    """The six tools, for `MCPServer(tools=...)`. Each is read-only, and an
    argument a tool does not take is refused rather than ignored."""
    from mcp.server.mcpserver.tools import Tool
    from mcp.types import ToolAnnotations

    read_only = ToolAnnotations(read_only_hint=True, destructive_hint=False,
                                idempotent_hint=True, open_world_hint=False)
    built: list[Any] = []

    def tool(name: str, description: str):
        def add(fn):
            t = Tool.from_function(fn, name=name, description=description,
                                   annotations=read_only)
            t.fn_metadata.arg_model = _strict(t.fn_metadata.arg_model)
            built.append(t)
            return fn
        return add

    @tool("summary", "Headline counts for a window: requests, deny rate, detection "
          "rate, surfaces, detectors and reconciliation totals.")
    async def summary_tool(window: Window = "7d", org: str | None = None) -> dict[str, Any]:
        return await summary(await current_caller(reader), window, org)

    @tool("coverage", "Surfaces by control point: which inline and post-hoc controls "
          "saw each surface, and which surfaces are audit-only.")
    async def coverage_tool(window: Window = "7d", org: str | None = None) -> dict[str, Any]:
        return await coverage(await current_caller(reader), window, org)

    @tool("findings", "Evaluated requests and scanned sessions, newest first, as the "
          f"dashboard's event log shows them. limit 1 to {FINDINGS_LIMIT_MAX}. Pass "
          "next_since back as since to fetch rows at or after it; rows at exactly "
          "that second come back again, so de-duplicate by request_id.")
    async def findings_tool(window: Window = "7d", org: str | None = None,
                            surface: str | None = None, detector: str | None = None,
                            source: str | None = None, action: Action = "all",
                            since: str | None = None,
                            limit: int = FINDINGS_LIMIT_DEFAULT) -> dict[str, Any]:
        return await findings(await current_caller(reader), window, org, surface,
                              detector, source, action, since, limit)

    @tool("record", f"One verdict by reference_id or session_id, searched over the "
          f"last {RECORD_WINDOW}, with its findings and any joined Activity Feed denial. "
          "`record` is the inference hook's row when there is one, then the other "
          "sources in order of trust; `other_sources` holds the newest row of each "
          "other source. A row whose `writer` is `intake_token` was shipped by a "
          "laptop or agent token and may have been written by anyone holding it.")
    async def record_tool(reference_id: str | None = None,
                          session_id: str | None = None) -> dict[str, Any]:
        return await record(await current_caller(reader), reference_id, session_id)

    @tool("reconciliation",
          "Live enforcement against post-hoc scanning: values seen post-hoc and "
          "never live, and Activity Feed denials joined by reference_id to the inference "
          "hook's verdicts. "
          f"limit 1 to {DENIALS_LIMIT_MAX}.")
    async def reconciliation_tool(window: Window = "7d", org: str | None = None,
                                  limit: int = DENIALS_LIMIT_DEFAULT) -> dict[str, Any]:
        return await reconciliation(await current_caller(reader), window, org, limit)

    @tool("topology", f"Which control points are delivering and which are late, over "
          f"the last {TOPOLOGY_WINDOW}.")
    async def topology_tool(org: str | None = None) -> dict[str, Any]:
        return await topology(await current_caller(reader), org)

    return built
