"""Which control points are still delivering, and which have gone quiet.

The question the dashboard could not answer at a glance: a control point
that stopped delivering looked exactly like a quiet week.

Three things here are judgement rather than mechanism, and each is the
reason a simpler version would be worse than nothing.

**One staleness threshold would be wrong per adapter.** They have
completely different expected cadences -- adapter 3 is a six-hourly cron,
adapter 1 is continuous while people are working. A flat "amber at an
hour" paints the audit job amber almost permanently and red whenever a
scheduled run slips, and a panel that is usually red is a panel people
stop reading.

**Three states look identical and only one is an alert.** Not configured,
configured-and-idle, configured-and-broken. Conflating them makes the
panel decorative; the third is the only one worth a colour that means
something.

**Nobody works at 03:00.** Quiet overnight is not a fault, so the live
adapters are only judged during a window when traffic is expected --
otherwise the panel is red every morning and the first thing anyone
learns is to ignore it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ..store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    SOURCE_MANAGED_SCAN,
    SOURCE_OTEL_COLLECT,
)
from ..store.query import newer

STATE_LIVE = "live"
STATE_IDLE = "idle"
STATE_LATE = "late"
STATE_OFF = "off"
# Configured somewhere in this deployment, but not for what is being viewed:
# the Compliance API for a Team workspace.
STATE_NA = "na"

NA_TEAM = "not applicable: a Team workspace has no Compliance API"
NA_SELECTION = "not applicable: the Compliance API does not cover this selection"
NA_NO_RUN = ("no run recorded: not applicable to a Team workspace; for an Enterprise "
             "org, check that the ingest job runs with its Compliance Access Key")

# Ordered as the data flows, not alphabetically: the three inbound
# adapters, then the one that only ever sees what already happened.
CONTROL_POINTS = (
    (SOURCE_INFERENCE_HOOK, "Inference hooks", "A1"),
    (SOURCE_CODE_HOOK, "Claude Code hook", "A2"),
    (SOURCE_OTEL_COLLECT, "OTel collector", "A4"),
    (SOURCE_COMPLIANCE_SCAN, "Compliance scan", "A3"),
)

# How late is late, per control point, in minutes.
#
# A1/A4 are continuous while people work, so a couple of hours of silence
# during the working day is worth showing. A2 is bursty -- one developer's
# session ends and nothing ships until the next -- so it gets a day. A3 is
# a cron: the default schedule is `0 */6 * * *`, and the threshold is two
# intervals plus slack, because one missed run is a slipped run and two is
# a broken job.
#
# A3's age is measured from its RUN MARKER, not from the records it
# wrote. Against the records this threshold was unreachable on a quiet
# org: a pass that scans nothing writes nothing, so the age would count
# time since the last org activity and on-time runs would read as an
# outage. See `compliance.scanner.last_run_at`.
LATE_AFTER_MIN = {
    SOURCE_INFERENCE_HOOK: 120,
    SOURCE_OTEL_COLLECT: 120,
    SOURCE_CODE_HOOK: 1440,
    # The FALLBACK, used until the job has run enough times to have
    # measured itself. 780 = two six-hour intervals plus an hour, which is
    # the chart default -- `tests/test_helm_chart.py` pins the two
    # together so our own drift is caught.
    SOURCE_COMPLIANCE_SCAN: 780,
    # Adapter 6 runs inside the same ingest job, on the same schedule.
    SOURCE_MANAGED_SCAN: 780,
}

# Two intervals plus slack, which is what 780 always meant. One missed run
# is a slipped run and two is a broken job.
LATE_AFTER_SLACK_MIN = 60

# A cadence below this makes the threshold hair-trigger and a panel that
# flickers is one nobody reads; above it, nothing useful is being watched.
MIN_DERIVED_LATE_MIN = 60
MAX_DERIVED_LATE_MIN = 14 * 24 * 60


def late_after_for(source: str, observed_interval_min: float | None = None) -> float:
    """How long before this control point counts as late.

    For the audit job this is DERIVED from the cadence the job measured
    for itself, not from a constant. The constant was 780 minutes because
    the chart ships `0 */6 * * *`, and nothing connected the two: a fork
    on a four-hourly cron kept a threshold that swallowed three missed
    runs, and one on a twelve-hourly cron went red on a single slipped
    one.
    """
    base = LATE_AFTER_MIN.get(source, 240)
    if source != SOURCE_COMPLIANCE_SCAN or not observed_interval_min:
        return base
    derived = 2 * observed_interval_min + LATE_AFTER_SLACK_MIN
    return max(MIN_DERIVED_LATE_MIN, min(MAX_DERIVED_LATE_MIN, derived))

# Only the continuous adapters are judged against the clock, and only
# inside a window when traffic is expected.
#
# IN UTC, AND THAT IS A DEFAULT SOMEONE ELSE INHERITS. A fork whose team
# works 09:00-17:00 in Los Angeles gets alerts through its evening and
# silence through its morning, which is worse than no window at all
# because it looks considered. So it is configuration, the default is
# stated in the detail text where an operator will see it, and a
# deployment that does not set it can at least tell that it did not.
DEFAULT_WORKING_HOURS = (7, 20)
CLOCK_WATCHED = (SOURCE_INFERENCE_HOOK, SOURCE_OTEL_COLLECT)


@dataclass(frozen=True)
class Watch:
    """When traffic is expected, and in whose clock."""

    start: int = DEFAULT_WORKING_HOURS[0]
    end: int = DEFAULT_WORKING_HOURS[1]
    # Minutes east of UTC. 0 is the default and is a GUESS about the
    # customer, which is why it is visible rather than buried.
    utc_offset_min: int = 0
    configured: bool = False

    def local_hour(self, now: datetime) -> float:
        shifted = now + timedelta(minutes=self.utc_offset_min)
        return shifted.hour + shifted.minute / 60.0

    def expecting(self, now: datetime, late_after_min: float) -> bool:
        """Is traffic expected right now?

        False for `late_after` minutes AFTER the window opens, not just
        outside it. At 07:00 a surface silent since 22:00 is nine hours
        stale and would go red the instant the window opened, before
        anybody has had the chance to send anything.
        """
        h = self.local_hour(now)
        if not (self.start <= h < self.end):
            return False
        return (h - self.start) * 60 >= late_after_min

    def describe(self) -> str:
        zone = "UTC" if not self.utc_offset_min else (
            f"UTC{self.utc_offset_min // 60:+d}")
        return f"{self.start:02d}:00-{self.end:02d}:00 {zone}"


def watch_from_policy(policy) -> Watch:
    raw = ((getattr(policy, "raw", {}) or {}).get("dashboard") or {}).get(
        "topology") or {}
    hours = raw.get("working_hours") or {}
    if not hours:
        return Watch()
    return Watch(
        start=int(hours.get("start", DEFAULT_WORKING_HOURS[0])),
        end=int(hours.get("end", DEFAULT_WORKING_HOURS[1])),
        utc_offset_min=int(hours.get("utc_offset_minutes", 0)),
        configured=True,
    )


@dataclass
class ControlPointState:
    source: str
    label: str
    short: str
    state: str
    requests: int
    last_seen: str
    detail: str
    # How far past its own threshold, as a multiple. 0 unless late. The
    # halo behind the core needs "late" and "way off" to look different,
    # and each control point's threshold is the only sensible unit --
    # thirteen hours is nothing for the audit job and a catastrophe for
    # the inference hook.
    overdue: float = 0.0

    @property
    def is_alert(self) -> bool:
        return self.state == STATE_LATE


def _parse(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _age_min(ts: str, now: datetime) -> float | None:
    seen = _parse(ts)
    if seen is None:
        return None
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    return (now - seen).total_seconds() / 60.0


def infer_configured(summary) -> dict[str, bool]:
    """A fallback for a Dashboard built without the policy.

    Anything that has delivered in this window is obviously configured.
    A1 and A2 are assumed present -- the server is why adapter 1 exists,
    and the hook needs no deployment so we cannot see it either way.

    Weaker than reading the policy, and deliberately so: it can say
    "configured and late" only for an adapter that has already written
    something, so it never invents an alert for a deployment that simply
    does not run that control point.
    """
    seen = set()
    for row in summary.surfaces:
        seen.update((row.last_seen_by_source or {}).keys())
    return {
        SOURCE_INFERENCE_HOOK: True,
        SOURCE_CODE_HOOK: True,
        SOURCE_OTEL_COLLECT: SOURCE_OTEL_COLLECT in seen,
        SOURCE_COMPLIANCE_SCAN: SOURCE_COMPLIANCE_SCAN in seen,
    }


def control_points(
    summary, configured: dict[str, bool] | None = None, *,
    now: datetime | None = None, watch: Watch | None = None,
    heartbeats: dict[str, str] | None = None,
    intervals: dict[str, float] | None = None,
) -> list[ControlPointState]:
    """One row per control point, with the state to paint it.

    `configured` says which adapters this deployment actually runs, and it
    comes from the policy rather than the store -- a surface nobody has
    set up has never written a record, which is indistinguishable from one
    that broke before it ever wrote.

    `heartbeats` maps a source to when it last RAN, for the one control
    point that can say so about itself. A record is evidence a control
    point ran, but the absence of a record is not evidence it did not,
    and adapter 3 spends most of its life with nothing to report. Passed
    in rather than read here so this stays a pure function of a summary.
    """
    now = now or datetime.now(UTC)
    watch = watch or Watch()
    if configured is None:
        configured = infer_configured(summary)
    seen: dict[str, str] = {}
    counts: dict[str, int] = {}
    for row in summary.surfaces:
        for source, ts in (row.last_seen_by_source or {}).items():
            if ts > seen.get(source, ""):
                seen[source] = ts
        for source, n in (
            (SOURCE_INFERENCE_HOOK, row.live),
            (SOURCE_COMPLIANCE_SCAN, row.post_hoc),
            (SOURCE_CODE_HOOK, row.code_hook),
            (SOURCE_OTEL_COLLECT, row.otel),
        ):
            if n:
                counts[source] = counts.get(source, 0) + n

    out: list[ControlPointState] = []
    for source, label, short in CONTROL_POINTS:
        reason = configured.get(source, False)
        if isinstance(reason, str):
            out.append(ControlPointState(source, label, short, STATE_NA, 0, "", reason))
            continue
        if not reason:
            out.append(ControlPointState(
                source, label, short, STATE_OFF, 0, "",
                "not configured here"))
            continue

        ts = seen.get(source, "")
        # `newer`, not an overwrite: the marker is normally the later of
        # the two, but a run that is mid-pass has written records without
        # yet saving its cursor, and taking the older of those would
        # report a job as stale while it is working.
        beat = (heartbeats or {}).get(source, "")
        if beat and newer(beat, ts):
            ts = beat
        n = counts.get(source, 0)
        age = _age_min(ts, now)
        late_after = late_after_for(source, (intervals or {}).get(source))
        # Checked BEFORE the nothing-received branch, which would otherwise
        # return LATE unconditionally: a configured adapter with an empty
        # window would go red at 03:00 -- the exact thing the window exists
        # to prevent.
        watched = source not in CLOCK_WATCHED or watch.expecting(now, late_after)

        if age is None:
            if watched:
                state, detail = STATE_LATE, "configured, nothing in this window"
            else:
                state, detail = STATE_IDLE, f"nothing yet · {watch.describe()}"
            out.append(ControlPointState(source, label, short, state, 0, "", detail))
            continue

        if age <= late_after:
            state, detail = STATE_LIVE, _ago(age)
        elif not watched:
            # Quiet outside working hours is not a fault. Saying so beats
            # a colour nobody can act on until morning.
            state, detail = STATE_IDLE, f"{_ago(age)} · {watch.describe()}"
        else:
            state, detail = STATE_LATE, f"{_ago(age)} · expected within {_dur(late_after)}"
        over = age / late_after if state == STATE_LATE and late_after else 0.0
        out.append(ControlPointState(source, label, short, state, n, ts,
                                     detail, over))
    return out


# How far past its threshold a control point has to be before the picture
# stops saying "late" and starts saying "broken". Two intervals late is a
# job that slipped; three times its whole allowance is one that stopped.
ALERT_OVERDUE = 3.0

HEALTH_OK = "ok"
HEALTH_WARN = "warn"
HEALTH_ALERT = "alert"


def core_health(points) -> str:
    """One verdict for the whole picture, for the halo behind the core.

    Reads the CONTROL POINTS rather than the surfaces. A surface is late
    when the product is quiet, which is a fact about how people are
    working; a control point is late when something we deployed has
    stopped delivering, which is a fact about us. Only the second should
    colour the core -- otherwise a quiet Friday afternoon paints the
    deployment red and the operator learns to ignore it.

    Off is not a fault: an adapter this deployment does not run cannot be
    behind. `control_points` has already applied the working-hours window
    and returned IDLE for anything merely quiet out of hours.
    """
    worst = HEALTH_OK
    for p in points:
        if p.state != STATE_LATE:
            continue
        if p.overdue >= ALERT_OVERDUE:
            return HEALTH_ALERT
        worst = HEALTH_WARN
    return worst


def _ago(minutes: float) -> str:
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{int(minutes)}m ago"
    if minutes < 48 * 60:
        return f"{int(minutes // 60)}h ago"
    return f"{int(minutes // 1440)}d ago"


def _dur(minutes: int) -> str:
    if minutes % 1440 == 0:
        return f"{minutes // 1440}d"
    if minutes % 60 == 0:
        return f"{minutes // 60}h"
    return f"{minutes}m"


def configured_from_policy(policy) -> dict[str, bool]:
    """Which adapters this deployment runs.

    From the policy, because the store cannot tell "never set up" from
    "set up and silent" -- both have written nothing.
    """
    raw = getattr(policy, "raw", {}) or {}
    otel = raw.get("otel") or {}
    return {
        # Adapter 1 is the reason the server exists; if this policy is
        # loaded by the dashboard, the deployment has one.
        SOURCE_INFERENCE_HOOK: True,
        # The hook needs no deployment, so it is configured wherever a
        # developer has installed it -- which we cannot see. Treated as
        # present, and idleness is the normal state.
        SOURCE_CODE_HOOK: True,
        SOURCE_OTEL_COLLECT: bool(otel.get("orgs")),
        SOURCE_COMPLIANCE_SCAN: bool(_compliance_entries(policy)),
    }


def _compliance_entries(policy) -> list[tuple[str, str, bool]]:
    """`(org id, state key, key resolvable here)` per org adapter 3 is set
    up to scan.

    A `compliance.orgs` entry counts when its id resolves. The single-org
    form counts when its org id or its key resolves; the built-in default
    key is a `$NAME` reference, so a policy that never mentions adapter 3
    does not count.
    """
    import os

    from ..models import env_or_literal, usable_secret

    compliance = (getattr(policy, "raw", {}) or {}).get("compliance") or {}
    if not isinstance(compliance, dict):
        return []
    entries = [o for o in (compliance.get("orgs") or []) if isinstance(o, dict)]
    multi = bool(entries)
    if not multi:
        entries = [{"id": compliance.get("org_id"), "api_key": compliance.get("api_key"),
                    "state_path": compliance.get("state_path")}]
    out = []
    for entry in entries:
        org_id = str(env_or_literal(entry.get("id")) or "")
        key_here = bool(usable_secret(env_or_literal(entry.get("api_key"))))
        if not org_id and (multi or not key_here):
            continue
        state_key = os.path.basename(policy._state_path_for(entry, org_id)) \
            or "compliance-state.json"
        out.append((org_id, state_key, key_here))
    return out


@dataclass(frozen=True)
class ComplianceOrg:
    state_key: str
    # The org's store partition; None when it cannot be resolved here.
    partition: str | None
    key_here: bool


@dataclass(frozen=True)
class CompliancePlan:
    """Which partitions adapter 3 scans, and which orgs it cannot."""

    orgs: tuple[ComplianceOrg, ...] = ()
    # Partitions of `orgs:` entries with no compliance org: Team workspaces.
    team: frozenset[str] = frozenset()


@dataclass(frozen=True)
class CursorReader:
    """A pulling reader whose cursor the pipeline panel watches."""

    reader: str
    name: str
    state_key: str
    # Days after which what it has not read is gone; None when unknown.
    limit_days: int | None
    # The store partition it scans; None when it cannot be resolved here.
    partition: str | None


def cursor_readers(policy, plan: CompliancePlan, labels: dict[str, str]) -> list[CursorReader]:
    """Adapter 3's orgs, judged against `compliance.retention_days`, and each
    Managed Agents workspace, against its `window_days`. `labels` maps a
    partition to the org label the dashboard shows."""
    raw = getattr(policy, "raw", {}) or {}
    compliance = raw.get("compliance") or {}
    retention = compliance.get("retention_days") if isinstance(compliance, dict) else None
    out = [CursorReader("compliance", labels.get(o.partition or "", f"org {i + 1}"),
                        o.state_key, retention, o.partition)
           for i, o in enumerate(plan.orgs)]
    managed = raw.get("managed_agents") or {}
    window = int(managed.get("window_days", 30)) if isinstance(managed, dict) else 30
    for ws in (managed.get("workspaces") or []) if isinstance(managed, dict) else []:
        if isinstance(ws, dict) and ws.get("key"):
            key = str(ws["key"])
            partition = policy.workspace_pseudonym(key) if hasattr(
                policy, "workspace_pseudonym") else None
            out.append(CursorReader("managed", str(ws.get("label") or key),
                                    f"managed-{key}.json", window, partition))
    return out


def compliance_plan(policy) -> CompliancePlan:
    from ..models import env_or_literal

    entries = _compliance_entries(policy)
    orgs = tuple(ComplianceOrg(key, policy.org_pseudonym(org_id) if org_id else None, here)
                 for org_id, key, here in entries)
    scanned = {org_id for org_id, _, _ in entries}
    team = set()
    for org in getattr(policy, "orgs", []) or []:
        org_id = str(env_or_literal(org.get("id")) or "")
        if org_id and org_id not in scanned:
            partition = policy.org_pseudonym(org_id)
            if partition:
                team.add(partition)
    return CompliancePlan(orgs, frozenset(team))


def compliance_view(plan: CompliancePlan, store, scoped: frozenset[str] | None
                    ) -> tuple[bool | str, dict[str, str], dict[str, float]]:
    """Adapter 3's `configured` value, heartbeats and cadence for a view of
    the partitions in `scoped` (None: every partition).

    False when no org is set up for it. A string, shown as the reason, when
    it does not apply to the view: no scanned partition is selected, or no
    selected org has a recorded run and none has its key in this process.
    The dashboard is not given the Compliance Access Key, so an org that
    has never been scanned cannot be told from a Team workspace listed
    under `compliance.orgs`.
    """
    if not plan.orgs:
        return False, {}, {}
    relevant = [o for o in plan.orgs if scoped is None or o.partition in scoped]
    if not relevant:
        return (NA_TEAM if scoped and scoped <= plan.team else NA_SELECTION), {}, {}
    beats, intervals = heartbeats(store, [o.state_key for o in relevant])
    if not beats and not any(o.key_here for o in relevant):
        return NA_NO_RUN, {}, {}
    return True, beats, intervals


# -- surfaces, which is what the diagram actually shows -------------------
#
# The strip above reasons about CONTROL POINTS, because that is what
# staleness is a property of -- each adapter has its own cadence. The
# diagram shows PRODUCTS, because that is what someone looking at it
# wants to see: is Cowork still reaching us, not is adapter 4.
#
# One product can arrive through several control points (Claude for M365
# is seen by the hook, the Compliance API and OTel), so a surface is as
# late as its FRESHEST feed -- if any control point still has it, it is
# arriving.

SURFACE_ICONS = {
    "claude-ai": "chat",
    "claude-code": "terminal",
    "cowork": "docs",
    "claude-for-m365": "grid",
    "claude-science": "chat",
    "claude-in-chrome": "chat",
}

SURFACE_LABELS = {
    "claude-ai": "claude.ai",
    "claude-code": "Claude Code",
    "cowork": "Cowork",
    "claude-for-m365": "Office agents",
    "claude-science": "Claude Science",
    "claude-in-chrome": "Claude in Chrome",
    # Adapter 4 could not attribute these. Named for what it means rather
    # than shown as a raw key, because it is the row an operator most
    # needs to notice.
    "otel-unknown": "Unattributed (OTel)",
}

# The order the KNOWN surfaces are drawn in, top to bottom. Fixed, so the
# diagram does not reshuffle itself between refreshes as volumes change --
# a panel whose rows move is one nobody can glance at.
#
# NOT an allowlist. Anything else with traffic is appended after these, in
# a stable order. Treated as the whole world, this tuple would hide every
# surface it does not name, otel-unknown included, and the panel would
# still look correct. A surface nobody recognises is the single thing a
# delivery panel most needs to show.
#
# `compliance-scan` is not here because it is a SOURCE, not a surface; a
# row for it could never light up. Each key is a name `normalize_surface`
# produces -- Cowork is `cowork`.
SURFACE_ORDER = (
    "claude-ai", "claude-code", "cowork", "claude-for-m365",
    "claude-science", "claude-in-chrome",
)


@dataclass
class SurfaceState:
    surface: str
    label: str
    icon: str
    state: str
    requests: int
    detail: str
    # A scheduled pull rather than a live stream. Drawn with a dashed
    # wire and a slow pulse: it feeds the core like everything else, and
    # pretending it arrives continuously would be the lie.
    periodic: bool = False


def surface_states(
    summary, configured: dict[str, bool] | None = None,
    *, now: datetime | None = None, watch: Watch | None = None,
    heartbeats: dict[str, str] | None = None,
    intervals: dict[str, float] | None = None,
) -> list[SurfaceState]:
    """One node per product, with the state to paint it."""
    now = now or datetime.now(UTC)
    watch = watch or Watch()
    by_surface = {r.surface: r for r in summary.surfaces}
    if configured is None:
        configured = infer_configured(summary)

    # Known names first, then anything else that actually has traffic.
    # Synthetic probes are already excluded upstream by build_summary.
    extra = sorted(
        k for k, r in by_surface.items()
        if k not in SURFACE_ORDER and r.requests
    )

    out: list[SurfaceState] = []

    for key in (*SURFACE_ORDER, *extra):
        row = by_surface.get(key)
        label = SURFACE_LABELS.get(key, key)
        icon = SURFACE_ICONS.get(key, "chat")
        if row is None and key not in SURFACE_ORDER:
            continue  # an appended name always has traffic
        if row is None or not row.requests:
            out.append(SurfaceState(key, label, icon, STATE_OFF, 0, "no traffic"))
            continue

        # As late as its freshest feed: a product still arriving through
        # ANY control point is arriving.
        best_age, best_src = None, None
        for source, ts in (row.last_seen_by_source or {}).items():
            if not configured.get(source, True):
                continue
            age = _age_min(ts, now)
            if age is not None and (best_age is None or age < best_age):
                best_age, best_src = age, source
        if best_age is None:
            # Every feed this surface has comes from a control point the
            # deployment does not run. Reporting it as idle would claim it
            # is fine; it is not being watched at all.
            out.append(SurfaceState(key, label, icon, STATE_OFF,
                                    row.requests,
                                    "no configured feed supplies this"))
            continue

        late_after = late_after_for(best_src, (intervals or {}).get(best_src))
        watched = best_src not in CLOCK_WATCHED or watch.expecting(now, late_after)
        if best_age <= late_after:
            state, detail = STATE_LIVE, _ago(best_age)
        elif not watched:
            state, detail = STATE_IDLE, f"{_ago(best_age)} · off hours"
        else:
            state, detail = STATE_LATE, f"{_ago(best_age)} · late"
        out.append(SurfaceState(key, label, icon, state, row.requests, detail))

    # The Compliance API is a CONTROL POINT, not a product -- it observes
    # several products on a schedule. It is drawn anyway, because "is the
    # audit job running and on time" is a question the picture should
    # answer, and leaving it out to keep the taxonomy tidy answered it
    # nowhere. Its state comes from the control-point view, its wire is
    # dashed, and its pulse is slow.
    for cp in control_points(summary, configured, now=now, watch=watch,
                             heartbeats=heartbeats, intervals=intervals):
        if cp.source != SOURCE_COMPLIANCE_SCAN or cp.state == STATE_OFF:
            continue
        # A not-applicable scan is drawn, so the strip says why it is quiet.
        out.append(SurfaceState(
            "compliance-scan", "Compliance scan", "clock",
            cp.state, cp.requests, cp.detail, periodic=True))
    return out


def heartbeats(store, scan_state_keys) -> tuple[dict[str, str], dict[str, float]]:
    """When each control point last ran, and how often it runs.

    Both come from the same cursor, so they are read together.

    Only adapter 3 does, and only because it keeps a cursor. The
    others are push: silence from them is the only signal there is.

    With several orgs the OLDEST marker wins. One CronJob scans them
    all in a pass, so a stalled org is a stalled job, and taking the
    freshest would let a healthy org hide it. An org that has never
    run has no marker and is skipped rather than counted as
    infinitely stale -- a newly onboarded org must not paint the
    whole control point red before its first run.
    """
    from ..compliance.scanner import last_run_at, observed_interval_min

    oldest = ""
    intervals: list[float] = []
    for key in scan_state_keys:
        ts = last_run_at(store, key)
        if ts and (not oldest or newer(oldest, ts)):
            oldest = ts
        seen = observed_interval_min(store, key)
        if seen:
            intervals.append(seen)
    beats = {SOURCE_COMPLIANCE_SCAN: oldest} if oldest else {}
    # The LONGEST observed cadence across orgs. They share one
    # CronJob, so they should agree; if they do not, the slowest is
    # the one that decides when silence is a fault.
    every = {SOURCE_COMPLIANCE_SCAN: max(intervals)} if intervals else {}
    return beats, every
