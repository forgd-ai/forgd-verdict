"""Adapter 6: scan Managed Agents session histories after the fact.

A managed agent runs on Anthropic's infrastructure: no inference hook, no
Claude Code hook, no documented OTel export. What it does leave is its
event history, persisted server-side and readable in full, which is
adapter 3's position against a different API.

Post-hoc only. It cannot stop anything; the client-side gate in
docs/AGENT-BUILDERS.md is the preventive half. Writes findings, never
content.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import build_id
from ..budget import Budget
from ..compliance.client import ComplianceError
from ..compliance.scanner import BEHAVIOUR_BUDGET_S, RUN_MARKER, State
from ..core import decide, left_out_tiers, scan, with_left_out
from ..extract import frame_units
from ..metadata import MetadataGuard, refuse_unsafe_labels
from ..models import UNSCANNED_PARTIAL, Finding
from ..orgregistry import check_workspace_pseudonyms, workspace_key, workspace_pseudonym
from ..policy import Policy
from ..store.base import SOURCE_MANAGED_SCAN, FindingRow, VerdictRecord, pseudonym, utcnow
from .client import ManagedAgentsClient

log = logging.getLogger("forgd_verdict.managed")

SURFACE = "managed-agents"
# A label becomes FORGD_MANAGED_AGENTS_KEY_<LABEL> in the chart, and a key
# names a store object, so neither may hold a '.'.
_NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

_TOOL_USE = ("agent.tool_use", "agent.mcp_tool_use", "agent.custom_tool_use")
_TOOL_RESULT = ("agent.tool_result", "agent.mcp_tool_result",
                "user.tool_result", "user.custom_tool_result")
# Lifecycle and control events. They carry no content an agent read or
# wrote -- `user.tool_confirmation`'s deny_message is ours -- and scanning
# `session.error` would scan Anthropic's error strings.
_SKIP = ("session.", "span.", "user.interrupt", "user.tool_confirmation")
_META = ("id", "type", "processed_at")
# The fields of a recognised event that `events_to_messages` places in its
# message.
_READ = ("content", "thinking", "name", "input", "tool_use_id", "mcp_tool_use_id",
         "custom_tool_use_id")


def events_to_messages(events: list[Any]) -> list[dict[str, Any]]:
    """A session's events in the inference-hook frame shape.

    One message per event, so a finding's locator names the event's
    position in the history. The user's own messages are the only `user`
    text; an event this does not recognise is kept, under a role the
    behavioural checks never trust, and every string in it is scanned.
    """
    out: list[dict[str, Any]] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        etype = str(ev.get("type") or "")
        content = ev.get("content")
        blocks = content if isinstance(content, list) else (
            [{"type": "text", "text": content}] if isinstance(content, str) else
            [] if content is None else [{"type": "managed_content", "content": content}])
        if etype == "user.message":
            message = {"role": "user", "content": blocks}
        elif etype == "agent.message":
            message = {"role": "assistant", "content": blocks}
        elif etype == "agent.thinking":
            message = {"role": "assistant", "content": [
                {"type": "text", "text": str(ev.get("thinking") or "")}]}
        elif etype in _TOOL_USE:
            message = {"role": "assistant", "content": [{
                "type": "tool_use", "id": ev.get("id"),
                "tool_name": ev.get("name"), "input": ev.get("input")}]}
        elif etype in _TOOL_RESULT:
            message = {"role": "user", "content": [{
                "type": "tool_result",
                "tool_use_id": (ev.get("tool_use_id") or ev.get("mcp_tool_use_id")
                                or ev.get("custom_tool_use_id")),
                "content": ev.get("content")}]}
        elif etype.startswith(_SKIP):
            continue
        else:
            rest = {k: v for k, v in ev.items() if k not in _META}
            if rest:
                out.append({"role": "synthetic",
                            "content": [{"type": "managed_event", **rest}]})
            continue
        # Fields of a recognised event that the message above does not
        # carry, as a block of a type the behavioural checks never trust.
        rest = {k: v for k, v in ev.items() if k not in _META and k not in _READ}
        if rest:
            message["content"] = [*message["content"], {"type": "managed_event", **rest}]
        out.append(message)
    return out


@dataclass
class ManagedReport:
    session_id: str
    agent_id: str | None
    created_at: str | None
    updated_at: str | None
    action: str
    findings: list[Finding] = field(default_factory=list)
    events: int = 0
    scan_ms: float = 0.0
    budget_exceeded: bool = False
    tiers_dropped: list[str] = field(default_factory=list)


class ManagedScanner:
    """One workspace: its API key, its cursor."""

    def __init__(self, policy: Policy, workspace: dict[str, Any],
                 store: Any | None = None, client: ManagedAgentsClient | None = None,
                 detectors: list[Any] | None = None):
        # The post-hoc profile, as adapter 3 uses: Presidio included, and
        # the behavioural checks if that profile enables them.
        self.policy = policy = policy.for_profile("compliance")
        from ..behaviour.provenance import from_policy
        from ..models import env_or_literal

        cfg = policy.raw.get("managed_agents") or {}
        self.label = str(workspace.get("label") or "unnamed")
        self.key = str(workspace.get("key") or "")
        if not self.key:
            raise ValueError("a Managed Agents workspace needs a key "
                             "(managed_agents.workspaces[].key)")
        self.client = client or ManagedAgentsClient(
            api_key=str(env_or_literal(workspace.get("api_key")) or ""),
            base_url=cfg.get("base_url", "https://api.anthropic.com"))
        # Named by the key, and logged by the label.
        log_name = f"workspace {self.label}"
        self.state = State(f"managed-{self.key}.json", store=store, log_name=log_name)
        if not self.state.loaded and self.key != self.label:
            # With no cursor under the key, it is seeded once from a cursor
            # named by the label, when one exists. It maps session ids, which
            # are unique across workspaces, so a cursor another workspace
            # left skips none of this one's sessions.
            legacy = State(f"managed-{self.label}.json", store=store, log_name=log_name)
            if legacy.loaded:
                self.state.data.update(legacy.data)
        self.detectors = (detectors if detectors is not None
                          else policy.build_detectors(profile="managed"))
        self.left_out = left_out_tiers(self.policy, self.detectors, "managed")
        # The guard and salt the ingest records go through.
        self.meta = MetadataGuard(self.detectors, policy.hash_salt, allow_subprocess=True)
        self._behaviour = from_policy(policy)
        self.page_limit = int(cfg.get("page_limit", 100))
        self.window_days = int(cfg.get("window_days", 30))

    def scan(self, max_sessions: int | None = None) -> Iterator[ManagedReport]:
        """Every session in the window whose history changed since last seen.

        Newest first, stopping at the first session created before the
        window. A session created earlier and still active is not reached;
        `window_days` is the trade.

        Nothing is saved here. The caller writes the records and then calls
        `commit()`, so a failed write cannot leave sessions marked seen that
        were never recorded.
        """
        self._run_started = utcnow()
        edge = datetime.now(UTC) - timedelta(days=self.window_days)
        seen = self.state.data.setdefault("sessions", {})
        self._pending: dict[str, str] = {}
        self.failed = 0
        count = 0
        for session in self.client.list_sessions(limit=self.page_limit):
            created = _parse(session.get("created_at"))
            if created is not None and created < edge:
                break
            sid = session.get("id")
            if not isinstance(sid, str):
                continue
            # A session with no updated_at is keyed on its creation time, so
            # it is scanned once rather than on every pass.
            mark = session.get("updated_at") or session.get("created_at") or ""
            if mark and seen.get(sid) == mark:
                continue
            if max_sessions is not None and count >= max_sessions:
                break
            count += 1
            try:
                report = self._scan_one(session)
            except ComplianceError as exc:
                # Deleted between the listing and the fetch: nothing to scan.
                # Any other refusal costs this session, not the pass: it is
                # not marked seen, so the next pass tries it again, and the
                # sessions after it are still reached.
                if exc.status != 404:
                    self.failed += 1
                    log.warning("could not read a managed session's history", extra={
                        "fields": {"workspace": self.label, "status": exc.status}})
                continue
            yield report
            self._pending[sid] = mark

    def commit(self) -> None:
        """Mark this pass's sessions seen and save, after they were written."""
        edge = datetime.now(UTC) - timedelta(days=self.window_days)
        seen = {**self.state.data.get("sessions", {}), **getattr(self, "_pending", {})}
        # Only sessions still inside the window: the map would otherwise
        # grow by every session the workspace ever ran.
        self.state.data["sessions"] = {
            k: v for k, v in seen.items() if (p := _parse(v)) is not None and p >= edge}
        self.state.data[RUN_MARKER] = getattr(self, "_run_started", utcnow())
        self.state.save()

    def _scan_one(self, session: dict[str, Any]) -> ManagedReport:
        status: dict[str, Any] = {"complete": True}
        events = list(self.client.session_events(
            session["id"], limit=self.page_limit,
            log_as=self.meta.one(session["id"], where="managed:log"), status=status))
        start = time.perf_counter()
        messages = events_to_messages(events)
        result = scan(frame_units(messages), self.detectors, Budget(self.policy.budget_ms))
        result.detectors_skipped = with_left_out(result.detectors_skipped, self.left_out)
        if not status["complete"]:
            result.detectors_skipped = [*result.detectors_skipped, UNSCANNED_PARTIAL]
        findings = list(result.findings)
        if self._behaviour is not None:
            from ..behaviour.provenance import run

            outcome = run(self._behaviour, messages, session=None, findings=result.findings,
                          time_budget_s=BEHAVIOUR_BUDGET_S)
            if outcome.error is not None:
                # The type only. A traceback's message can be built from the
                # transcript text being analysed.
                log.warning("behavioural check failed for a session",
                            extra={"fields": {"error": type(outcome.error).__name__}})
            elif outcome.dropped:
                log.warning("behavioural checks stopped at their time budget for a session",
                            extra={"fields": {"checks": outcome.dropped}})
            findings += outcome.findings
            result.detectors_skipped = with_left_out(result.detectors_skipped, outcome.dropped)
        verdict = decide(findings, self.policy, dropped=result.detectors_skipped)
        agent = session.get("agent")
        return ManagedReport(
            session_id=session["id"],
            agent_id=agent.get("id") if isinstance(agent, dict) else None,
            created_at=session.get("created_at"),
            updated_at=session.get("updated_at"),
            action=verdict.action,
            findings=findings,
            events=len(events),
            scan_ms=(time.perf_counter() - start) * 1000.0,
            budget_exceeded=bool(result.budget_exceeded),
            tiers_dropped=list(result.detectors_skipped or []),
        )


def report_to_record(report: ManagedReport, salt: str, key: str) -> VerdictRecord:
    return VerdictRecord(
        source=SOURCE_MANAGED_SCAN,
        observed_at=utcnow(),
        session_started_at=report.created_at,
        session_updated_at=report.updated_at,
        session_id=report.session_id,
        surface=SURFACE,
        tenant_hash=workspace_pseudonym(key, salt),
        # The agent is the actor: a managed session has no signed-in user.
        actor_hash=pseudonym(report.agent_id, salt, "user"),
        messages_total=report.events,
        messages_scanned=report.events,
        action=report.action,
        scan_ms=report.scan_ms,
        findings_count=len(report.findings),
        findings=[FindingRow.from_finding(f) for f in report.findings],
        budget_exceeded=report.budget_exceeded,
        tiers_dropped=list(report.tiers_dropped),
        build=build_id(),
    )


def workspaces(policy: Policy) -> list[dict[str, Any]]:
    """Every configured workspace, each with a string `key`.

    Labels and keys must be set, unique and safe, and no two keys may share
    a pseudonym. Raises ValueError on the first that is not. The message
    names workspaces by label, never by key.
    """
    raw = (policy.raw.get("managed_agents") or {}).get("workspaces") or []
    raw = [w for w in raw if isinstance(w, dict)]
    labels = [str(w.get("label") or "") for w in raw]
    if len(set(labels)) != len(labels) or not all(_NAME_OK.fullmatch(x) for x in labels):
        raise ValueError("managed_agents.workspaces[].label must be set, unique, and "
                         "letters, digits, '_' or '-' (it names the API key's "
                         "variable)")
    for ws, label in zip(raw, labels, strict=True):
        key = workspace_key(ws)
        if not key:
            raise ValueError(
                f"managed_agents.workspaces entry {label!r} has no `key`. Add "
                f"`key: {label}` to it. The key names the workspace's findings "
                "partition and cursor, so it must never change and never be "
                "reused by another workspace; the label can then be renamed "
                "freely.")
        if not _NAME_OK.fullmatch(key):
            raise ValueError(
                f"managed_agents.workspaces entry {label!r} has a `key` that is not "
                "1 to 64 letters, digits, '_' or '-', starting with a letter or "
                "digit")
    # A key names the workspace's cursor in the store, so two keys that
    # differ only in case would share it on a case-insensitive filesystem.
    folded = [workspace_key(ws).lower() for ws in raw]
    if len(set(folded)) != len(folded):
        raise ValueError("managed_agents.workspaces[].key must be unique without regard "
                         "to case: each names the workspace's cursor in the store")
    check_workspace_pseudonyms(
        [(workspace_key(ws), label) for ws, label in zip(raw, labels, strict=True)],
        policy.hash_salt)
    return [{**ws, "key": workspace_key(ws)} for ws in raw]


def run_managed_ingest(policy: Policy, store, *, max_sessions: int | None = None,
                       batch_size: int = 50) -> dict[str, Any]:
    """One pass over every configured workspace. Never raises for one.

    A workspace whose key does not resolve is REPORTED, not skipped: the
    chart marks the key optional, so a secret missing from the vault would
    otherwise be zero coverage and a clean summary.
    """
    from ..models import env_or_literal, usable_secret

    policy.refuse_unsalted("managed agents ingest")
    salt = policy.hash_salt
    per: list[dict[str, Any]] = []
    raw = [w for w in (policy.raw.get("managed_agents") or {}).get("workspaces") or []
           if isinstance(w, dict)]
    detectors = policy.for_profile("compliance").build_detectors(profile="managed") \
        if raw else []
    try:
        guard = MetadataGuard(detectors, allow_subprocess=True)
        refuse_unsafe_labels([w.get("label") for w in raw], guard,
                             "managed_agents.workspaces")
        refuse_unsafe_labels([w.get("key") for w in raw], guard,
                             "managed_agents.workspaces", noun="key")
        configured = workspaces(policy)
    except ValueError as exc:
        log.error("managed_agents.workspaces is misconfigured; skipped",
                  extra={"fields": {"detail": str(exc)}})
        return {"workspaces": [], "error": "invalid managed_agents.workspaces",
                "detail": str(exc)}
    for ws in configured:
        label = str(ws["label"])
        if not usable_secret(env_or_literal(ws.get("api_key"))):
            log.error("managed agents workspace has no API key", extra={
                "fields": {"workspace": label}})
            per.append({"workspace": label, "ok": False, "error": "no api key"})
            continue
        scanned = written = 0
        try:
            scanner = ManagedScanner(policy, ws, store=store, detectors=detectors)
            meta = MetadataGuard(scanner.detectors, salt, allow_subprocess=True)
            batch: list[VerdictRecord] = []
            for report in scanner.scan(max_sessions=max_sessions):
                scanned += 1
                batch.append(report_to_record(report, salt, str(ws["key"])))
                if len(batch) >= batch_size:
                    written += store.write_verdicts(meta.records(batch))
                    batch = []
            if batch:
                written += store.write_verdicts(meta.records(batch))
            scanner.commit()
        except Exception as exc:  # noqa: BLE001
            # One workspace must not abandon the others, or the Compliance
            # summary printed after this. The type and status only: this
            # summary is logged and printed whole.
            log.error("managed agents ingest failed for a workspace", extra={
                "fields": {"workspace": label, "error": type(exc).__name__,
                           "status": getattr(exc, "status", None)}})
            per.append({"workspace": label, "ok": False, "error": type(exc).__name__,
                        "status": getattr(exc, "status", None)})
            continue
        per.append({"workspace": label, "ok": True, "sessions_scanned": scanned,
                    "sessions_failed": scanner.failed, "verdicts_written": written})
    return {"workspaces": per}


def _parse(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
