"""Adapter 3: post-hoc Compliance API scanner.

Pulls session transcripts, runs the same scan core over them, and joins the
results to Inference hooks denials via `reference_id`. Read-only: this
adapter is for audit and backfill, never enforcement.

Two things this is good for:
  * Backfill. The verdict server only sees traffic from the moment it is
    enforcing; the Compliance API reaches back over the retention window.
  * Honesty check on adapter 1. Scan the same sessions post-hoc and compare:
    findings the live scanner missed are false negatives you can count.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from ..budget import Budget
from ..core import decide, left_out_tiers, scan, with_left_out
from ..extract import artifact_units, chat_units, compliance_units
from ..fsmode import write_private
from ..metadata import MetadataGuard
from ..models import ACTION_DENY, UNSCANNED_ARTIFACT, UNSCANNED_DELETED, Finding, pseudonym
from ..policy import Policy, state_key
from .client import ComplianceClient, ComplianceError

DENIED_ACTIVITY = "inference_hooks_request_denied"
BREAKER_ACTIVITY = "inference_hooks_circuit_breaker_tripped"


@dataclass
class ChatReport:
    """A scanned claude.ai chat.

    Separate from SessionReport because chats come from a different endpoint
    family entirely: the session endpoints cover Cowork, Claude Code,
    Claude Science, M365 and Chrome, and claude.ai chat content appears in
    none of them. Scanning only sessions means every prompt typed into
    claude.ai is invisible -- which is exactly the gap this closes.
    """

    chat_id: str
    name: str | None = None
    user_id: str | None = None
    model: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    deleted_at: str | None = None
    project_id: str | None = None
    action: str = "allow"
    findings: list[Finding] = field(default_factory=list)
    messages: int = 0
    # False when no message of the chat could be read.
    content_read: bool = True
    artifacts_scanned: int = 0
    # Fetches that failed. A skipped artifact is not a clean one, and
    # `artifacts_scanned` being lower than it should be is a number
    # nobody can check against an expected value.
    artifacts_failed: int = 0
    # Failed fetches other than a 404; these hold the chat cursor.
    artifacts_retryable: int = 0
    scan_ms: float = 0.0
    budget_exceeded: bool = False
    tiers_dropped: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "chat_id": self.chat_id,
            "user_id": self.user_id,
            "model": self.model,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "deleted_at": self.deleted_at,
            "action": self.action,
            "messages": self.messages,
            "content_read": self.content_read,
            "artifacts_scanned": self.artifacts_scanned,
            "artifacts_failed": self.artifacts_failed,
            "scan_ms": round(self.scan_ms, 2),
            "findings": [f.to_log() for f in self.findings],
        }


@dataclass
class SessionReport:
    session_id: str
    product_surface: str | None
    user_id: str | None
    created_at: str | None
    updated_at: str | None
    action: str
    findings: list[Finding] = field(default_factory=list)
    messages: int = 0
    scan_ms: float = 0.0
    # T2 runs on this path and nowhere else, so this is the only path where a
    # tier can actually be dropped.
    budget_exceeded: bool = False
    tiers_dropped: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "product_surface": self.product_surface,
            "user_id": self.user_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "action": self.action,
            "messages": self.messages,
            "scan_ms": round(self.scan_ms, 2),
            "findings": [f.to_log() for f in self.findings],
        }


log = logging.getLogger("forgd_verdict.compliance")


class State:
    """Resumable cursors, persisted as JSON.

    Two places it can live. A FILE is right for a local run and for tests.
    A STORE is right for the deployed ingest job, which is a scheduled
    Container Apps Job: its replica is destroyed when the pass finishes, so
    a file cursor is gone before the next run reads it and every pass
    re-walks the same window. `latest_per_session` collapsed the duplicate
    records on the dashboard, so the symptom never surfaced.

    The store is already durable, the job already holds an identity that
    can write to it, and it works on every deployment target -- which
    matters more than an Azure Files share would.
    """

    def __init__(self, path: str, store: Any | None = None, key: str | None = None,
                 log_name: str | None = None):
        self.path = path
        self.store = store
        # Derived from the path so two orgs keep distinct cursors: a shared
        # one means a pass that fails midway advances the cursor for an org
        # it never scanned, and those sessions are never looked at again.
        self.key = key or state_key(path)
        # What log lines call this cursor, when its key must not be logged.
        self.log_name = log_name or self.key
        self.data: dict[str, Any] = {
            "last_run_started_at": None,
            "activities_cursor": None,
            "sessions": {},  # session_id -> {"updated_at":..., "messages":N}
        }
        loaded = self._load()
        self.loaded = isinstance(loaded, dict)
        if self.loaded:
            self.data.update(loaded)

    def _load(self) -> Any:
        if self.store is not None:
            blob = self.store.get_state(self.key)
            if not blob:
                return None
            try:
                return json.loads(blob)
            except (ValueError, RecursionError):
                # A corrupt cursor reads as "never ran", which rescans. That
                # is wasteful and safe; trusting a half-parsed one would
                # skip sessions instead, which is neither.
                log.warning("ingest cursor did not parse; starting from scratch",
                            extra={"fields": {"key": self.log_name}})
                return None
        if not os.path.exists(self.path):
            return None
        try:
            with open(self.path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError, RecursionError):
            return None

    def save(self) -> None:
        blob = json.dumps(self.data, indent=2, default=str).encode("utf-8")
        if self.store is not None:
            self.store.put_state(self.key, blob)
            return
        write_private(os.path.abspath(self.path), blob)


# Provenance and taint per session, post-hoc. Twenty times adapter 1's
# per-frame limit: nobody is waiting, and a session is read once per pass,
# so work cut off here is not resumed by a later frame.
BEHAVIOUR_BUDGET_S = 5.0

# The cursor field that says the job RAN. Named here, beside the only
# writer, because the dashboard has to read it and a second copy of the
# string could drift from this one without failing anything.
RUN_MARKER = "last_run_started_at"

# Observed gaps between runs, newest last. See `_record_gap`.
RUN_GAPS = "run_gaps_min"
GAP_SAMPLES = 5


def observed_interval_min(store: Any, key: str) -> float | None:
    """The cadence this job actually runs at, or None if not yet known.

    The median of the last few gaps. One sample is not a cadence and two
    can both be wrong, so a caller gets None until there are three and
    falls back to its own default.
    """
    if store is None:
        return None
    try:
        blob = store.get_state(key)
    except Exception:  # noqa: BLE001
        return None
    if not blob:
        return None
    try:
        data = json.loads(blob)
    except (ValueError, TypeError, RecursionError):
        return None
    gaps = data.get(RUN_GAPS) if isinstance(data, dict) else None
    if not isinstance(gaps, list):
        return None
    clean = sorted(float(g) for g in gaps
                   if isinstance(g, int | float) and g > 0)
    if len(clean) < 3:
        return None
    return clean[len(clean) // 2]


def last_run_at(store: Any, key: str) -> str | None:
    """When adapter 3 last completed a pass over `key`'s org.

    A scan that finds nothing writes no verdict record, so liveness
    cannot be inferred from the records: three healthy six-hourly runs
    over a quiet org wrote zero rows and the delivery panel reported the
    job 17h late while it was 5h into a 6h cycle. The cursor is
    saved at the end of every pass whether or not anything was found, so
    it is the only evidence the job ran at all.

    The stamp is when the pass STARTED -- close enough for a staleness
    threshold measured in hours, and it is what the scanner already
    records for resuming.
    """
    if store is None:
        return None
    try:
        blob = store.get_state(key)
    except Exception:  # noqa: BLE001
        # The dashboard must not 500 because a cursor is unreadable. No
        # marker degrades to the record-derived behaviour, which is what
        # every deployment had before this.
        log.warning("could not read scan cursor", extra={"fields": {"key": key}})
        return None
    if not blob:
        return None
    try:
        data = json.loads(blob)
    except (ValueError, TypeError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None
    ts = data.get(RUN_MARKER)
    return str(ts) if ts else None


class ComplianceScanner:
    def __init__(
        self,
        policy: Policy,
        client: ComplianceClient | None = None,
        org: dict[str, Any] | None = None,
        store: Any | None = None,
        detectors: list[Any] | None = None,
    ):
        # Adopt the post-hoc profile here rather than in the CLI: this is the
        # adapter boundary, so a library caller cannot get inline tiers by
        # constructing the scanner directly.
        self.policy = policy = policy.for_profile("compliance")
        from ..behaviour.provenance import from_policy

        self._behaviour = from_policy(policy)
        # The post-hoc judge and the tool baseline, which write a flag on a
        # session for the verdict server to read (behaviour/flags.py).
        from ..behaviour import baseline as _baseline
        from ..behaviour import judge as _judge

        self._judge = _judge.from_policy(policy)
        self._baseline = _baseline.from_policy(policy, store)
        self._flag_store = store
        self.sessions_flagged = 0
        cfg = policy.compliance
        from ..models import env_or_literal

        # `org` is one entry from `Policy.compliance_orgs()`. Its key and
        # cursor win over the top-level ones, because with several orgs the
        # top-level values are either absent or belong to a different org --
        # and reading one org's transcripts against another's cursor is
        # silent data loss, not an error.
        org = org or {}
        self.org_id = str(org.get("id") or env_or_literal(cfg.get("org_id")) or "")
        self.org_label = str(org.get("label")
                             or pseudonym(self.org_id, policy.hash_salt, "org") or "unnamed")

        self.client = client or ComplianceClient(
            api_key=str(org.get("api_key") or env_or_literal(cfg.get("api_key")) or ""),
            base_url=cfg.get("base_url", "https://api.anthropic.com"),
            anthropic_version=cfg.get("anthropic_version", "2023-06-01"),
        )
        # The cursor goes in the STORE when there is one. A scheduled job's
        # replica is destroyed when the pass finishes, so a file cursor is
        # gone before the next run reads it.
        self.state = State(
            str(org.get("state_path") or cfg.get("state_path")
                or "./compliance-state.json"),
            store=store,
        )
        # The cursor values AS THEY WERE when this pass started.
        #
        # The sessions pass is committed, which advances the marker,
        # before `_ingest_one_org` calls `scan_chats`. A chat pass reading the live
        # state would get a cursor equal to THIS run's start time and ask
        # for the last ten minutes -- every run, whatever the cron
        # interval. On a six-hourly schedule that leaves 5h50m of claude.ai
        # activity unscanned, reported as `chats_scanned: 0` with no gap
        # shown.
        self._entry = dict(self.state.data)
        # Cursor values a pass has reached, applied to `state.data` and
        # saved by `commit`.
        self._pending: dict[str, Any] = {}
        # The earliest window a session pass in this run listed from, and
        # the sessions it recorded; `commit` prunes `sessions` to them.
        self._session_window: datetime | None = None
        self._sessions_seen: set[str] = set()
        self.detectors = (detectors if detectors is not None
                          else policy.build_detectors(profile="compliance"))
        self.left_out = left_out_tiers(self.policy, self.detectors, "compliance")
        # The same guard and salt the ingest records go through, so a logged
        # id is the id, or the placeholder, on the record.
        self.meta = MetadataGuard(self.detectors, policy.hash_salt, allow_subprocess=True)
        self.page_limit = int(cfg.get("page_limit", 100))
        # Sessions whose messages could not be fetched, across every pass.
        self.sessions_failed = 0
        # Chats whose messages could not be fetched, across every pass.
        self.chats_failed = 0
        self.lookback_minutes = int(cfg.get("lookback_minutes", 10))

    # -- sessions ---------------------------------------------------------

    def scan_sessions(
        self,
        family: str = "local",
        since: str | None = None,
        max_sessions: int | None = None,
    ) -> Iterator[SessionReport]:
        run_started = _now_rfc3339()
        window_start = since or self._resume_window(f"sessions:{family}")
        start = _parse_ts(window_start)
        if start is not None and (self._session_window is None
                                  or start < self._session_window):
            self._session_window = start

        kwargs: dict[str, Any] = {"limit": self.page_limit}
        if family == "local":
            # `updated_at.gte` polls by last activity, which is what we want
            # when re-walking growing sessions. The docs warn that it lags at
            # page boundaries, so the resume window is deliberately backdated.
            kwargs["updated_at_gte"] = window_start
        else:
            kwargs["created_at_gte"] = window_start

        truncated = failed = False
        for count, session in enumerate(self.client.list_sessions(family, **kwargs)):
            if max_sessions is not None and count >= max_sessions:
                truncated = True
                break
            try:
                report = self._scan_one(session, family)
            except ComplianceError as exc:
                # A 404 is a session deleted between the listing and the
                # fetch. Any other status costs this session, not the
                # family: it is counted, and the resume cursor stays put so
                # the next pass lists it again.
                if exc.status != 404:
                    failed = True
                    self.sessions_failed += 1
                    log.warning("could not read a compliance session's messages",
                                extra={"fields": {"family": family,
                                                  "status": exc.status}})
                continue
            if report is not None:
                yield report

        # The RUN marker moves on a truncated pass too: the dashboard's
        # liveness signal is about whether the job ran, not about how much
        # it got through.
        self._record_gap(run_started)
        self._pending[RUN_MARKER] = run_started
        # The RESUME cursor does not move on a truncated pass. If it did,
        # 500 sessions available and `--max-sessions 10` would scan ten and
        # advance the window past the other 490, permanently. With the two
        # separate, the job is reported fresh AND the unscanned sessions
        # are still in the window next time. A session that could not be
        # read holds it back the same way.
        if not truncated and not failed:
            self._pending[self._cursor_key(f"sessions:{family}")] = run_started

    def commit(self) -> None:
        """Apply the cursors the passes so far have reached, and save.

        Called once their records are written. Until then nothing moves,
        neither a resume cursor nor the run marker.
        """
        self.state.data.update(self._pending)
        self._pending.clear()
        if self._session_window is not None:
            # Only sessions this run recorded or updated inside its window:
            # the map would otherwise grow by every session the org ever ran.
            edge = self._session_window
            self.state.data["sessions"] = {
                k: v for k, v in (self.state.data.get("sessions") or {}).items()
                if k in self._sessions_seen or (
                    (p := _parse_ts((v or {}).get("updated_at"))) is not None
                    and p >= edge)}
        self.state.save()

    def _record_gap(self, run_started: str) -> None:
        """How long it has actually been between runs.

        The dashboard's "late" threshold for this adapter is two
        intervals plus slack. A constant interval would not follow a
        fork's `ingest.schedule` in the Helm chart: on a four-hourly or
        twelve-hourly cron it would swallow three missed runs in one
        direction and go red on a single slipped run in the other.

        So the interval is measured. The job does not know its own cron
        expression -- it is invoked by one -- but it knows when it last
        ran, and the gap between two runs is the interval.
        """
        prev = self._entry.get(RUN_MARKER)
        if not prev or RUN_GAPS in self._pending:
            return
        try:
            a = datetime.fromisoformat(str(prev).replace("Z", "+00:00"))
            b = datetime.fromisoformat(run_started.replace("Z", "+00:00"))
        except ValueError:
            return
        gap = (b - a).total_seconds() / 60.0
        # A clock jump, a restored backup, or a gap so long the schedule
        # plainly was not running. Neither tells us the cadence.
        if not 1.0 <= gap <= 7 * 24 * 60:
            return
        gaps = list(self.state.data.get(RUN_GAPS) or [])
        gaps.append(round(gap, 1))
        # A short window, and the MEDIAN of it. A one-off manual run
        # produces a tiny gap; a mean or a min would let that tighten the
        # threshold and start reporting a healthy job as late.
        self._pending[RUN_GAPS] = gaps[-GAP_SAMPLES:]

    def _cursor_key(self, pass_name: str) -> str:
        """One cursor per pass, and per family within the session pass.

        They advance independently because they cover different data. A
        shared cursor means whichever pass ran last decides where the
        others resume from -- it narrows the chat window to ten minutes,
        and is the same corruption `_state_path_for` refuses to allow
        between two orgs.
        """
        return f"cursor:{pass_name}"

    def _resume_window(self, pass_name: str | None = None) -> str:
        if pass_name:
            last = self.state.data.get(self._cursor_key(pass_name))
            if not last:
                # A state file without this pass's cursor resumes from the
                # shared RUN_MARKER, read as it was AT ENTRY, not as an
                # earlier pass in this same run has left it.
                last = self._entry.get(RUN_MARKER)
        else:
            last = self.state.data.get("last_run_started_at")
        if not last:
            return _rfc3339(datetime.now(UTC) - timedelta(days=1))
        # Backdate: a session whose final call was still indexing at the
        # previous run's timestamp would otherwise be dropped permanently.
        try:
            parsed = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
        except ValueError:
            return _rfc3339(datetime.now(UTC) - timedelta(days=1))
        return _rfc3339(parsed - timedelta(minutes=self.lookback_minutes))

    def _scan_one(self, session: dict[str, Any], family: str) -> SessionReport | None:
        session_id = session.get("id")
        if not session_id:
            return None
        messages = list(
            self.client.session_messages(session_id, family, limit=self.page_limit)
        )
        start = time.perf_counter()
        units = compliance_units(messages)
        budget = Budget(self.policy.budget_ms)  # compliance.scan.budget_ms
        result = scan(units, self.detectors, budget, self.policy.sealer(self.org_id or None))
        result.detectors_skipped = with_left_out(result.detectors_skipped, self.left_out)
        extra, dropped = self._behaviour_findings(messages, result.findings)
        findings = list(result.findings) + extra
        result.detectors_skipped = with_left_out(result.detectors_skipped, dropped)
        verdict = decide(findings, self.policy, dropped=result.detectors_skipped)
        elapsed = (time.perf_counter() - start) * 1000.0

        user = session.get("user") or {}
        report = SessionReport(
            session_id=session_id,
            product_surface=session.get("product_surface"),
            user_id=user.get("id") if isinstance(user, dict) else None,
            created_at=session.get("created_at"),
            updated_at=session.get("updated_at"),
            action=verdict.action,
            findings=findings,
            messages=len(messages),
            scan_ms=elapsed,
            budget_exceeded=bool(result.budget_exceeded),
            tiers_dropped=list(result.detectors_skipped or []),
        )
        self._flag(session_id, report.product_surface, report.user_id, messages)
        self._sessions_seen.add(session_id)
        self.state.data.setdefault("sessions", {})[session_id] = {
            "updated_at": session.get("updated_at"),
            "messages": len(messages),
            "action": verdict.action,
            "findings": len(findings),
        }
        return report

    def _flag(self, session_id: str, surface: str | None, user: str | None,
              messages: list) -> None:
        """Ask the judge and the tool baseline about the session, and write
        a flag when either says to. A failure flags nothing and is logged."""
        if self._flag_store is None or (self._judge is None and self._baseline is None):
            return
        from ..behaviour import baseline as _baseline
        from ..behaviour import flags as _flags

        found: list[tuple[str, str]] = []
        if self._baseline is not None:
            actor = pseudonym(user, self.policy.hash_salt, "user") if user else None
            reason = self._fail_open("baseline", lambda: self._baseline.observe(
                surface, actor, session_id, _baseline.tools_in(messages)))
            if reason:
                found.append((reason, _flags.SOURCE_BASELINE))
        if self._judge is not None:
            reason = self._fail_open("judge", lambda: self._judge.judge(messages))
            if reason:
                found.append((reason, _flags.SOURCE_JUDGE))
        if found:
            reason, source = found[-1]
            if self._fail_open("write", lambda: _flags.write_flag(
                    self._flag_store, session_id, self.policy.hash_salt,
                    reason, source) or True):
                self.sessions_flagged += 1

    @staticmethod
    def _fail_open(check: str, run):
        """`run()`, or None, logged, when it raises."""
        try:
            return run()
        except Exception as exc:  # noqa: BLE001 - a check that fails flags nothing
            log.warning("session flag check failed", extra={"fields": {
                "check": check, "error": type(exc).__name__}})
            return None

    def _behaviour_findings(self, messages, dlp_findings) -> tuple[list, list[str]]:
        """(findings, checks that did not finish) of provenance and taint over
        the transcript, when the profile enables them.

        The same checks adapter 1 runs, after the fact and over every
        session, so a session the inference hook allowed or never saw is
        still judged -- and the behavioural checks get a backlog of real
        transcripts to measure against rather than waiting on live traffic.

        No session cache and a generous time limit: each session is read
        once per pass, with nobody waiting on the answer. A failure, or a
        pass cut short at the limit, is logged and reported as dropped.
        """
        if self._behaviour is None:
            return [], []
        from ..behaviour.provenance import from_compliance, run

        outcome = run(self._behaviour, from_compliance(messages), session=None,
                      findings=dlp_findings, time_budget_s=BEHAVIOUR_BUDGET_S)
        if outcome.error is not None:
            log.warning("behavioural check failed for a session",
                        extra={"fields": {"error": type(outcome.error).__name__}})
        elif outcome.dropped:
            log.warning("behavioural checks stopped at their time budget for a session",
                        extra={"fields": {"checks": outcome.dropped}})
        return outcome.findings, outcome.dropped

    # -- claude.ai chats ---------------------------------------------------

    def scan_chats(
        self,
        since: str | None = None,
        max_chats: int | None = None,
        include_artifacts: bool = True,
    ) -> Iterator[ChatReport]:
        """Scan claude.ai chats. The endpoint family the session scan misses."""
        run_started = _now_rfc3339()
        window_start = since or self._resume_window("chats")
        truncated = failed = False
        for count, chat in enumerate(
            self.client.list_chats(updated_at_gte=window_start, limit=self.page_limit)
        ):
            if max_chats is not None and count >= max_chats:
                truncated = True
                break
            try:
                report = self._scan_chat(chat, include_artifacts)
            except ComplianceError as exc:
                # As a session: a 404 is a chat deleted between the listing
                # and the fetch, and any other status is counted and holds
                # the cursor.
                if exc.status != 404:
                    failed = True
                    self.chats_failed += 1
                    log.warning("could not read a compliance chat's messages",
                                extra={"fields": {"status": exc.status}})
                continue
            if report is not None:
                failed = failed or report.artifacts_retryable > 0
                yield report

        # Its own cursor, advanced by its own pass. See `_cursor_key`. A chat
        # that could not be read, or with an artifact that could not be
        # fetched, other than with a 404, holds it back, as a truncated pass
        # does, so the next pass lists that chat again.
        if not truncated and not failed:
            self._pending[self._cursor_key("chats")] = run_started

    def _scan_chat(self, chat: dict[str, Any], include_artifacts: bool) -> ChatReport | None:
        chat_id = chat.get("id")
        if not chat_id:
            return None
        user = chat.get("user") or {}
        user_id = user.get("id") if isinstance(user, dict) else None
        # A chat deleted in claude.ai still lists, with deleted_at set. Its
        # messages are fetched and scanned while the API still serves them;
        # a 404 or an empty message list records it as deleted and unread.
        deleted_at = chat.get("deleted_at") or None
        if deleted_at is not None:
            deleted_at = str(deleted_at)
        try:
            full = self.client.chat_messages(chat_id)
        except ComplianceError as exc:
            if deleted_at is None or exc.status != 404:
                raise
            full = None
        if deleted_at is not None and not (full or {}).get("chat_messages"):
            dropped = [UNSCANNED_DELETED]
            return ChatReport(
                chat_id=chat_id, user_id=user_id, model=chat.get("model"),
                created_at=chat.get("created_at"), updated_at=chat.get("updated_at"),
                deleted_at=deleted_at, project_id=chat.get("project_id"),
                action=decide([], self.policy, dropped=dropped).action,
                content_read=False, tiers_dropped=dropped,
            )
        full = full if isinstance(full, dict) else {}
        start = time.perf_counter()
        units = chat_units({**full, "name": full.get("name", chat.get("name"))})

        artifacts = 0
        artifacts_failed = 0
        artifacts_retryable = 0
        if include_artifacts:
            # Artifacts hold generated code and markdown, so a credential
            # written into one is invisible to a message-text-only scan.
            for midx, message in enumerate(_list(full.get("chat_messages"))):
                message = message if isinstance(message, dict) else {}
                for aidx, art in enumerate(_list(message.get("artifacts"))):
                    art = art if isinstance(art, dict) else {}
                    version = art.get("version_id")
                    if not version:
                        # chat_units scanned any inline content. With none,
                        # the artifact was not read and is counted as such.
                        if isinstance(art.get("content"), str) and art["content"]:
                            artifacts += 1
                        else:
                            artifacts_failed += 1
                            log.warning("artifact has no version_id; not scanned",
                                        extra={"fields": {
                                            "chat": self.meta.one(chat_id,
                                                                  where="compliance:log")}})
                        continue
                    try:
                        body = self.client.artifact_content(version)
                    except Exception as exc:  # noqa: BLE001 - one artifact must not kill a pass
                        # Counted. This skipped silently and did not
                        # increment anything, so a chat whose artifact
                        # holds a credential and whose fetch 500s was
                        # reported clean -- with `artifacts_scanned`
                        # merely lower than it should have been, which is
                        # a number nobody can check against an expected
                        # value.
                        artifacts_failed += 1
                        if not (isinstance(exc, ComplianceError) and exc.status == 404):
                            artifacts_retryable += 1
                        log.warning("artifact fetch failed; not scanned",
                                    extra={"fields": {
                                        "chat": self.meta.one(chat_id, where="compliance:log"),
                                        "error": type(exc).__name__}})
                        continue
                    artifacts += 1
                    units.extend(
                        artifact_units(
                            f"msg[{midx}].artifacts[{aidx}].content",
                            body.get("content"),
                        )
                    )

        budget = Budget(self.policy.budget_ms)  # compliance.scan.budget_ms
        result = scan(units, self.detectors, budget, self.policy.sealer(self.org_id or None))
        result.detectors_skipped = with_left_out(result.detectors_skipped, self.left_out)
        dropped = list(result.detectors_skipped or [])
        if artifacts_failed:
            dropped.append(UNSCANNED_ARTIFACT)
        verdict = decide(result.findings, self.policy, dropped=dropped)
        elapsed = (time.perf_counter() - start) * 1000.0

        return ChatReport(
            chat_id=chat_id,
            name=chat.get("name"),
            user_id=user_id,
            model=chat.get("model"),
            created_at=chat.get("created_at"),
            updated_at=chat.get("updated_at"),
            deleted_at=deleted_at,
            project_id=chat.get("project_id"),
            action=verdict.action,
            findings=result.findings,
            messages=len(_list(full.get("chat_messages"))),
            artifacts_scanned=artifacts,
            artifacts_failed=artifacts_failed,
            artifacts_retryable=artifacts_retryable,
            scan_ms=elapsed,
            budget_exceeded=bool(result.budget_exceeded),
            tiers_dropped=dropped,
        )

    # -- activity feed join ------------------------------------------------

    def denials(self, since: str | None = None) -> Iterator[dict[str, Any]]:
        """Yield inference_hooks_request_denied activities, newest first."""
        cursor = self.state.data.get("activities_cursor")
        last_seen = None
        for activity, last_id, _has_more in self.client.activities(
            activity_types=[DENIED_ACTIVITY],
            after_id=cursor,
            created_at_gte=since,
            limit=self.page_limit,
        ):
            last_seen = last_id or last_seen
            yield activity
        if last_seen:
            self._pending["activities_cursor"] = last_seen

    @staticmethod
    def extract_reference_id(activity: dict[str, Any]) -> str | None:
        """Our reference_id from a denial activity: its `reference_id` field,
        as the API reference documents on inference_hooks_request_denied."""
        value = activity.get("reference_id")
        return value if isinstance(value, str) and value else None

    def join_denials(
        self, reports: list[SessionReport], since: str | None = None
    ) -> dict[str, Any]:
        """Correlate our own scan output with Anthropic's denial records."""
        activities = list(self.denials(since))
        by_reference: dict[str, dict[str, Any]] = {}
        unjoinable = 0
        for activity in activities:
            ref = self.extract_reference_id(activity)
            if ref is None:
                unjoinable += 1
                continue
            by_reference[ref] = activity

        return {
            "denial_activities": len(activities),
            "with_request_id": sum(1 for a in activities
                                   if isinstance(a.get("request_id"), str) and a["request_id"]),
            "tool_call": sum(1 for a in activities if a.get("event") == "tool_call"),
            "with_reference_id": len(by_reference),
            "without_reference_id": unjoinable,
            "reference_ids": sorted(by_reference),
            "sessions_scanned": len(reports),
            "sessions_would_deny": sum(1 for r in reports if r.action == ACTION_DENY),
        }


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _parse_ts(value: Any) -> datetime | None:
    """An RFC 3339 timestamp as an aware datetime, or None."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _now_rfc3339() -> str:
    return _rfc3339(datetime.now(UTC))


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
