"""Adapter 3 as a scheduled ingest job.

Runs on a cron (an ACA Job), holds the Compliance Access Key, scans
transcripts with the shared core, and writes findings to the store. The
dashboard reads the store and never sees the key -- which is the whole point
of splitting ingest from presentation: the credential that can read every
chat in the org stays in a job that nobody signs into.

Writes findings only. Never transcript content.
"""

from __future__ import annotations

import logging
from typing import Any

from .. import build_id
from ..metadata import MetadataGuard, refuse_unsafe_labels
from ..plugins import describe_for_log
from ..store.base import (
    SOURCE_COMPLIANCE_SCAN,
    DenialRecord,
    FindingRow,
    VerdictRecord,
    pseudonym,
)
from .client import ComplianceError
from .scanner import ChatReport, ComplianceScanner, SessionReport

log = logging.getLogger("forgd_verdict.ingest")


def report_to_record(
    report: SessionReport, salt: str = "", org_id: str = ""
) -> VerdictRecord:
    # observed_at is when the scan ran, NOT when the session was active.
    # Using the session's timestamp meant a pass over older sessions wrote
    # records dated in the past, so every time window and the statistics
    # reset excluded work that had just been done -- the dashboard read zero
    # sessions immediately after a successful ingest.
    from ..store.base import utcnow

    return VerdictRecord(
        source=SOURCE_COMPLIANCE_SCAN,
        observed_at=utcnow(),
        session_started_at=report.created_at,
        session_updated_at=report.updated_at,
        session_id=report.session_id,
        surface=report.product_surface,
        tenant_hash=pseudonym(org_id, salt, "org"),
        actor_hash=pseudonym(report.user_id, salt, "user"),
        messages_total=report.messages,
        messages_scanned=report.messages,
        action=report.action,
        scan_ms=report.scan_ms,
        findings_count=len(report.findings),
        findings=[FindingRow.from_finding(f) for f in report.findings],
        budget_exceeded=report.budget_exceeded,
        tiers_dropped=list(report.tiers_dropped),
        build=build_id(),
    )


def chat_to_record(
    report: ChatReport, salt: str = "", org_id: str = ""
) -> VerdictRecord:
    """A claude.ai chat, as a post-hoc observation.

    `surface` is set to `claude-ai` so it lines up with the inference hook's
    source.application for the same product -- that alignment is what makes
    the reconciliation view able to say "the inline control saw N of these
    prompts and the post-hoc scan found M values it never reported".
    """
    from ..store.base import utcnow

    return VerdictRecord(
        source=SOURCE_COMPLIANCE_SCAN,
        observed_at=utcnow(),
        session_id=report.chat_id,
        session_started_at=report.created_at,
        session_updated_at=report.updated_at,
        deleted_at=report.deleted_at,
        surface="claude-ai",
        tenant_hash=pseudonym(org_id, salt, "org"),
        actor_hash=pseudonym(report.user_id, salt, "user"),
        model=report.model,
        # None, not 0, for a chat none of whose messages could be read.
        messages_total=report.messages if report.content_read else None,
        messages_scanned=report.messages if report.content_read else None,
        action=report.action,
        scan_ms=report.scan_ms,
        findings_count=len(report.findings),
        findings=[FindingRow.from_finding(f) for f in report.findings],
        budget_exceeded=report.budget_exceeded,
        tiers_dropped=list(report.tiers_dropped),
        build=build_id(),
    )


def activity_to_denial(
    activity: dict[str, Any],
    scanner: ComplianceScanner,
    salt: str = "",
    org_id: str = "",
) -> DenialRecord:
    actor = activity.get("actor") or {}
    return DenialRecord(
        activity_id=str(activity.get("id") or ""),
        created_at=str(activity.get("created_at") or ""),
        reference_id=scanner.extract_reference_id(activity),
        tenant_hash=pseudonym(org_id, salt, "org"),
        actor_hash=pseudonym(
            actor.get("user_id") or actor.get("email_address"), salt, "user"
        ),
    )


# The session endpoint families. `local` and `remote` are different
# populations, not two views of one: `local` holds office agents, Cowork
# and Claude Code sessions, `remote` holds Cowork remote ones, and they do
# not overlap.
#
# Both by default. Scanning `local` only leaves every remote session
# invisible to every run, and the coverage matrix reports the gap as an
# empty cell rather than as something not looked at.
FAMILIES = ("local", "remote")


def parse_families(value: str | None) -> list[str]:
    """`--family local,remote` -> ['local', 'remote']. Order preserved.

    An unknown name is refused rather than skipped. A typo that silently
    scanned nothing would report `sessions_scanned: 0`, which is
    indistinguishable from a quiet org -- the failure this whole change
    is about.
    """
    if not value:
        return list(FAMILIES)
    names = [v.strip() for v in str(value).split(",") if v.strip()]
    unknown = [n for n in names if n not in FAMILIES]
    if unknown:
        raise ValueError(
            f"unknown session family {unknown}; known families are "
            f"{list(FAMILIES)}"
        )
    # Deduplicated: two passes over one family share a cursor and the
    # second would scan nothing while looking like coverage.
    out: list[str] = []
    for n in names:
        if n not in out:
            out.append(n)
    return out


def run_ingest(
    policy,
    store,
    *,
    family: str = "local",
    since: str | None = None,
    max_sessions: int | None = None,
    include_denials: bool = True,
    include_chats: bool = True,
    batch_size: int = 50,
) -> dict[str, Any]:
    """One ingest pass across every configured org. Summary for logging.

    Orgs are scanned SERIALLY. The Compliance client is already deliberately
    serial and rate-limited; the limits are per-org, but a parallel pass
    turns one rate-limited job into several competing for the same runner on
    a six-hourly cron with nobody waiting. There is nothing to buy.
    """
    from ..applog import warn_if_unsalted
    from ..policy import warn_unset_credentials

    policy.refuse_unsalted("compliance ingest")
    warn_if_unsalted(log, policy)
    warn_unset_credentials(log, policy, "ingest")
    families = parse_families(family)
    orgs = policy.compliance_orgs()
    detectors = policy.for_profile("compliance").build_detectors(profile="compliance")
    refuse_unsafe_labels([org.get("label") for org in orgs],
                         MetadataGuard(detectors, allow_subprocess=True),
                         "compliance org")
    totals = {
        "sessions_scanned": 0,
        "sessions_with_findings": 0,
        "sessions_failed": 0,
        "chats_scanned": 0,
        "chats_with_findings": 0,
        "chats_failed": 0,
        "chats_deleted_unread": 0,
        "artifacts_scanned": 0,
        "artifacts_failed": 0,
        "verdicts_written": 0,
        "denials_written": 0,
    }
    per_org: list[dict[str, Any]] = []
    for org in orgs:
        try:
            result = _ingest_one_org(
                policy, store, org,
                families=families, since=since, max_sessions=max_sessions,
                include_denials=include_denials, include_chats=include_chats,
                batch_size=batch_size, detectors=detectors,
            )
        except Exception as exc:  # noqa: BLE001
            # One org's key expiring must not abandon the others. Recorded
            # per org and surfaced in the summary: a pass that scanned two
            # of three orgs and reported success would be worse than one
            # that crashed, because nobody would look.
            # log.error, not log.exception. The traceback carries the
            # full `str(exc)`, `JsonFormatter` emits it deliberately, and
            # with logging unconfigured -- the cron path -- it still
            # reaches stderr. The `fields` here were already careful and
            # the traceback went around them.
            log.error("ingest failed for an org", extra={
                "fields": {"org": org.get("label"),
                           "error": type(exc).__name__,
                           "status": getattr(exc, "status", None)}
            })
            per_org.append({
                "org": org.get("label"),
                "ok": False,
                # The TYPE and the status, never the message. This summary
                # is logged wholesale and the CLI prints it to stdout.
                "error": type(exc).__name__,
                "status": getattr(exc, "status", None),
            })
            continue
        per_org.append({"org": org.get("label"), "ok": True, **result})
        for key in totals:
            totals[key] += result.get(key, 0)

    failed = [o for o in per_org if not o["ok"]]
    summary = {
        "families": families,
        "since": since,
        "orgs_configured": len(orgs),
        "orgs_scanned": len(per_org) - len(failed),
        "orgs_failed": len(failed),
        **totals,
        "orgs": per_org,
        "store": describe_for_log(store),
    }
    log.info("ingest complete", extra={"fields": summary})
    return summary


def _ingest_one_org(
    policy,
    store,
    org: dict[str, Any],
    *,
    families: list[str],
    since: str | None,
    max_sessions: int | None,
    include_denials: bool,
    include_chats: bool,
    batch_size: int,
    detectors: list[Any] | None = None,
) -> dict[str, Any]:
    # The store holds the cursor as well as the findings.
    scanner = ComplianceScanner(policy, org=org, store=store, detectors=detectors)
    salt = policy.hash_salt
    org_id = scanner.org_id

    meta = MetadataGuard(scanner.detectors, salt, allow_subprocess=True)
    sessions = denies = written = 0
    batch: list[VerdictRecord] = []
    # Each family gets its own pass and its own cursor. A family the org
    # does not have answers 404, which is skipped rather than failing the
    # org: a Team workspace has no remote sessions and that is not a
    # fault, it is a different product.
    per_family: dict[str, int] = {}
    for fam in families:
        before = sessions
        try:
            for report in scanner.scan_sessions(
                family=fam, since=since, max_sessions=max_sessions
            ):
                sessions += 1
                if report.action == "deny":
                    denies += 1
                batch.append(report_to_record(report, salt, org_id))
                if len(batch) >= batch_size:
                    written += store.write_verdicts(meta.records(batch))
                    batch = []
        except ComplianceError as exc:
            if getattr(exc, "status", None) != 404:
                raise
            log.info("session family not available for this org", extra={
                "fields": {"org": org.get("label"), "family": fam}})
            continue
        per_family[fam] = sessions - before
    if batch:
        written += store.write_verdicts(meta.records(batch))
        batch = []
    scanner.commit()

    # claude.ai chats live in a different endpoint family from sessions.
    # Scanning only sessions means every prompt typed into claude.ai is
    # invisible, which is the gap that made an obviously-seeded AWS key fail
    # to appear in the findings.
    chats = chat_denies = chat_rows = artifacts = artifacts_failed = chats_unread = 0
    if include_chats:
        batch = []
        for report in scanner.scan_chats(since=since):
            chats += 1
            artifacts += report.artifacts_scanned
            artifacts_failed += report.artifacts_failed
            chats_unread += not report.content_read
            if report.action == "deny":
                chat_denies += 1
            batch.append(chat_to_record(report, salt, org_id))
            if len(batch) >= batch_size:
                chat_rows += store.write_verdicts(meta.records(batch))
                batch = []
        if batch:
            chat_rows += store.write_verdicts(meta.records(batch))
        scanner.commit()

    denial_rows = 0
    if include_denials:
        # The Activity Feed is Anthropic's record of what it actually
        # blocked. Stored separately from our own verdicts so the join is
        # explicit rather than assumed.
        pending: list[DenialRecord] = []
        for activity in scanner.denials(since=since):
            pending.append(activity_to_denial(activity, scanner, salt, org_id))
            if len(pending) >= batch_size:
                denial_rows += store.write_denials(meta.records(pending))
                pending = []
        if pending:
            denial_rows += store.write_denials(meta.records(pending))
        scanner.commit()

    return {
        "sessions_scanned": sessions,
        "sessions_with_findings": denies,
        "sessions_failed": scanner.sessions_failed,
        "chats_scanned": chats,
        "chats_with_findings": chat_denies,
        "chats_failed": scanner.chats_failed,
        "chats_deleted_unread": chats_unread,
        "artifacts_scanned": artifacts,
        "artifacts_failed": artifacts_failed,
        "verdicts_written": written + chat_rows,
        "denials_written": denial_rows,
    }
