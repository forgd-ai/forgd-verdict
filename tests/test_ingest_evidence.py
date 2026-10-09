"""A later observation of a session that read less never stands in for an
earlier one that found something: a deleted chat, a history read in part,
or a rescan of fewer messages."""

from __future__ import annotations

import asyncio
import itertools
from dataclasses import replace

import pytest
from conftest import FAKE_AWS_KEY, make_policy

from forgd_verdict.compliance.client import ComplianceError
from forgd_verdict.compliance.ingest import chat_to_record
from forgd_verdict.compliance.scanner import ComplianceScanner
from forgd_verdict.models import UNSCANNED_DELETED, UNSCANNED_PARTIAL
from forgd_verdict.store.base import (
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_MANAGED_SCAN,
    FindingRow,
    VerdictRecord,
)
from forgd_verdict.store.local import LocalFileStore
from forgd_verdict.store.query import (
    build_summary,
    latest_per_session,
    preferred_observation,
    session_preference,
)

CHAT_ID = "claude_chat_01H5CWunD7RpVJ5bHa8RCkja"
LISTED = {"id": CHAT_ID, "name": "deploy help", "created_at": "2026-09-17T20:00:00Z",
          "updated_at": "2026-09-17T21:01:00Z", "deleted_at": None,
          "user": {"id": "user_01Xy"}}
DELETED = {**LISTED, "deleted_at": "2026-09-18T09:00:00Z",
           "updated_at": "2026-09-18T09:00:00Z", "name": ""}


class Chats:
    """A Compliance client serving one listing; `messages` is the chat's
    messages response, or the status its fetch answers."""

    def __init__(self, listed, messages):
        self.listed, self.messages = listed, messages

    def list_chats(self, **_):
        yield self.listed

    def chat_messages(self, chat_id, limit=None):
        if isinstance(self.messages, int):
            raise ComplianceError(self.messages, "", "https://x/v1/compliance/apps/chats")
        return self.messages

    def artifact_content(self, version_id):
        raise AssertionError("no artifact here")


def _scanner(tmp_path, client):
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(tmp_path / "s.json"), "api_key": "sk-ant-api01-x"},
    )
    return ComplianceScanner(policy, client=client)


def _pass(tmp_path, store, client, observed_at):
    (report,) = list(_scanner(tmp_path, client).scan_chats())
    record = replace(chat_to_record(report, org_id="org-a"), observed_at=observed_at)
    store.write_verdicts([record])
    return record


def test_a_chat_deleted_after_a_detection_stays_detected(tmp_path):
    """The reproducer: run 1 scans the live chat and detects the key; the
    user deletes the chat; run 2 lists it with deleted_at and its messages
    404. Every summary still says detected, and the row says deleted."""
    store = LocalFileStore(str(tmp_path / "store"))
    live = {**LISTED, "chat_messages": [
        {"id": "m1", "role": "user",
         "content": [{"type": "text", "text": f"export AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}"}]}]}
    first = _pass(tmp_path, store, Chats(LISTED, live), "2026-09-17T22:00:00Z")
    second = _pass(tmp_path, store, Chats(DELETED, 404), "2026-09-18T10:00:00Z")
    assert first.disposition == "detected"
    assert second.disposition == "deleted" and second.tiers_dropped == [UNSCANNED_DELETED]

    records = list(store.read_verdicts(None))
    assert len(records) == 2
    (kept,) = latest_per_session(records)
    assert kept.disposition == "detected"
    assert kept.deleted_at == DELETED["deleted_at"]
    summary = build_summary(records)
    assert summary.detections == 1
    assert summary.reconciliation.scan_detections == 1
    assert summary.deleted_unread == 0


def test_a_chat_deleted_before_any_pass_is_deleted_and_unread_not_clean(tmp_path):
    store = LocalFileStore(str(tmp_path / "store"))
    _pass(tmp_path, store, Chats(DELETED, 404), "2026-09-18T10:00:00Z")
    (kept,) = latest_per_session(store.read_verdicts(None))
    assert kept.disposition == "deleted"
    assert kept.messages_total is None
    summary = build_summary(store.read_verdicts(None))
    assert summary.deleted_unread == 1
    assert summary.detections == 0


def test_the_connector_record_tool_returns_the_kept_observation(monkeypatch):
    from forgd_verdict.connector import tools

    records = [_rec(observed_at="2026-09-17T22:00:00Z", detected=True, messages=3),
               _rec(observed_at="2026-09-18T10:00:00Z", unread=True, deleted=True)]

    class Store:
        orgs = None

        def read_verdicts(self, since, orgs):
            return list(records)

        def read_denials(self, since, orgs):
            return []

    class Caller:
        def scoped(self, _):
            return Store()

        def org(self, org):
            return {"org": org}

    monkeypatch.setattr(tools, "_since", lambda store, window: None)
    out = asyncio.run(tools.record(Caller(), session_id=CHAT_ID))
    assert out["record"]["disposition"] == "detected"
    assert out["record"]["deleted_at"] == "2026-09-18T09:00:00Z"
    assert out["earlier_observations"] == 1


def _rec(*, observed_at="2026-09-18T00:00:00Z", detected=False, flagged=False,
         unread=False, partial=False, messages=5, deleted=False,
         source=SOURCE_COMPLIANCE_SCAN) -> VerdictRecord:
    findings = []
    if detected:
        findings.append(FindingRow("regex:aws-access-key", "block", "msg[0]", "h-block"))
    if flagged:
        findings.append(FindingRow("presidio:person", "warn", "msg[0]", "h-warn"))
    tiers = [UNSCANNED_DELETED] if unread else []
    if partial:
        tiers.append(UNSCANNED_PARTIAL)
    return VerdictRecord(
        source=source, session_id=CHAT_ID, observed_at=observed_at,
        deleted_at="2026-09-18T09:00:00Z" if deleted else None,
        messages_total=None if unread else messages,
        messages_scanned=None if unread else messages,
        tiers_dropped=tiers, findings=findings, findings_count=len(findings),
        action="deny" if detected else "allow")


_SHAPES = [dict(zip(("detected", "flagged", "unread", "partial", "messages", "deleted"), v,
                    strict=True))
           for v in itertools.product((False, True), (False, True), (False, True),
                                      (False, True), (0, 3, 9), (False, True))
           if not (v[2] and (v[0] or v[1] or v[4]))]


@pytest.mark.parametrize("source", [SOURCE_COMPLIANCE_SCAN, SOURCE_MANAGED_SCAN])
def test_no_later_observation_with_less_evidence_replaces_an_earlier_one(source):
    """Every pair of observation shapes, the stronger one first in time.
    The later one is kept only when it found as much: a detection is never
    replaced by a record without one, a flag by one without a finding, a
    read by an unread record, a whole history by a partial one, or more
    messages by fewer, at the same level of finding."""
    for a, b in itertools.product(_SHAPES, repeat=2):
        early = _rec(observed_at="2026-09-17T00:00:00Z", source=source, **a)
        late = _rec(observed_at="2026-09-18T00:00:00Z", source=source, **b)
        (kept,) = latest_per_session([early, late])
        assert kept == preferred_observation([late, early]), (a, b)
        same_finding = (late.detected, late.flagged) == (early.detected, early.flagged)
        both_read = not a["unread"] and not b["unread"]
        if early.detected and not late.detected:
            assert kept.detected, (a, b)
        if early.flagged and not late.flagged and same_finding is False \
                and early.detected == late.detected:
            assert kept.flagged, (a, b)
        if not a["unread"] and b["unread"]:
            assert UNSCANNED_DELETED not in kept.tiers_dropped, (a, b)
        if same_finding and both_read and not a["partial"] and b["partial"]:
            assert UNSCANNED_PARTIAL not in kept.tiers_dropped, (a, b)
        if same_finding and both_read and a["partial"] == b["partial"] \
                and a["messages"] > b["messages"]:
            assert kept.messages_total == a["messages"], (a, b)
        if late.deleted_at:
            assert kept.deleted_at == late.deleted_at, (a, b)


def test_session_preference_ranks_finding_then_read_then_whole_then_count_then_time():
    order = [
        _rec(unread=True, messages=0),
        _rec(partial=True, messages=9),
        _rec(messages=3, observed_at="2026-09-19T00:00:00Z"),
        _rec(messages=9, observed_at="2026-09-17T00:00:00Z"),
        _rec(messages=9, observed_at="2026-09-18T00:00:00Z"),
        _rec(flagged=True, unread=False, messages=1),
        _rec(detected=True, partial=True, messages=1),
        _rec(detected=True, messages=1),
    ]
    assert sorted(order, key=session_preference) == order


def test_the_summary_window_applies_before_the_collapse():
    """A detection outside the window does not count in it; the deletion
    observed inside it is what the window shows, as deleted, never clean."""
    records = [_rec(observed_at="2026-09-01T00:00:00Z", detected=True),
               _rec(observed_at="2026-09-18T10:00:00Z", unread=True, deleted=True)]
    summary = build_summary(records, since="2026-09-10T00:00:00Z")
    assert summary.detections == 0
    assert summary.deleted_unread == 1
    assert summary.scanned_sessions == 1


def test_an_inline_record_is_never_collapsed():
    from forgd_verdict.store.base import SOURCE_CODE_HOOK

    rows = [replace(_rec(), source=SOURCE_CODE_HOOK, request_id=f"r{i}") for i in range(3)]
    assert len(latest_per_session(rows)) == 3
