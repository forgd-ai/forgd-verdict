"""Members' saved instructions: `user_preferences`, scanned by adapter 3.

The text a member saves as Instructions for Claude, or as Cowork's Global
instructions, is sent with every chat. Shape from platform.claude.com/docs/
en/manage-claude/compliance-org-data, verified 2026-11-28.
"""

from __future__ import annotations

import json
import logging
import uuid

import pytest
from conftest import FAKE_AWS_KEY, make_policy

from forgd_verdict.compliance import scanner as scanner_mod
from forgd_verdict.compliance.client import ComplianceClient, ComplianceError
from forgd_verdict.compliance.ingest import instructions_to_record, run_ingest
from forgd_verdict.compliance.scanner import (
    INSTRUCTIONS_STATE,
    INSTRUCTIONS_SURFACE,
    ComplianceScanner,
)
from forgd_verdict.store.base import pseudonym
from forgd_verdict.store.local import LocalFileStore
from forgd_verdict.store.query import build_summary, latest_per_session

SALT = "s"
ORG = str(uuid.uuid4())
DETECTORS = {"gitleaks": {"enabled": False, "severity": "block"}}


def _member(uid, conversation=None, cowork=None):
    return {"user": {"id": uid, "email_address": f"{uid}@example.com"},
            "conversation_preferences": conversation, "cowork_global_instructions": cowork}


class Preferences:
    """A Compliance client serving `user_preferences` pages, and nothing
    for the other passes. `fail_after` raises once that many pages are
    served."""

    def __init__(self, pages, fail_after=None, status=500):
        self.pages, self.fail_after, self.status = pages, fail_after, status
        self.calls: list[tuple[str, dict]] = []

    def user_preferences(self, org_uuid, **kwargs):
        self.calls.append((org_uuid, kwargs))
        for n, page in enumerate(self.pages):
            if self.fail_after is not None and n >= self.fail_after:
                raise ComplianceError(self.status, "", "https://x/v1/compliance/organizations")
            yield from page

    def list_sessions(self, family="local", **kwargs):
        return iter(())

    def list_chats(self, **kwargs):
        return iter(())

    def activities(self, **kwargs):
        return iter(())


def _policy(tmp_path, org_id=ORG):
    compliance = {"api_key": "sk-ant-api01-x", "state_path": str(tmp_path / "s.json")}
    if org_id:
        compliance["org_id"] = org_id
    return make_policy(privacy={"hash_salt": SALT}, detectors=DETECTORS, compliance=compliance)


def _scanner(tmp_path, client, org_id=ORG):
    return ComplianceScanner(_policy(tmp_path, org_id), client=client)


def _pass(tmp_path, client):
    scanner = _scanner(tmp_path, client)
    reports = list(scanner.scan_user_preferences())
    scanner.commit()
    return reports, scanner


# --- the scanner ---------------------------------------------------------


def test_a_credential_in_saved_instructions_is_found(tmp_path):
    client = Preferences([[_member("user_a", conversation=f"deploy with {FAKE_AWS_KEY}",
                                   cowork="be brief")]])
    reports, _ = _pass(tmp_path, client)
    by_field = {r.field_name: r for r in reports}
    assert set(by_field) == {"conversation_preferences", "cowork_global_instructions"}
    assert by_field["conversation_preferences"].action == "deny"
    assert by_field["conversation_preferences"].findings
    assert by_field["cowork_global_instructions"].action == "allow"
    assert all(r.org_id == ORG for r in reports)
    # Every page asks for unset members too, so a cleared field is seen.
    assert client.calls == [(ORG, {"include_unset": True, "limit": 100})]


def test_the_cursor_keeps_a_digest_never_the_text(tmp_path):
    _pass(tmp_path, Preferences([[_member("user_a", conversation=f"key {FAKE_AWS_KEY}")]]))
    saved = (tmp_path / "s.json").read_text()
    assert FAKE_AWS_KEY not in saved and "user_a" not in saved
    state = json.loads(saved)[INSTRUCTIONS_STATE]
    member = pseudonym("user_a", SALT, "user")
    assert set(state) == {member}
    assert set(state[member]) == {"conversation_preferences"}


def test_unchanged_text_is_not_rescanned(tmp_path):
    pages = [[_member("user_a", conversation="be brief")]]
    first, _ = _pass(tmp_path, Preferences(pages))
    second, _ = _pass(tmp_path, Preferences(pages))
    assert len(first) == 1 and second == []


def test_changed_text_is_rescanned(tmp_path):
    _pass(tmp_path, Preferences([[_member("user_a", conversation="be brief")]]))
    reports, _ = _pass(tmp_path, Preferences(
        [[_member("user_a", conversation=f"key {FAKE_AWS_KEY}")]]))
    assert [(r.field_name, r.action) for r in reports] == [("conversation_preferences", "deny")]


def test_a_cleared_field_yields_a_clean_report_and_leaves_the_cursor(tmp_path):
    _pass(tmp_path, Preferences([[_member("user_a", conversation=f"key {FAKE_AWS_KEY}")]]))
    reports, _ = _pass(tmp_path, Preferences([[_member("user_a")]]))
    (report,) = reports
    assert report.cleared and report.action == "allow" and not report.findings
    assert json.loads((tmp_path / "s.json").read_text())[INSTRUCTIONS_STATE] == {}
    # Cleared once, not on every pass after.
    again, _ = _pass(tmp_path, Preferences([[_member("user_a")]]))
    assert again == []


def test_every_page_is_read_including_an_empty_one(tmp_path):
    client = Preferences([[_member("user_a", conversation="one")], [],
                          [_member("user_b", conversation="two")]])
    reports, _ = _pass(tmp_path, client)
    assert sorted(r.user_id for r in reports) == ["user_a", "user_b"]


def test_a_pass_that_fails_midway_keeps_the_old_digests(tmp_path):
    pages = [[_member("user_a", conversation="one")], [_member("user_b", conversation="two")]]
    _pass(tmp_path, Preferences(pages))
    before = (tmp_path / "s.json").read_text()
    scanner = _scanner(tmp_path, Preferences(
        [[_member("user_a", conversation="changed")], *pages[1:]], fail_after=1))
    with pytest.raises(ComplianceError):
        list(scanner.scan_user_preferences())
    scanner.commit()
    assert json.loads((tmp_path / "s.json").read_text())[INSTRUCTIONS_STATE] == \
        json.loads(before)[INSTRUCTIONS_STATE]


def test_a_member_without_an_id_is_skipped(tmp_path):
    client = Preferences([[{"user": {}, "conversation_preferences": "x"},
                           {"conversation_preferences": "y"}]])
    reports, _ = _pass(tmp_path, client)
    assert reports == []


def test_no_org_uuid_scans_nothing(tmp_path, caplog):
    client = Preferences([[_member("user_a", conversation="x")]])
    with caplog.at_level(logging.INFO, logger="forgd_verdict.compliance"):
        reports = list(_scanner(tmp_path, client, org_id="").scan_user_preferences())
    assert reports == [] and client.calls == []
    assert any("organization UUID" in r.getMessage() for r in caplog.records)


# --- records -------------------------------------------------------------


def test_a_record_names_the_field_and_member_never_the_user_id(tmp_path):
    reports, _ = _pass(tmp_path, Preferences(
        [[_member("user_a", conversation=f"key {FAKE_AWS_KEY}")]]))
    record = instructions_to_record(reports[0], SALT)
    member = pseudonym("user_a", SALT, "user")
    assert record.surface == INSTRUCTIONS_SURFACE
    tenant = pseudonym(ORG, SALT, "org")
    assert record.session_id == f"instructions:conversation_preferences:{tenant}:{member}"
    assert record.actor_hash == member
    assert record.tenant_hash == pseudonym(ORG, SALT, "org")
    assert record.action == "deny" and record.findings_count == 1
    assert "user_a" not in json.dumps(record.__dict__, default=str)


def test_a_detection_stays_the_latest_after_the_text_is_cleared(tmp_path):
    """As for a deleted chat: the credential went out with every chat while
    it was saved, and clearing the text does not undo that."""
    first, _ = _pass(tmp_path, Preferences(
        [[_member("user_a", conversation=f"key {FAKE_AWS_KEY}")]]))
    cleared, _ = _pass(tmp_path, Preferences([[_member("user_a")]]))
    records = [instructions_to_record(r, SALT) for r in first + cleared]
    (kept,) = latest_per_session(records)
    assert kept.action == "deny"


def test_a_member_of_two_orgs_keeps_a_record_under_each(tmp_path):
    """The text is account-level: the API returns it under both orgs, and
    each org's view must show it."""
    other = str(uuid.uuid4())
    page = [[_member("user_a", conversation=f"key {FAKE_AWS_KEY}")]]
    records = []
    for n, org in enumerate((ORG, other)):
        scanner = ComplianceScanner(_policy(tmp_path / str(n), org), client=Preferences(page))
        records += [instructions_to_record(r, SALT) for r in scanner.scan_user_preferences()]
    kept = latest_per_session(records)
    assert sorted(r.tenant_hash for r in kept) == sorted(
        [pseudonym(ORG, SALT, "org"), pseudonym(other, SALT, "org")])


def test_the_summary_counts_findings_but_not_requests_or_sessions(tmp_path):
    """A thousand members with instructions set are not a thousand scanned
    sessions: counting them so would skew coverage and reconciliation."""
    reports, _ = _pass(tmp_path, Preferences(
        [[_member("user_a", conversation=f"key {FAKE_AWS_KEY}", cowork="be brief"),
          _member("user_b", conversation="be brief")]]))
    summary = build_summary([instructions_to_record(r, SALT) for r in reports])
    assert summary.instructions_checked == 3
    assert summary.instructions_detected == 1
    assert summary.total_findings == 1
    assert summary.total_requests == 0
    assert summary.scanned_sessions == 0
    assert summary.reconciliation.scanned_sessions == 0
    row = {r.surface: r for r in summary.surfaces}[INSTRUCTIONS_SURFACE]
    assert row.findings == 1 and row.detections == 1
    assert row.requests == 0 and row.post_hoc == 0


# --- the ingest pass -----------------------------------------------------


def _ingest(tmp_path, monkeypatch, client, **kwargs):
    monkeypatch.setattr(scanner_mod, "ComplianceClient", lambda **_: client)
    store = LocalFileStore(str(tmp_path / "store"))
    return store, run_ingest(_policy(tmp_path), store, **kwargs)


def test_ingest_writes_the_records_and_counts_them(tmp_path, monkeypatch):
    client = Preferences([[_member("user_a", conversation=f"key {FAKE_AWS_KEY}"),
                           _member("user_b", cowork="be brief")]])
    store, summary = _ingest(tmp_path, monkeypatch, client)
    records = [r for r in store.read_verdicts() if r.surface == INSTRUCTIONS_SURFACE]
    assert len(records) == 2
    assert summary["instructions_scanned"] == 2
    assert summary["instructions_with_findings"] == 1
    assert summary["instructions_failed"] == 0
    assert summary["verdicts_written"] == 2


def test_ingest_skips_instructions_when_asked(tmp_path, monkeypatch):
    client = Preferences([[_member("user_a", conversation="x")]])
    _, summary = _ingest(tmp_path, monkeypatch, client, include_instructions=False)
    assert client.calls == [] and summary["instructions_scanned"] == 0


def test_an_org_without_the_endpoint_is_not_a_failure(tmp_path, monkeypatch):
    client = Preferences([[_member("user_a", conversation="x")]], fail_after=0, status=404)
    _, summary = _ingest(tmp_path, monkeypatch, client)
    assert summary["orgs_failed"] == 0 and summary["instructions_failed"] == 0


def test_a_failed_read_costs_the_pass_not_the_org(tmp_path, monkeypatch, caplog):
    client = Preferences([[_member("user_a", conversation="x")]], fail_after=0, status=500)
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.ingest"):
        _, summary = _ingest(tmp_path, monkeypatch, client)
    assert summary["orgs_failed"] == 0 and summary["instructions_failed"] == 1
    (record,) = [r for r in caplog.records if "saved instructions" in r.getMessage()]
    assert record.fields["status"] == 500


def test_the_cli_flag_turns_the_pass_off(monkeypatch):
    from forgd_verdict import cli

    seen = []
    monkeypatch.setattr(cli, "_cmd_ingest", lambda args: seen.append(args) or 0)
    assert cli.main(["ingest", "--no-instructions"]) == 0
    assert cli.main(["ingest"]) == 0
    assert [a.no_instructions for a in seen] == [True, False]


# --- the client ----------------------------------------------------------


def test_the_client_resends_include_unset_on_every_page(monkeypatch):
    sent: list[tuple[str, dict]] = []
    pages = iter([{"data": [_member("user_a")], "next_page": "p2"},
                  {"data": [], "next_page": "p3"},
                  {"data": [_member("user_b")], "next_page": None}])

    def fake_get(self, path, params=None):
        sent.append((path, dict(params or {})))
        return next(pages)

    monkeypatch.setattr(ComplianceClient, "get", fake_get)
    client = ComplianceClient(api_key="sk-ant-api01-x")
    users = [m["user"]["id"] for m in client.user_preferences(ORG, include_unset=True,
                                                              limit=500)]
    assert users == ["user_a", "user_b"]
    assert [p for _, p in sent] == [
        {"limit": 100, "include_unset": "true"},
        {"limit": 100, "include_unset": "true", "page": "p2"},
        {"limit": 100, "include_unset": "true", "page": "p3"},
    ]
    assert {path for path, _ in sent} == {
        f"/v1/compliance/organizations/{ORG}/user_preferences"}
