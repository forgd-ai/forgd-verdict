"""Adapter 3, driven by a stub client. No network.

Shapes come from platform.claude.com/docs/en/manage-claude/compliance-sessions
and .../compliance-activity-feed, verified 2026-09-17.
"""

from __future__ import annotations

import json

import pytest
from conftest import FAKE_AWS_KEY, make_policy

from forgd_verdict.compliance.client import ComplianceClient, _encode_params
from forgd_verdict.compliance.scanner import ComplianceScanner
from forgd_verdict.extract import compliance_units


class StubClient:
    """Records the calls made, replays canned pages."""

    def __init__(self, sessions=None, messages=None, activities=None):
        self._sessions = sessions or []
        self._messages = messages or {}
        self._activities = activities or []
        self.calls: list[tuple] = []

    def list_sessions(self, family="local", **kwargs):
        self.calls.append(("list_sessions", family, kwargs))
        yield from self._sessions

    def session_messages(self, session_id, family="local", **kwargs):
        self.calls.append(("session_messages", session_id, family, kwargs))
        yield from self._messages.get(session_id, [])

    def activities(self, **kwargs):
        self.calls.append(("activities", kwargs))
        items = self._activities
        for i, item in enumerate(items):
            yield item, f"activity_{i}", i < len(items) - 1


SESSION = {
    "type": "compliance_local_session",
    "id": "clls_01HxKpLmNoPqRsTuVwXyZaBc",
    "organization_uuid": "9a1e0000-0000-0000-0000-000000000000",
    "workspace_id": None,
    "user": {"id": "user_01Gp", "email_address": "engineer@example.com"},
    "product_surface": "claude_code",
    "created_at": "2026-09-09T14:02:11Z",
    "updated_at": "2026-09-09T14:02:38Z",
}


def transcript(secret: str | None = None) -> list[dict]:
    return [
        {
            "type": "compliance_local_session_message",
            "id": "clsm_1",
            "role": "user",
            "model": None,
            "provenance": {"type": "synthetic_marker"},
            "content": [{"type": "text", "text": "[system prompt content not shown]",
                         "truncated": True}],
        },
        {
            "type": "compliance_local_session_message",
            "id": "clsm_2",
            "role": "user",
            "provenance": None,
            "content": [{"type": "text", "text": "fix the failing test", "truncated": False}],
        },
        {
            "type": "compliance_local_session_message",
            "id": "clsm_3",
            "role": "assistant",
            "model": "claude-opus-5",
            "provenance": None,
            "content": [
                {"type": "text", "text": "reading the file", "truncated": False},
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "Read",
                    # NB: a JSON-encoded string here, not an object.
                    "input": json.dumps({"file_path": "tests/auth_test.py"}),
                    "truncated": False,
                },
            ],
        },
        {
            "type": "compliance_local_session_message",
            "id": "clsm_4",
            "role": "user",
            "provenance": None,
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "name": "Read",
                    "is_error": False,
                    "content": [{"type": "text", "text": secret or "def test_login(): ..."}],
                    "truncated": False,
                }
            ],
        },
    ]


@pytest.fixture
def scanner(tmp_path, request):
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(tmp_path / "state.json"), "api_key": "sk-ant-api01-x"},
    )
    stub = getattr(request, "param", None) or StubClient()
    return ComplianceScanner(policy, client=stub), stub


# -- extraction ------------------------------------------------------------


def test_compliance_transcript_shape_is_extracted():
    units = compliance_units(transcript())
    locators = [u.locator for u in units]
    assert "msg[1].content[0]" in locators                       # text
    assert "msg[2].content[1].input.file_path" in locators       # JSON-string input
    assert "msg[3].content[0].content[0].text" in locators       # tool_result entries
    assert any(u.tool_name == "Read" for u in units)


def test_truncated_tool_use_input_is_scanned_as_raw_text():
    """A truncated input is no longer valid JSON; it must not be parsed."""
    messages = [
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "t1",
                    "name": "Bash",
                    "input": '{"command":"export KEY=' + FAKE_AWS_KEY + '…[truncated',
                    "truncated": True,
                }
            ],
        }
    ]
    units = compliance_units(messages)
    assert any(FAKE_AWS_KEY in u.text for u in units)


def test_unknown_block_type_still_scanned():
    messages = [{"role": "user", "content": [{"type": "future_block", "note": FAKE_AWS_KEY}]}]
    assert any(FAKE_AWS_KEY in u.text for u in compliance_units(messages))


# -- scanning --------------------------------------------------------------


def test_clean_session_reports_allow(scanner):
    scan, stub = scanner
    stub._sessions = [SESSION]
    stub._messages = {SESSION["id"]: transcript()}
    reports = list(scan.scan_sessions())
    assert len(reports) == 1
    assert reports[0].action == "allow"
    assert reports[0].product_surface == "claude_code"
    assert reports[0].messages == 4


def test_session_with_secret_reports_deny_without_leaking_it(scanner):
    scan, stub = scanner
    stub._sessions = [SESSION]
    stub._messages = {SESSION["id"]: transcript(secret=f"key={FAKE_AWS_KEY}")}
    report = next(iter(scan.scan_sessions()))
    assert report.action == "deny"
    assert report.findings
    assert FAKE_AWS_KEY not in json.dumps(report.to_json())


def test_state_is_persisted_and_resumes(scanner, tmp_path):
    scan, stub = scanner
    stub._sessions = [SESSION]
    stub._messages = {SESSION["id"]: transcript()}
    list(scan.scan_sessions())
    scan.commit()
    saved = json.loads((tmp_path / "state.json").read_text())
    assert saved["last_run_started_at"]
    assert SESSION["id"] in saved["sessions"]

    # A second scanner resumes from the persisted timestamp, backdated by
    # lookback_minutes so a still-indexing final call is not dropped.
    scan2 = ComplianceScanner(scan.policy, client=stub)
    list(scan2.scan_sessions())
    window = stub.calls[-2][2]["updated_at_gte"]
    assert window < saved["last_run_started_at"]


def test_local_family_uses_updated_at_and_remote_uses_created_at(scanner):
    scan, stub = scanner
    list(scan.scan_sessions(family="local"))
    assert "updated_at_gte" in stub.calls[0][2]
    list(scan.scan_sessions(family="remote"))
    remote_call = next(c for c in stub.calls if c[0] == "list_sessions" and c[1] == "remote")
    assert "updated_at_gte" not in remote_call[2]
    assert "created_at_gte" in remote_call[2]


def test_truncation_caps_are_raised_to_the_server_maximum(scanner):
    """The 10,000-byte default would hide a secret past that offset."""
    scan, stub = scanner
    stub._sessions = [SESSION]
    stub._messages = {SESSION["id"]: transcript()}
    list(scan.scan_sessions())
    assert any(c[0] == "session_messages" for c in stub.calls)
    # The scanner uses the client's own defaults, which are -1.
    import inspect

    sig = inspect.signature(ComplianceClient.session_messages)
    assert sig.parameters["tool_use_input_max_bytes"].default == -1
    assert sig.parameters["tool_result_max_bytes"].default == -1


# -- activity feed join ----------------------------------------------------


DENIAL = {
    "id": "activity_01Xy",
    "created_at": "2026-09-17T08:09:10Z",
    "organization_id": "org_01Wv",
    "actor": {"type": "user_actor", "email_address": "user@example.com", "user_id": "user_01Tu"},
    "type": "inference_hooks_request_denied",
    "reference_id": "fv_awsaccesske_01K5QW8ZPJ7N2R4T6V8XYA0BCD",
}


def test_denials_are_joined_by_reference_id(scanner):
    scan, stub = scanner
    stub._activities = [DENIAL]
    stub._sessions = [SESSION]
    stub._messages = {SESSION["id"]: transcript(secret=f"key={FAKE_AWS_KEY}")}
    reports = list(scan.scan_sessions())
    summary = scan.join_denials(reports)
    assert summary["denial_activities"] == 1
    assert summary["with_reference_id"] == 1
    assert summary["reference_ids"] == [DENIAL["reference_id"]]
    assert summary["sessions_would_deny"] == 1


@pytest.mark.parametrize("key", ["some_other_key", "inference_hooks_reference_id",
                                 "hook_reference_id"])
def test_denial_without_a_reference_id_is_counted_not_guessed(scanner, key):
    """The API reference names the field `reference_id` on
    inference_hooks_request_denied, so a value under any other key is not
    joined. Mutation: try a fallback key."""
    scan, stub = scanner
    stub._activities = [{**DENIAL, "reference_id": None, key: "fv_x_01"}]
    summary = scan.join_denials([])
    assert summary["with_reference_id"] == 0
    assert summary["without_reference_id"] == 1


def test_activities_cursor_is_persisted(scanner, tmp_path):
    scan, stub = scanner
    stub._activities = [DENIAL, {**DENIAL, "id": "activity_02"}]
    list(scan.denials())
    scan.commit()
    saved = json.loads((tmp_path / "state.json").read_text())
    assert saved["activities_cursor"] == "activity_1"


# -- client plumbing -------------------------------------------------------


def test_repeatable_params_use_array_bracket_syntax():
    encoded = _encode_params({"activity_types[]": ["a", "b"], "limit": 10})
    assert "activity_types%5B%5D=a" in encoded
    assert "activity_types%5B%5D=b" in encoded
    assert "limit=10" in encoded


def test_none_params_are_dropped():
    assert _encode_params({"page": None, "limit": 1}) == "limit=1"


def test_client_requires_a_key():
    with pytest.raises(ValueError, match="Compliance Access Key"):
        ComplianceClient(api_key="")


def test_ingest_exits_cleanly_without_a_key(tmp_path, monkeypatch, capsys):
    """A cron firing into a deployment that has no key yet must be a log
    line, not a crash-loop."""
    from forgd_verdict.cli import main

    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", raising=False)
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({
        "compliance": {"api_key": "$ANTHROPIC_COMPLIANCE_ACCESS_KEY"},
        "server": {"store": str(tmp_path / "findings"), "csv_path": None},
    }))
    assert main(["--policy", str(policy), "ingest"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "no Compliance Access Key" in out["skipped"]
    assert "read:compliance_user_data" in out["remediation"]


def test_the_sessions_map_is_pruned_to_the_scan_window(tmp_path):
    from datetime import UTC, datetime, timedelta

    from forgd_verdict.compliance.scanner import State

    now = datetime.now(UTC)

    def ts(delta):
        return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")

    state_path = tmp_path / "state.json"
    seed = State(str(state_path))
    seed.data["cursor:sessions:local"] = ts(timedelta(hours=1))
    seed.data["sessions"] = {
        "clls_old": {"updated_at": ts(timedelta(days=40)), "messages": 3},
        "clls_recent": {"updated_at": ts(timedelta(minutes=5)), "messages": 3},
    }
    seed.save()

    recent = {**SESSION, "id": "clls_recent", "updated_at": ts(timedelta(minutes=5))}
    stub = StubClient(sessions=[recent], messages={"clls_recent": transcript()})
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(state_path), "api_key": "sk-ant-api01-x"},
    )
    scanner = ComplianceScanner(policy, client=stub)
    reports = list(scanner.scan_sessions())
    scanner.commit()

    sessions = State(str(state_path)).data["sessions"]
    assert "clls_old" not in sessions
    assert "clls_recent" in sessions
    # The map is not read to skip anything: one listed session, one report.
    assert [r.session_id for r in reports] == ["clls_recent"]


# -- claude.ai chats: a separate endpoint family ---------------------------

CHAT = {
    "id": "claude_chat_01H5CWunD7RpVJ5bHa8RCkja",
    "name": "deploy help",
    "created_at": "2026-09-17T20:00:00Z",
    "updated_at": "2026-09-17T21:01:00Z",
    "deleted_at": None,
    "model": "claude-opus-5",
    "project_id": None,
    "user": {"id": "user_01Xy", "email_address": "a@example.com"},
}


def chat_with(text, artifacts=None):
    return {
        **CHAT,
        "chat_messages": [
            {"id": "m1", "role": "user", "created_at": "2026-09-17T20:00:00Z",
             "content": [{"type": "text", "text": text}],
             "files": [{"id": "claude_file_1", "filename": "creds.env",
                        "mime_type": "text/plain", "size_bytes": 12}],
             "generated_files": None},
            {"id": "m2", "role": "assistant", "created_at": "2026-09-17T20:00:05Z",
             "content": [{"type": "text", "text": "I'll take a look."}],
             "artifacts": artifacts},
        ],
    }


class ChatStub(StubClient):
    def __init__(self, chats=None, full=None, artifacts=None, **kw):
        super().__init__(**kw)
        self._chats = chats or []
        self._full = full or {}
        self._artifacts = artifacts or {}

    def list_chats(self, **kwargs):
        self.calls.append(("list_chats", kwargs))
        yield from self._chats

    def chat_messages(self, chat_id, limit=None):
        self.calls.append(("chat_messages", chat_id))
        return self._full[chat_id]

    def artifact_content(self, version_id):
        self.calls.append(("artifact_content", version_id))
        return self._artifacts[version_id]


def chat_scanner(tmp_path, stub):
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(tmp_path / "s.json"), "api_key": "sk-ant-api01-x"},
    )
    return ComplianceScanner(policy, client=stub)


def test_chats_are_scanned_at_all(tmp_path):
    """The session endpoints cover Cowork, Claude Code, Claude Science, M365
    and Chrome -- claude.ai chat content appears in none of them. Scanning
    only sessions meant an obviously-seeded AWS key in a claude.ai prompt
    produced no finding, because that transcript was never fetched."""
    text = f"deploy with AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}"
    stub = ChatStub(chats=[CHAT], full={CHAT["id"]: chat_with(text)})
    reports = list(chat_scanner(tmp_path, stub).scan_chats())
    assert len(reports) == 1
    r = reports[0]
    assert r.action == "deny"
    assert {f.detector for f in r.findings} == {"regex:aws-access-key"}
    assert r.messages == 2
    assert FAKE_AWS_KEY not in json.dumps(r.to_json())


def test_chat_list_uses_updated_at_ordering(tmp_path):
    """The time bound must match the sort key -- pairing created_at with
    order_by=updated_at is a 400 -- and updated_at ordering is what keeps an
    export current across runs."""
    stub = ChatStub(chats=[], full={})
    list(chat_scanner(tmp_path, stub).scan_chats())
    assert stub.calls[0][0] == "list_chats"
    assert "updated_at_gte" in stub.calls[0][1]


def test_artifacts_are_fetched_and_scanned(tmp_path):
    """Artifacts hold the code Claude generates, so a credential written
    into one is invisible to a message-text-only scan."""
    arts = [{"id": "claude_artifact_1", "version_id": "claude_artifact_version_1",
             "title": "deploy.sh", "artifact_type": "text/markdown"}]
    stub = ChatStub(
        chats=[CHAT],
        full={CHAT["id"]: chat_with("write me a deploy script", artifacts=arts)},
        artifacts={"claude_artifact_version_1": {
            "content": f"#!/bin/sh\nexport AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n"}},
    )
    report = next(iter(chat_scanner(tmp_path, stub).scan_chats()))
    assert report.artifacts_scanned == 1
    assert report.action == "deny"
    assert any("artifacts" in f.locator for f in report.findings)


def test_artifacts_can_be_skipped(tmp_path):
    arts = [{"id": "a", "version_id": "v1", "title": "t"}]
    stub = ChatStub(chats=[CHAT], full={CHAT["id"]: chat_with("hi", artifacts=arts)},
                    artifacts={"v1": {"content": FAKE_AWS_KEY}})
    report = next(iter(chat_scanner(tmp_path, stub).scan_chats(include_artifacts=False)))
    assert report.artifacts_scanned == 0
    assert report.findings == []


def test_a_failing_artifact_fetch_does_not_kill_the_pass(tmp_path):
    arts = [{"id": "a", "version_id": "missing", "title": "t"}]
    stub = ChatStub(chats=[CHAT], full={CHAT["id"]: chat_with("hi", artifacts=arts)},
                    artifacts={})
    report = next(iter(chat_scanner(tmp_path, stub).scan_chats()))
    assert report.artifacts_scanned == 0   # skipped, not fatal


class FailingArtifactStub(ChatStub):
    def artifact_content(self, version_id):
        self.calls.append(("artifact_content", version_id))
        raise RuntimeError("upstream 500")


def _failing_artifact_chat():
    arts = [{"id": "a", "version_id": "v1", "title": "t"}]
    return FailingArtifactStub(chats=[CHAT],
                               full={CHAT["id"]: chat_with("hi", artifacts=arts)})


def test_a_failed_artifact_fetch_marks_the_chat_unscanned(tmp_path):
    report = next(iter(chat_scanner(tmp_path, _failing_artifact_chat()).scan_chats()))
    assert report.artifacts_failed == 1
    assert "unscanned:artifact" in report.tiers_dropped
    # The shipped policy sets server.on_tier_dropped: allow.
    assert report.action == "allow"


def test_a_failed_artifact_fetch_denies_under_on_tier_dropped_deny(tmp_path):
    policy = make_policy(
        server={"on_tier_dropped": "deny"},
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(tmp_path / "s.json"), "api_key": "sk-ant-api01-x"},
    )
    scanner = ComplianceScanner(policy, client=_failing_artifact_chat())
    report = next(iter(scanner.scan_chats()))
    assert report.action == "deny"


@pytest.mark.parametrize("failing, advances", [(True, False), (False, True)])
def test_the_chat_cursor_holds_while_an_artifact_could_not_be_fetched(
        tmp_path, failing, advances):
    from forgd_verdict.compliance.scanner import State

    if failing:
        stub = _failing_artifact_chat()
    else:
        arts = [{"id": "a", "version_id": "v1", "title": "t"}]
        stub = ChatStub(chats=[CHAT], full={CHAT["id"]: chat_with("hi", artifacts=arts)},
                        artifacts={"v1": {"content": "nothing here"}})
    scanner = chat_scanner(tmp_path, stub)
    list(scanner.scan_chats())
    scanner.commit()
    assert ("cursor:chats" in State(str(tmp_path / "s.json")).data) is advances


class StatusArtifactStub(ChatStub):
    def __init__(self, status, **kw):
        super().__init__(**kw)
        self.status = status

    def artifact_content(self, version_id):
        from forgd_verdict.compliance.client import ComplianceError

        self.calls.append(("artifact_content", version_id))
        raise ComplianceError(self.status, "", "https://x/v1/artifacts")


@pytest.mark.parametrize("status, advances", [(404, True), (500, False)])
def test_a_deleted_artifact_is_unscanned_but_does_not_hold_the_chat_cursor(
        tmp_path, status, advances):
    from forgd_verdict.compliance.scanner import State

    arts = [{"id": "a", "version_id": "v1", "title": "t"}]
    stub = StatusArtifactStub(status, chats=[CHAT],
                              full={CHAT["id"]: chat_with("hi", artifacts=arts)})
    scanner = chat_scanner(tmp_path, stub)
    (report,) = list(scanner.scan_chats())
    scanner.commit()
    assert report.artifacts_failed == 1
    assert "unscanned:artifact" in report.tiers_dropped
    assert ("cursor:chats" in State(str(tmp_path / "s.json")).data) is advances


class DeletedChatStub(ChatStub):
    """A chat listed as deleted whose messages answer `status`, or are
    served when `status` is None."""

    def __init__(self, status, **kw):
        super().__init__(**kw)
        self.status = status

    def chat_messages(self, chat_id, limit=None):
        from forgd_verdict.compliance.client import ComplianceError

        self.calls.append(("chat_messages", chat_id))
        if self.status is not None:
            raise ComplianceError(self.status, "", "https://x/v1/compliance/apps/chats")
        return self._full[chat_id]


DELETED = {**CHAT, "deleted_at": "2026-09-17T22:00:00Z", "name": ""}


def test_a_deleted_chat_is_fetched_and_recorded_as_deleted_and_unread(tmp_path):
    """It still lists, with deleted_at set. A 404 on its messages records
    it as deleted and unread, never as a clean scan of nothing."""
    from forgd_verdict.compliance.ingest import chat_to_record

    stub = DeletedChatStub(404, chats=[DELETED])
    report = next(iter(chat_scanner(tmp_path, stub).scan_chats()))
    assert ("chat_messages", CHAT["id"]) in stub.calls
    assert report.deleted_at == "2026-09-17T22:00:00Z"
    assert report.findings == []
    assert report.tiers_dropped == ["unscanned:deleted"]
    assert report.content_read is False
    rec = chat_to_record(report)
    assert rec.deleted_at == "2026-09-17T22:00:00Z"
    assert rec.disposition == "deleted"
    assert rec.messages_total is None and rec.messages_scanned is None


def test_a_deleted_chat_whose_messages_are_still_served_is_scanned(tmp_path):
    stub = DeletedChatStub(None, chats=[DELETED], full={
        CHAT["id"]: {**chat_with(f"key {FAKE_AWS_KEY}"), "deleted_at": DELETED["deleted_at"]}})
    report = next(iter(chat_scanner(tmp_path, stub).scan_chats()))
    assert report.action == "deny"
    assert {f.detector for f in report.findings} == {"regex:aws-access-key"}
    assert report.deleted_at == DELETED["deleted_at"]
    assert report.content_read is True


@pytest.mark.parametrize("status", [500, 403])
def test_a_deleted_chat_that_could_not_be_fetched_holds_the_cursor(tmp_path, status):
    from forgd_verdict.compliance.scanner import State

    scanner = chat_scanner(tmp_path, DeletedChatStub(status, chats=[DELETED]))
    assert list(scanner.scan_chats()) == []
    scanner.commit()
    assert scanner.chats_failed == 1
    assert "cursor:chats" not in State(str(tmp_path / "s.json")).data


def test_a_deleted_unread_chat_denies_under_on_tier_dropped_deny(tmp_path):
    policy = make_policy(
        server={"on_tier_dropped": "deny"},
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(tmp_path / "s.json"), "api_key": "sk-ant-api01-x"},
    )
    scanner = ComplianceScanner(policy, client=DeletedChatStub(404, chats=[DELETED]))
    report = next(iter(scanner.scan_chats()))
    assert report.action == "deny"


def test_chat_record_surface_aligns_with_the_inference_hook(tmp_path):
    """Set to `claude-ai` so it matches source.application for the same
    product -- that alignment is what lets the reconciliation say how many
    of these prompts the inline control saw."""
    from forgd_verdict.compliance.ingest import chat_to_record

    stub = ChatStub(chats=[CHAT], full={CHAT["id"]: chat_with("hello")})
    report = next(iter(chat_scanner(tmp_path, stub).scan_chats()))
    rec = chat_to_record(report)
    assert rec.surface == "claude-ai"
    assert rec.session_id == CHAT["id"]
    assert rec.session_updated_at == CHAT["updated_at"]
    assert rec.observed_at > CHAT["updated_at"]   # scan time, not chat time


def test_chat_extractor_reads_filenames_and_titles():
    from forgd_verdict.extract import chat_units

    units = chat_units(chat_with("hello", artifacts=[{"id": "a", "version_id": "v",
                                                      "title": "secrets.md"}]))
    locators = [u.locator for u in units]
    assert "msg[0].content[0]" in locators
    assert any("files[0].filename" in loc for loc in locators)
    assert any("artifacts[0].title" in loc for loc in locators)


# -- spot checking a detector's precision --------------------------------
#
# The store keeps hashes, so nothing downstream can tell a real name from a
# code fragment spaCy mistook for one. That is the right default and it left
# 200 distinct `presidio:person` values unverifiable. These cover the value
# recovery, which is the part that can silently return nothing.


def test_a_multi_token_value_is_recovered():
    """An NHS number is `943 476 5919` and a person is `Dana Whitfield`.
    Splitting on whitespace recovers neither."""
    from forgd_verdict.models import ScanUnit
    from forgd_verdict.policy import load_policy
    from forgd_verdict.spotcheck import _match_values

    policy = load_policy("policy.yaml")
    units = [ScanUnit(locator="m", tool_name=None,
                      text="NHS number 943 476 5919 for the referral.")]
    found = _match_values(units, policy.build_detectors(),
                          "checksum:nhs-number", policy.budget_ms)
    assert "943 476 5919" in found


def test_the_finding_name_selects_the_rule_not_the_detector():
    """Findings are named `regex:ssn` while the detector object is `regex`.
    Filtering on the object returned every rule that detector owned, so a
    spot check of one rule reported another rule's values."""
    from forgd_verdict.models import ScanUnit
    from forgd_verdict.policy import load_policy
    from forgd_verdict.spotcheck import _match_values

    policy = load_policy("policy.yaml")
    units = [ScanUnit(locator="m", tool_name=None,
                      text="SSN: 457-55-5462 and card 4539578763621486")]
    dets = policy.build_detectors()
    ssn = _match_values(units, dets, "regex:ssn", policy.budget_ms)
    pan = _match_values(units, dets, "regex:pan", policy.budget_ms)
    assert set(ssn) == {"457-55-5462"}
    assert set(pan) == {"4539578763621486"}


def test_values_are_masked_by_default():
    """The output is judged by eye and then thrown away, but a masked
    default means a shoulder-read or a pasted terminal is not the leak the
    rest of the design prevents."""
    from forgd_verdict.spotcheck import Sample, mask

    # Edges kept so the value class is still judgeable, middle masked.
    assert mask("943 476 5919") == "94• ••• ••19"
    assert mask("Dana Whitfield") == "Da•• •••••••ld"
    assert "Whitfield" not in mask("Dana Whitfield")
    # Too short to mask partially: mask it entirely.
    assert mask("KB") == "••"

    s = Sample(detector="presidio:person")
    s.values.update(["Dana Whitfield"])
    assert s.rows(5, reveal=False)[0][0] != "Dana Whitfield"
    assert s.rows(5, reveal=True)[0][0] == "Dana Whitfield"


def test_env_file_never_overrides_an_export():
    """A stale file must not beat what the operator just exported."""
    import os
    import tempfile
    from unittest import mock

    from forgd_verdict.spotcheck import load_env_file
    with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
        fh.write("FORGD_SPOTCHECK_PROBE=from-file\n# a comment\n\nBAD LINE\n")
        path = fh.name
    with mock.patch.dict(os.environ, {"FORGD_SPOTCHECK_PROBE": "from-export"}):
        names = load_env_file(path)
        assert "FORGD_SPOTCHECK_PROBE" not in names
        assert os.environ["FORGD_SPOTCHECK_PROBE"] == "from-export"
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("FORGD_SPOTCHECK_PROBE", None)
        assert load_env_file(path) == ["FORGD_SPOTCHECK_PROBE"]
        assert os.environ["FORGD_SPOTCHECK_PROBE"] == "from-file"
        os.environ.pop("FORGD_SPOTCHECK_PROBE", None)
    os.unlink(path)


# -- the cursor bookkeeping ----------------------------------------------


def _ts(s):
    from datetime import datetime
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def test_the_chat_window_is_not_this_runs_start(tmp_path):
    """The bug, and it needed a real sequence to see.

    The sessions pass advanced the marker and saved; `_ingest_one_org`
    then ran `scan_chats`, which read that same marker. The chat window was therefore `now - lookback_minutes`
    -- ten minutes -- on every run whatever the cron interval. On the
    six-hourly schedule that is ~5h50m of claude.ai activity never looked
    at, reported as `chats_scanned: 0` with nothing indicating a gap.

    Asserting only that `updated_at_gte` is PRESENT passes no matter how
    wrong the value is.
    """
    from forgd_verdict.compliance.scanner import RUN_MARKER, State

    state_path = tmp_path / "s.json"
    # A cursor from six hours ago, as a six-hourly cron would leave it.
    seeded = "2026-09-21T06:00:00Z"
    store_state = State(str(state_path))
    store_state.data[RUN_MARKER] = seeded
    store_state.save()

    stub = ChatStub(chats=[], full={})
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(state_path), "api_key": "sk-ant-api01-x"},
    )
    scanner = ComplianceScanner(policy, client=stub)

    # The sessions pass runs FIRST and moves the marker to now.
    list(scanner.scan_sessions())
    scanner.commit()
    # Then the chat pass. It must still see the six-hour-old window.
    list(scanner.scan_chats())

    chat_call = [c for c in stub.calls if c[0] == "list_chats"][0]
    window = chat_call[1]["updated_at_gte"]
    assert _ts(window) < _ts("2026-09-21T06:30:00Z"), (
        f"chat window {window} is not the seeded cursor {seeded}; "
        "the sessions pass clobbered it again"
    )


def test_each_pass_keeps_its_own_cursor(tmp_path):
    from forgd_verdict.compliance.scanner import State

    state_path = tmp_path / "s.json"
    stub = ChatStub(chats=[], full={})
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(state_path), "api_key": "sk-ant-api01-x"},
    )
    scanner = ComplianceScanner(policy, client=stub)
    list(scanner.scan_sessions(family="local"))
    list(scanner.scan_chats())
    scanner.commit()

    saved = State(str(state_path)).data
    assert "cursor:sessions:local" in saved
    assert "cursor:chats" in saved


def test_a_truncated_session_pass_does_not_advance_the_resume_cursor(tmp_path):
    """`--max-sessions 10` against 500 available scanned ten and moved the
    window past the other 490, permanently.

    The RUN marker still moves, because the job did run and the
    dashboard's liveness signal is about whether it ran. Separating the
    two makes both correct.
    """
    from forgd_verdict.compliance.scanner import RUN_MARKER, State

    state_path = tmp_path / "s.json"
    many = [dict(SESSION, id=f"clls_{i}") for i in range(20)]
    stub = StubClient(sessions=many, messages={})
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(state_path), "api_key": "sk-ant-api01-x"},
    )
    scanner = ComplianceScanner(policy, client=stub)
    list(scanner.scan_sessions(max_sessions=3))
    scanner.commit()

    saved = State(str(state_path)).data
    assert saved.get(RUN_MARKER), "the job ran; liveness must still move"
    assert not saved.get("cursor:sessions:local"), (
        "the resume cursor advanced past 17 sessions nobody scanned"
    )


def test_a_complete_session_pass_does_advance_it(tmp_path):
    from forgd_verdict.compliance.scanner import State

    state_path = tmp_path / "s.json"
    stub = StubClient(sessions=[SESSION], messages={SESSION["id"]: transcript()})
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(state_path), "api_key": "sk-ant-api01-x"},
    )
    scanner = ComplianceScanner(policy, client=stub)
    list(scanner.scan_sessions(max_sessions=99))
    scanner.commit()
    assert State(str(state_path)).data.get("cursor:sessions:local")


def test_families_are_parsed_and_a_typo_is_refused():
    """A typo that silently scanned nothing would report
    `sessions_scanned: 0`, which is indistinguishable from a quiet org --
    the exact failure this change is about."""
    from forgd_verdict.compliance.ingest import FAMILIES, parse_families

    assert parse_families(None) == list(FAMILIES)
    assert parse_families("local,remote") == ["local", "remote"]
    assert parse_families("remote, local") == ["remote", "local"]
    assert parse_families("local,local") == ["local"]
    with pytest.raises(ValueError) as e:
        parse_families("locl")
    assert "locl" in str(e.value)


def test_both_families_are_scanned_and_do_not_share_a_cursor(tmp_path):
    """`local` and `remote` sessions do not overlap, so a job scanning
    only `local` never sees a remote session."""
    from forgd_verdict.compliance.scanner import State

    state_path = tmp_path / "s.json"
    stub = StubClient(sessions=[SESSION], messages={SESSION["id"]: transcript()})
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(state_path), "api_key": "sk-ant-api01-x"},
    )
    scanner = ComplianceScanner(policy, client=stub)
    for fam in ("local", "remote"):
        list(scanner.scan_sessions(family=fam))
    scanner.commit()

    asked = [c[1] for c in stub.calls if c[0] == "list_sessions"]
    assert asked == ["local", "remote"]
    saved = State(str(state_path)).data
    assert saved.get("cursor:sessions:local")
    assert saved.get("cursor:sessions:remote")


def test_an_empty_device_salt_file_is_repaired(tmp_path):
    """A zero-length salt file -- a truncated write, a filled disk --
    failed the `if existing:` check, the O_EXCL create then failed because
    the file existed, the handler re-read the same empty file and fell
    back to a process-lifetime salt. Nothing ever rewrote it, so every
    hook invocation got its OWN namespace, permanently, and that laptop's
    records became mutually incomparable.
    """
    from forgd_verdict.hook.device import device_salt, device_salt_path

    path = device_salt_path(str(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")

    first = device_salt(str(tmp_path))
    second = device_salt(str(tmp_path))
    assert first == second, "each call minted its own salt"
    assert path.read_text().strip() == first, "the empty file was never rewritten"


def test_a_missing_device_salt_file_is_created_once(tmp_path):
    from forgd_verdict.hook.device import device_salt

    assert device_salt(str(tmp_path)) == device_salt(str(tmp_path))


def test_an_existing_salt_is_never_replaced(tmp_path):
    """O_EXCL is there so a concurrent hook cannot overwrite a salt
    already in use -- records written either side would hash differently
    with nothing recording that."""
    from forgd_verdict.hook.device import device_salt, device_salt_path

    path = device_salt_path(str(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = "ab" * 32
    path.write_text(existing + "\n")
    assert device_salt(str(tmp_path)) == existing


def test_the_scanner_measures_its_own_cadence(tmp_path):
    """The threshold is two intervals plus slack, and the interval was a
    constant in `dashboard/topology.py` derived by hand from
    `ingest.schedule` in the Helm chart, with nothing connecting them.

    The job does not know its own cron expression -- it is invoked by one
    -- but it knows when it last ran, and the gap between two runs is the
    interval.
    """
    from forgd_verdict.compliance.scanner import (
        RUN_GAPS,
        State,
        observed_interval_min,
    )
    from forgd_verdict.store.local import LocalFileStore

    store = LocalFileStore(str(tmp_path))
    st = State("./compliance-state.json", store=store)
    # Four six-hourly runs.
    st.data[RUN_GAPS] = [360.0, 359.5, 360.2, 360.1]
    st.save()
    # Approximately, because a real cron does not fire to the second and
    # the median of an even-length list is the upper middle.
    seen = observed_interval_min(store, "compliance-state.json")
    assert 359 <= seen <= 361, seen


def test_two_samples_are_not_a_cadence(tmp_path):
    """One sample is not a cadence and two can both be wrong."""
    from forgd_verdict.compliance.scanner import RUN_GAPS, State, observed_interval_min
    from forgd_verdict.store.local import LocalFileStore

    store = LocalFileStore(str(tmp_path))
    st = State("./compliance-state.json", store=store)
    st.data[RUN_GAPS] = [360.0, 361.0]
    st.save()
    assert observed_interval_min(store, "compliance-state.json") is None


def test_one_manual_run_does_not_tighten_the_threshold(tmp_path):
    """A median, not a mean or a min. Somebody kicking the job by hand
    produces a tiny gap, and a mean would let that start reporting a
    healthy scan as late."""
    from forgd_verdict.compliance.scanner import RUN_GAPS, State, observed_interval_min
    from forgd_verdict.store.local import LocalFileStore

    store = LocalFileStore(str(tmp_path))
    st = State("./compliance-state.json", store=store)
    st.data[RUN_GAPS] = [360.0, 2.0, 360.0, 359.0, 361.0]
    st.save()
    assert observed_interval_min(store, "compliance-state.json") == 360.0


def test_an_implausible_gap_is_not_recorded(tmp_path):
    """A clock jump or a restored backup tells us nothing about cadence."""
    from datetime import UTC, datetime, timedelta

    from forgd_verdict.compliance.scanner import RUN_GAPS, RUN_MARKER, State

    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(tmp_path / "s.json"),
                    "api_key": "sk-ant-api01-x"},
    )
    from forgd_verdict.store.local import LocalFileStore

    store = LocalFileStore(str(tmp_path))
    seed = State("./s.json", store=store)
    # A year ago: far outside the plausible window.
    seed.data[RUN_MARKER] = (datetime.now(UTC) - timedelta(days=365)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    seed.save()

    stub = StubClient(sessions=[], messages={})
    list(ComplianceScanner(policy, client=stub, store=store,
                           org={"state_path": "./s.json"}).scan_sessions())
    assert not State("./s.json", store=store).data.get(RUN_GAPS)


# -- the cursor moves only once the pass is stored --------------------------


class _FailsOnPartialBatch:
    """A store whose final, partial batch write raises once."""

    def __init__(self, inner, batch_size, fail=True):
        self._inner = inner
        self._size = batch_size
        self.fail = fail

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def _check(self, rows):
        if self.fail and len(rows) < self._size:
            raise OSError("store unavailable")

    def write_verdicts(self, rows):
        self._check(rows)
        return self._inner.write_verdicts(rows)

    def write_denials(self, rows):
        self._check(rows)
        return self._inner.write_denials(rows)


SEEDED_CURSOR = "2026-09-20T00:00:00Z"


def _ingest_twice(tmp_path, monkeypatch, stub, cursor_key, seed, **passes):
    """Run ingest against a store that fails the final batch, then again
    against one that works. Returns both summaries, the cursor state after
    the failed run, and the store."""
    from forgd_verdict.compliance import ingest
    from forgd_verdict.compliance.scanner import RUN_MARKER, State
    from forgd_verdict.store import LocalFileStore

    state_path = str(tmp_path / "s.json")
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": state_path, "api_key": "sk-ant-api01-x"},
    )
    store = _FailsOnPartialBatch(LocalFileStore(tmp_path / "f", instance="t"), 2)
    seeded = State(state_path, store=store)
    seeded.data[cursor_key] = seed
    seeded.data[RUN_MARKER] = SEEDED_CURSOR
    seeded.save()
    monkeypatch.setattr(ingest, "ComplianceScanner",
                        lambda policy, org=None, store=None, detectors=None:
                        ComplianceScanner(policy, client=stub, org=org, store=store,
                                          detectors=detectors))
    opts = {"include_chats": False, "include_denials": False, **passes}
    failed = ingest.run_ingest(policy, store, batch_size=2, **opts)
    after_failure = dict(State(state_path, store=store).data)
    store.fail = False
    ok = ingest.run_ingest(policy, store, batch_size=2, **opts)
    return failed, after_failure, ok, store


def test_a_failed_final_session_write_does_not_move_the_cursor(tmp_path, monkeypatch):
    from forgd_verdict.compliance.scanner import RUN_MARKER

    sessions = [dict(SESSION, id=f"clls_{i}") for i in range(3)]
    stub = StubClient(sessions=sessions,
                      messages={s["id"]: transcript() for s in sessions})
    failed, state, ok, store = _ingest_twice(
        tmp_path, monkeypatch, stub, "cursor:sessions:local", SEEDED_CURSOR)
    assert failed["orgs_failed"] == 1
    assert state["cursor:sessions:local"] == SEEDED_CURSOR
    assert state[RUN_MARKER] == SEEDED_CURSOR, "a pass that stored nothing has not run"
    windows = [c[2]["updated_at_gte"] for c in stub.calls if c[0] == "list_sessions"]
    assert len(windows) == 2 and windows[0] == windows[1]
    assert ok["orgs_failed"] == 0
    stored = {r.session_id for r in store.read_verdicts()}
    assert {s["id"] for s in sessions} <= stored


def test_a_failed_final_chat_write_does_not_move_the_cursor(tmp_path, monkeypatch):
    chats = [dict(CHAT, id=f"claude_chat_{i}") for i in range(3)]
    stub = ChatStub(chats=chats, full={c["id"]: chat_with("hello there") | {"id": c["id"]}
                                       for c in chats})
    failed, state, ok, _ = _ingest_twice(
        tmp_path, monkeypatch, stub, "cursor:chats", SEEDED_CURSOR,
        include_chats=True, family="local")
    assert failed["orgs_failed"] == 1
    assert state["cursor:chats"] == SEEDED_CURSOR
    windows = [c[1]["updated_at_gte"] for c in stub.calls if c[0] == "list_chats"]
    assert len(windows) == 2 and windows[0] == windows[1]
    assert ok["orgs_failed"] == 0 and ok["chats_scanned"] == 3


def test_a_failed_final_denial_write_does_not_move_the_cursor(tmp_path, monkeypatch):
    stub = StubClient(activities=[dict(DENIAL, id=f"activity_{i}") for i in range(3)])
    failed, state, ok, store = _ingest_twice(
        tmp_path, monkeypatch, stub, "activities_cursor", "activity_seed",
        include_denials=True)
    assert failed["orgs_failed"] == 1
    assert state["activities_cursor"] == "activity_seed"
    after = [c[1]["after_id"] for c in stub.calls if c[0] == "activities"]
    assert after == ["activity_seed", "activity_seed"]
    assert ok["orgs_failed"] == 0 and ok["denials_written"] == 3


class _RefusingStub(StubClient):
    """A StubClient whose session fetch, or a family's listing, answers with
    a ComplianceError status."""

    def __init__(self, *a, refuse=None, refuse_family=None, **kw):
        super().__init__(*a, **kw)
        self._refuse = refuse or {}
        self._refuse_family = refuse_family or {}

    def list_sessions(self, family="local", **kwargs):
        from forgd_verdict.compliance.client import ComplianceError

        if family in self._refuse_family:
            self.calls.append(("list_sessions", family, kwargs))
            raise ComplianceError(self._refuse_family[family], "", "https://x/v1/sessions")
        yield from super().list_sessions(family, **kwargs)

    def session_messages(self, session_id, family="local", **kwargs):
        from forgd_verdict.compliance.client import ComplianceError

        if session_id in self._refuse:
            self.calls.append(("session_messages", session_id, family, kwargs))
            raise ComplianceError(self._refuse[session_id], "", "https://x/v1/messages")
        yield from super().session_messages(session_id, family, **kwargs)


def _ingest_with(tmp_path, monkeypatch, stub, families="local"):
    from forgd_verdict.compliance import ingest
    from forgd_verdict.compliance.scanner import State
    from forgd_verdict.store import LocalFileStore

    state_path = str(tmp_path / "s.json")
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": state_path, "api_key": "sk-ant-api01-x"},
    )
    store = LocalFileStore(tmp_path / "f", instance="t")
    seeded = State(state_path, store=store)
    seeded.data["cursor:sessions:local"] = SEEDED_CURSOR
    seeded.save()
    monkeypatch.setattr(ingest, "ComplianceScanner",
                        lambda policy, org=None, store=None, detectors=None:
                        ComplianceScanner(policy, client=stub, org=org, store=store,
                                          detectors=detectors))
    summary = ingest.run_ingest(policy, store, family=families,
                                include_chats=False, include_denials=False)
    return summary, State(state_path, store=store).data, store


def _three_sessions(status):
    sessions = [dict(SESSION, id=f"clls_{i}") for i in range(3)]
    return _RefusingStub(sessions=sessions,
                         messages={s["id"]: transcript() for s in sessions},
                         refuse={"clls_1": status})


def _fetched(stub):
    return [c[1] for c in stub.calls if c[0] == "session_messages"]


def test_a_deleted_session_does_not_stop_its_family(tmp_path, monkeypatch, caplog):
    stub = _three_sessions(404)
    with caplog.at_level("INFO"):
        summary, state, store = _ingest_with(tmp_path, monkeypatch, stub)
    assert _fetched(stub) == ["clls_0", "clls_1", "clls_2"]
    assert {r.session_id for r in store.read_verdicts()} == {"clls_0", "clls_2"}
    assert summary["orgs_failed"] == 0
    assert summary["sessions_scanned"] == 2
    assert summary["sessions_failed"] == 0
    assert state["cursor:sessions:local"] != SEEDED_CURSOR
    assert "session family not available" not in caplog.text


def test_a_refused_session_is_counted_and_holds_the_cursor(tmp_path, monkeypatch, caplog):
    stub = _three_sessions(500)
    with caplog.at_level("INFO"):
        summary, state, store = _ingest_with(tmp_path, monkeypatch, stub)
    assert _fetched(stub) == ["clls_0", "clls_1", "clls_2"]
    assert {r.session_id for r in store.read_verdicts()} == {"clls_0", "clls_2"}
    assert summary["orgs_failed"] == 0
    assert summary["sessions_failed"] == 1
    assert summary["orgs"][0]["sessions_failed"] == 1
    # The window stays where it was, so the next pass asks for clls_1 again.
    assert state["cursor:sessions:local"] == SEEDED_CURSOR
    assert "session family not available" not in caplog.text


class _RefusingChatStub(ChatStub):
    """A ChatStub whose message fetch for the chats in `refuse` answers with
    a ComplianceError status."""

    def __init__(self, *a, refuse=None, **kw):
        super().__init__(*a, **kw)
        self._refuse = refuse or {}

    def chat_messages(self, chat_id, limit=None):
        from forgd_verdict.compliance.client import ComplianceError

        if chat_id in self._refuse:
            self.calls.append(("chat_messages", chat_id))
            raise ComplianceError(self._refuse[chat_id], "", "https://x/v1/chats")
        return super().chat_messages(chat_id, limit)


def _three_chats(status):
    chats = [dict(CHAT, id=f"claude_chat_{i}") for i in range(3)]
    return _RefusingChatStub(
        chats=chats, full={c["id"]: chat_with("hello there") | {"id": c["id"]} for c in chats},
        activities=[DENIAL], refuse={"claude_chat_1": status})


@pytest.mark.parametrize("status", [404, 500])
def test_a_chat_that_cannot_be_fetched_costs_that_chat(tmp_path, status):
    from forgd_verdict.compliance.scanner import State

    stub = _three_chats(status)
    scanner = chat_scanner(tmp_path, stub)
    reports = list(scanner.scan_chats())
    scanner.commit()
    assert [r.chat_id for r in reports] == ["claude_chat_0", "claude_chat_2"]
    assert scanner.chats_failed == (0 if status == 404 else 1)
    assert ("cursor:chats" in State(str(tmp_path / "s.json")).data) is (status == 404)


@pytest.mark.parametrize("status", [404, 500])
def test_a_refused_chat_leaves_the_org_and_its_denials_pass_running(
        tmp_path, monkeypatch, caplog, status):
    """A chat fetch that raised left `scan_chats`, then `_ingest_one_org`,
    before the chat batch was written and before the denials pass ran, and
    the whole org was reported failed."""
    from forgd_verdict.compliance import ingest
    from forgd_verdict.compliance.scanner import State
    from forgd_verdict.store import LocalFileStore

    state_path = str(tmp_path / "s.json")
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": state_path, "api_key": "sk-ant-api01-x"},
    )
    store = LocalFileStore(tmp_path / "f", instance="t")
    seeded = State(state_path, store=store)
    seeded.data["cursor:chats"] = SEEDED_CURSOR
    seeded.save()
    stub = _three_chats(status)
    monkeypatch.setattr(ingest, "ComplianceScanner",
                        lambda policy, org=None, store=None, detectors=None:
                        ComplianceScanner(policy, client=stub, org=org, store=store,
                                          detectors=detectors))
    with caplog.at_level("INFO"):
        summary = ingest.run_ingest(policy, store, include_chats=True, include_denials=True)
    state = State(state_path, store=store).data

    assert [c[1] for c in stub.calls if c[0] == "chat_messages"] == [
        "claude_chat_0", "claude_chat_1", "claude_chat_2"]
    assert {r.session_id for r in store.read_verdicts()} == {"claude_chat_0", "claude_chat_2"}
    assert summary["orgs_failed"] == 0
    assert summary["chats_scanned"] == 2
    assert summary["chats_failed"] == (0 if status == 404 else 1)
    assert summary["orgs"][0]["chats_failed"] == summary["chats_failed"]
    assert summary["denials_written"] == 1
    assert (state["cursor:chats"] == SEEDED_CURSOR) is (status != 404)
    assert "claude_chat_1" not in caplog.text


def test_a_family_the_org_does_not_have_is_skipped(tmp_path, monkeypatch, caplog):
    stub = _RefusingStub(sessions=[SESSION], messages={SESSION["id"]: transcript()},
                         refuse_family={"remote": 404})
    with caplog.at_level("INFO"):
        summary, state, _ = _ingest_with(tmp_path, monkeypatch, stub,
                                         families="local,remote")
    assert summary["orgs_failed"] == 0
    assert summary["sessions_scanned"] == 1
    assert "session family not available" in caplog.text
    assert state["cursor:sessions:local"] != SEEDED_CURSOR
    assert not state.get("cursor:sessions:remote")


@pytest.mark.parametrize("value, expected", [
    ("nan", 4), ("NaN", 4), ("inf", 4), ("-inf", 4), ("-5", 4), ("not a number", 4),
    ("0", 0.0), ("10", 10.0), ("100", 60.0),
])
def test_retry_after_that_is_not_a_finite_non_negative_number_backs_off_as_usual(value,
                                                                              expected):
    from forgd_verdict.compliance.client import _retry_after

    assert _retry_after({"retry-after": value}, 2) == expected


@pytest.mark.parametrize("status, scanned", [(None, 1), (404, 0)])
def test_spotcheck_reads_a_deleted_chat_while_its_messages_are_served(tmp_path, status, scanned):
    from forgd_verdict.spotcheck import sample_chats

    stub = DeletedChatStub(status, chats=[DELETED], full={CHAT["id"]: chat_with("hello")})
    sample = sample_chats(chat_scanner(tmp_path, stub), "regex:aws-access-key")
    assert sample.sources_scanned == scanned
