"""Adapters 3 and 6: upstream ids and policy labels on their log and summary paths."""

from __future__ import annotations

import json
import logging

import pytest
from conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN
from test_compliance import CHAT, ChatStub, chat_scanner, chat_with
from test_managed_agents import KEY, WS_KEY, FakeClient, history, session, ws_policy

from forgd_verdict.compliance.ingest import run_ingest
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store.local import LocalFileStore

# A chat or session id an upstream returned that is credential-shaped.
EVIL_ID = f"claude_chat_{FAKE_AWS_KEY}"


def _all_logged(caplog, capsys) -> str:
    out = capsys.readouterr()
    return "\n".join([out.out, out.err, caplog.text,
                      *(json.dumps(getattr(r, "fields", ""), default=str)
                        for r in caplog.records)])


class _ArtifactFails(ChatStub):
    def artifact_content(self, version_id):
        raise RuntimeError(f"500 for chat {EVIL_ID}")


def test_a_failed_artifact_fetch_does_not_log_the_chat_id(tmp_path, caplog, capsys):
    chat = {**CHAT, "id": EVIL_ID}
    full = {**chat_with("hello", artifacts=[{"id": "a", "version_id": "v1", "title": "t"}]),
            "id": EVIL_ID}
    scanner = chat_scanner(tmp_path, _ArtifactFails(chats=[chat], full={EVIL_ID: full}))
    caplog.set_level(logging.DEBUG)
    (report,) = list(scanner.scan_chats())
    assert report.artifacts_failed == 1
    logged = _all_logged(caplog, capsys)
    assert "artifact fetch failed" in logged
    assert FAKE_AWS_KEY not in logged
    # The log names the chat as the guarded record does.
    guarded = MetadataGuard(scanner.detectors, scanner.policy.hash_salt).one(EVIL_ID)
    assert guarded.startswith("redacted_") and guarded in logged


def test_an_ordinary_chat_id_is_logged_as_it_is_recorded(tmp_path, caplog):
    full = chat_with("hello", artifacts=[{"id": "a", "version_id": "v1", "title": "t"}])
    scanner = chat_scanner(tmp_path, _ArtifactFails(chats=[CHAT], full={CHAT["id"]: full}))
    caplog.set_level(logging.WARNING)
    list(scanner.scan_chats())
    (rec,) = [r for r in caplog.records if "artifact fetch failed" in r.getMessage()]
    assert rec.fields["chat"] == CHAT["id"]


def test_a_failed_behavioural_check_logs_the_error_type_only(tmp_path, caplog, capsys):
    from test_compliance import SESSION, StubClient, transcript

    scanner = chat_scanner(tmp_path, StubClient(sessions=[SESSION],
                                                messages={SESSION["id"]: transcript()}))

    class Boom:
        checks = ["provenance"]

        def check(self, *a, **k):
            raise ValueError(f"could not parse {FAKE_GITHUB_TOKEN}")

    scanner._behaviour = Boom()
    caplog.set_level(logging.DEBUG)
    list(scanner.scan_sessions())
    logged = _all_logged(caplog, capsys)
    assert "behavioural check failed" in logged and "ValueError" in logged
    assert FAKE_GITHUB_TOKEN not in logged


def _compliance_policy(label):
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": "s"},
        "orgs": [{"id": "org-a", "label": label}],
        "detectors": {"gitleaks": {"enabled": False}},
        "compliance": {"orgs": [{"id": "org-a", "api_key": "k-a"}]},
    }))


def test_a_credential_shaped_org_label_refuses_the_ingest(tmp_path, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ValueError) as e:
        run_ingest(_compliance_policy(FAKE_AWS_KEY), LocalFileStore(tmp_path, instance="t"),
                   include_denials=False, include_chats=False)
    assert "compliance org entry 0: the label matches regex:aws-access-key" in str(e.value)
    assert FAKE_AWS_KEY not in str(e.value) + _all_logged(caplog, capsys)


def test_an_overlong_org_label_refuses_the_ingest(tmp_path):
    with pytest.raises(ValueError, match="entry 0: the label is longer than 128"):
        run_ingest(_compliance_policy("x" * 200), LocalFileStore(tmp_path, instance="t"),
                   include_denials=False, include_chats=False)


@pytest.mark.parametrize("field, noun", [("label", "label"), ("key", "key")])
def test_a_credential_shaped_workspace_label_or_key_refuses_the_ingest(
        field, noun, tmp_path, monkeypatch, caplog, capsys):
    from forgd_verdict.managed.scanner import run_managed_ingest

    entry = {"key": WS_KEY, "label": "prod", field: FAKE_GITHUB_TOKEN}
    caplog.set_level(logging.DEBUG)
    out = run_managed_ingest(ws_policy(entry), LocalFileStore(tmp_path, instance="t"))
    assert out["workspaces"] == [] and out["error"] == "invalid managed_agents.workspaces"
    assert f"managed_agents.workspaces entry 0: the {noun} matches" in out["detail"]
    assert FAKE_GITHUB_TOKEN not in json.dumps(out) + _all_logged(caplog, capsys)


def test_a_stalled_history_does_not_log_the_session_id(tmp_path, monkeypatch, caplog, capsys):
    from forgd_verdict.managed.client import ManagedAgentsClient
    from forgd_verdict.managed.scanner import run_managed_ingest

    pages = {"data": [{"type": "user.message", "id": "e1",
                       "content": [{"type": "text", "text": "hi"}]}], "next_page": "p2"}
    real = ManagedAgentsClient(api_key=KEY)
    monkeypatch.setattr(real, "list_sessions", lambda limit=100: iter([session(EVIL_ID)]))
    monkeypatch.setattr(real, "get", lambda path, params=None: pages)
    monkeypatch.setattr("forgd_verdict.managed.scanner.ManagedAgentsClient",
                        lambda **kw: real)
    caplog.set_level(logging.DEBUG)
    out = run_managed_ingest(ws_policy({"key": WS_KEY, "label": "prod"}),
                             LocalFileStore(tmp_path, instance="t"))
    assert out["workspaces"][0]["ok"] is True
    logged = _all_logged(caplog, capsys)
    assert "paging did not advance" in logged
    assert FAKE_AWS_KEY not in logged + json.dumps(out)


def test_a_client_with_no_log_name_logs_no_session_field(caplog, monkeypatch):
    from forgd_verdict.managed.client import ManagedAgentsClient

    client = ManagedAgentsClient(api_key=KEY)
    page = {"data": [{"id": "e1"}], "next_page": "p2"}
    monkeypatch.setattr(client, "get", lambda path, params=None: page)
    caplog.set_level(logging.WARNING)
    list(client.session_events(EVIL_ID))
    (rec,) = [r for r in caplog.records if "did not advance" in r.getMessage()]
    assert "session" not in rec.fields


def test_benign_labels_still_ingest(tmp_path, monkeypatch):
    from forgd_verdict.managed.scanner import run_managed_ingest

    fake = FakeClient([session("sesn_1")], {"sesn_1": history()})
    monkeypatch.setattr("forgd_verdict.managed.scanner.ManagedAgentsClient",
                        lambda **kw: fake)
    p = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": "s"},
        "managed_agents": {"workspaces": [{"key": WS_KEY, "label": "prod", "api_key": KEY}]}}))
    out = run_managed_ingest(p, LocalFileStore(tmp_path, instance="t"))
    assert out["workspaces"][0]["ok"] is True
