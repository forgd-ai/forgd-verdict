"""Adapter 3 keeps each `compliance.orgs` entry to the org its `id` names.

A Compliance Access Key created for the parent organization reads every
linked organization. The chat list, the remote session list and the Activity
Feed take `organization_ids[]`; the local session list does not, so its
records are checked one by one. Shapes from platform.claude.com/docs/en/
manage-claude/compliance-org-data and .../compliance-sessions, verified
2026-11-28.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from conftest import make_policy

from forgd_verdict.compliance import scanner as scanner_mod
from forgd_verdict.compliance.client import ComplianceClient
from forgd_verdict.compliance.ingest import activity_to_denial, run_ingest
from forgd_verdict.compliance.scanner import ComplianceScanner
from forgd_verdict.store.base import pseudonym
from forgd_verdict.store.local import LocalFileStore

SALT = "s"
# Generated per run: tests name no real organization.
ORG_A = str(uuid.uuid4())
ORG_B = str(uuid.uuid4())
DETECTORS = {"gitleaks": {"enabled": False, "severity": "block"}}


def _session(sid, org):
    return {"id": sid, "organization_uuid": org, "user": {"id": f"user_{sid}"},
            "product_surface": "claude_code", "created_at": "2026-11-27T10:00:00Z",
            "updated_at": "2026-11-27T10:05:00Z"}


def _chat(cid, org):
    return {"id": cid, "organization_uuid": org, "user": {"id": f"user_{cid}"},
            "created_at": "2026-11-27T10:00:00Z", "updated_at": "2026-11-27T10:05:00Z",
            "deleted_at": None}


def _activity(aid, org):
    return {"id": aid, "organization_uuid": org, "type": "inference_hooks_request_denied",
            "created_at": "2026-11-27T10:00:00Z", "actor": {"user_id": f"user_{aid}"}}


class ParentKey:
    """What a key created for the parent organization reads: both orgs.

    `honours_filter` False stands in for a list that returns another org's
    records despite `organization_ids[]`."""

    def __init__(self, honours_filter=True):
        self.honours_filter = honours_filter
        self.calls: list[tuple[str, dict]] = []
        self.local = [_session("local-a", ORG_A), _session("local-b", ORG_B)]
        self.remote = [_session("remote-a", ORG_A), _session("remote-b", ORG_B)]
        self.chats = [_chat("chat-a", ORG_A), _chat("chat-b", ORG_B)]
        self.denials = [_activity("act-a", ORG_A), _activity("act-b", ORG_B)]

    def _narrow(self, records, kwargs, filterable=True):
        wanted = kwargs.get("organization_ids")
        if not (wanted and filterable and self.honours_filter):
            return records
        return [r for r in records if r.get("organization_uuid", wanted[0]) in wanted]

    def list_sessions(self, family="local", **kwargs):
        self.calls.append((f"sessions:{family}", kwargs))
        source = self.local if family == "local" else self.remote
        # The real local list has no organization filter.
        yield from self._narrow(source, kwargs, filterable=family == "remote")

    def session_messages(self, session_id, family="local", **kwargs):
        return iter(())

    def list_chats(self, **kwargs):
        self.calls.append(("chats", kwargs))
        yield from self._narrow(self.chats, kwargs)

    def chat_messages(self, chat_id, limit=None):
        return {"id": chat_id, "chat_messages": []}

    def artifact_content(self, version_id):
        raise AssertionError("no artifacts here")

    def activities(self, **kwargs):
        self.calls.append(("activities", kwargs))
        items = self._narrow(self.denials, kwargs)
        for i, item in enumerate(items):
            yield item, f"cursor_{i}", i < len(items) - 1


def _policy(tmp_path, orgs=None, **single):
    compliance = ({"orgs": orgs} if orgs is not None
                  else {"api_key": "sk-ant-api01-x", "state_path": str(tmp_path / "s.json"),
                        **single})
    return make_policy(privacy={"hash_salt": SALT}, detectors=DETECTORS,
                       compliance=compliance)


def _entries(tmp_path, *ids):
    return [{"id": org, "label": f"org{n}", "api_key": "sk-ant-api01-x",
             "state_path": str(tmp_path / f"cursor-{n}.json")}
            for n, org in enumerate(ids)]


def _ingest(tmp_path, monkeypatch, client, *ids):
    monkeypatch.setattr(scanner_mod, "ComplianceClient", lambda **_: client)
    store = LocalFileStore(str(tmp_path / "store"))
    summary = run_ingest(_policy(tmp_path, orgs=_entries(tmp_path, *ids)), store,
                         family="local,remote")
    return store, summary


# --- the pass ------------------------------------------------------------


@pytest.mark.parametrize("honours_filter", [True, False],
                         ids=["filter-honoured", "filter-ignored"])
def test_one_parent_key_in_two_entries_files_each_record_once_under_its_org(
        tmp_path, monkeypatch, honours_filter):
    """The failure this prevents: each entry read both orgs and filed all of
    it under its own id, so every finding appeared twice, once under each
    org."""
    store, summary = _ingest(tmp_path, monkeypatch, ParentKey(honours_filter), ORG_A, ORG_B)

    verdicts = list(store.read_verdicts())
    ids = sorted(r.session_id for r in verdicts)
    assert ids == sorted(["local-a", "local-b", "remote-a", "remote-b", "chat-a", "chat-b"])
    for record in verdicts:
        org = ORG_A if record.session_id.endswith("-a") else ORG_B
        assert record.tenant_hash == pseudonym(org, SALT, "org"), record.session_id

    denials = list(store.read_denials())
    assert sorted(d.activity_id for d in denials) == ["act-a", "act-b"]
    for denial in denials:
        org = ORG_A if denial.activity_id.endswith("-a") else ORG_B
        assert denial.tenant_hash == pseudonym(org, SALT, "org")

    assert summary["orgs_scanned"] == 2
    # Each entry skips the other org's local session. With the filter
    # ignored it also skips the other org's remote session, chat and denial.
    per_entry = 1 if honours_filter else 4
    assert [o["other_org_skipped"] for o in summary["orgs"]] == [per_entry, per_entry]
    assert summary["other_org_skipped"] == 2 * per_entry


def test_each_filterable_list_is_asked_for_the_entry_org_only(tmp_path, monkeypatch):
    client = ParentKey()
    _ingest(tmp_path, monkeypatch, client, ORG_A)
    asked = {name: kwargs.get("organization_ids") for name, kwargs in client.calls}
    assert asked == {"sessions:local": [ORG_A], "sessions:remote": [ORG_A],
                     "chats": [ORG_A], "activities": [ORG_A]}


def test_a_key_that_reads_other_orgs_is_logged_with_the_count(tmp_path, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.ingest"):
        _ingest(tmp_path, monkeypatch, ParentKey(), ORG_A)
    (record,) = [r for r in caplog.records if "other than this entry" in r.getMessage()]
    assert record.fields == {"org": "org0", "skipped": 1}


def test_a_single_org_key_skips_nothing_and_logs_nothing(tmp_path, monkeypatch, caplog):
    client = ParentKey()
    for name in ("local", "remote", "chats", "denials"):
        setattr(client, name, [r for r in getattr(client, name)
                               if r["organization_uuid"] == ORG_A])
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.ingest"):
        store, summary = _ingest(tmp_path, monkeypatch, client, ORG_A)
    assert summary["other_org_skipped"] == 0
    assert not [r for r in caplog.records if "other than this entry" in r.getMessage()]
    assert len(list(store.read_verdicts())) == 3


# --- the scanner ---------------------------------------------------------


def test_the_entry_id_is_matched_without_case(tmp_path):
    scanner = ComplianceScanner(
        _policy(tmp_path, orgs=_entries(tmp_path, ORG_A.upper())),
        org=_entries(tmp_path, ORG_A.upper())[0], client=ParentKey())
    assert scanner.scope == ORG_A
    reports = list(scanner.scan_sessions(family="local"))
    assert [r.session_id for r in reports] == ["local-a"]
    # Filed under the id as written, so it hashes as the registry's does.
    assert reports[0].org_id == ORG_A.upper()


def _strip_org(record):
    return {k: v for k, v in record.items() if k != "organization_uuid"}


def test_a_local_session_naming_no_organization_is_skipped_when_scoped(tmp_path):
    """The local list is not narrowed by the API, so a session there with no
    `organization_uuid` could be any linked org's."""
    client = ParentKey()
    client.local = [_strip_org(_session("local-x", ORG_A))]
    entry = _entries(tmp_path, ORG_A)[0]
    scanner = ComplianceScanner(_policy(tmp_path, orgs=[entry]), org=entry, client=client)
    assert list(scanner.scan_sessions(family="local")) == []
    assert scanner.other_org_skipped == 1


def test_a_narrowed_record_naming_no_organization_belongs_to_the_entry(tmp_path):
    """The remote and chat lists were asked for the entry's org only."""
    client = ParentKey()
    client.remote = [_strip_org(_session("remote-x", ORG_A))]
    client.chats = [_strip_org(_chat("chat-x", ORG_A))]
    entry = _entries(tmp_path, ORG_A)[0]
    scanner = ComplianceScanner(_policy(tmp_path, orgs=[entry]), org=entry, client=client)
    assert [r.org_id for r in scanner.scan_sessions(family="remote")] == [ORG_A]
    assert [r.org_id for r in scanner.scan_chats()] == [ORG_A]
    assert scanner.other_org_skipped == 0


@pytest.mark.parametrize("kind", ["sessions", "chats"])
def test_the_scan_limit_counts_only_the_entry_records(tmp_path, kind):
    """Other orgs' records ahead of the entry's must not use up the limit:
    the truncated pass holds the cursor, so the next run would list them
    first again and never reach the entry's."""
    client = ParentKey(honours_filter=False)
    if kind == "sessions":
        client.local = ([_session(f"local-b{n}", ORG_B) for n in range(3)]
                        + [_session("local-a", ORG_A)])
    else:
        client.chats = ([_chat(f"chat-b{n}", ORG_B) for n in range(3)]
                        + [_chat("chat-a", ORG_A)])
    entry = _entries(tmp_path, ORG_A)[0]
    scanner = ComplianceScanner(_policy(tmp_path, orgs=[entry]), org=entry, client=client)
    if kind == "sessions":
        found = [r.session_id for r in scanner.scan_sessions(family="local", max_sessions=1)]
        assert found == ["local-a"]
    else:
        assert [r.chat_id for r in scanner.scan_chats(max_chats=1)] == ["chat-a"]
    assert scanner.other_org_skipped == 3


def test_an_id_that_is_not_a_uuid_is_not_narrowed_and_says_so(tmp_path, caplog):
    entry = _entries(tmp_path, "org_01Wv6QeBcDfGhJkLmNpQrSt8")[0]
    client = ParentKey()
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.compliance"):
        scanner = ComplianceScanner(_policy(tmp_path, orgs=[entry]), org=entry, client=client)
    assert any("not an organization UUID" in r.getMessage() for r in caplog.records)
    assert len(list(scanner.scan_chats())) == 2
    assert "organization_ids" not in dict(client.calls)["chats"]
    assert scanner.other_org_skipped == 0


def test_with_no_org_id_each_record_is_filed_under_its_own_org(tmp_path):
    scanner = ComplianceScanner(_policy(tmp_path), client=ParentKey())
    assert scanner.scope == ""
    sessions = {r.session_id: r.org_id for r in scanner.scan_sessions(family="local")}
    assert sessions == {"local-a": ORG_A, "local-b": ORG_B}
    chats = {r.chat_id: r.org_id for r in scanner.scan_chats()}
    assert chats == {"chat-a": ORG_A, "chat-b": ORG_B}
    denial = activity_to_denial(_activity("act-b", ORG_B), scanner, SALT,
                                scanner.tenant_of(_activity("act-b", ORG_B)))
    assert denial.tenant_hash == pseudonym(ORG_B, SALT, "org")


def test_the_sealer_is_asked_for_each_record_org(tmp_path, monkeypatch):
    scanner = ComplianceScanner(_policy(tmp_path), client=ParentKey())
    asked: list[str | None] = []
    monkeypatch.setattr(type(scanner.policy), "sealer",
                        lambda self, org_id=None: asked.append(org_id))
    list(scanner.scan_sessions(family="local"))
    list(scanner.scan_chats())
    assert asked == [ORG_A, ORG_B, ORG_A, ORG_B]


# --- the client ----------------------------------------------------------


@pytest.fixture
def sent(monkeypatch):
    calls: list[tuple[str, dict]] = []

    def fake_get(self, path, params=None):
        calls.append((path, dict(params or {})))
        return {"data": [], "has_more": False}

    monkeypatch.setattr(ComplianceClient, "get", fake_get)
    return calls


def test_the_client_sends_the_filter_where_the_api_takes_it(sent):
    client = ComplianceClient(api_key="sk-ant-api01-x")
    list(client.list_chats(organization_ids=[ORG_A]))
    list(client.activities(organization_ids=[ORG_A]))
    list(client.list_sessions("remote", organization_ids=[ORG_A]))
    list(client.list_sessions("local", organization_ids=[ORG_A]))
    by_path = {path: params for path, params in sent}
    assert by_path["/v1/compliance/apps/chats"]["organization_ids[]"] == [ORG_A]
    assert by_path["/v1/compliance/activities"]["organization_ids[]"] == [ORG_A]
    assert by_path["/v1/compliance/apps/sessions/remote"]["organization_ids[]"] == [ORG_A]
    # The local list has no organization filter; sending one would be a 400.
    assert "organization_ids[]" not in by_path["/v1/compliance/apps/sessions/local"]


def test_the_client_sends_no_filter_when_none_is_given(sent):
    client = ComplianceClient(api_key="sk-ant-api01-x")
    list(client.list_chats())
    list(client.activities())
    list(client.list_sessions("remote"))
    assert all("organization_ids[]" not in params for _, params in sent)
