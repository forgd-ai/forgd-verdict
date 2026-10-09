"""Adapter 6: Managed Agents session histories, scanned post-hoc.

Event shapes are the documented ones for the managed-agents-2026-04-01
beta; values are synthetic.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import FAKE_AWS_KEY, FAKE_SSN

from forgd_verdict.compliance.client import ComplianceError
from forgd_verdict.managed.client import BETA, ManagedAgentsClient
from forgd_verdict.managed.scanner import (
    SURFACE,
    ManagedScanner,
    events_to_messages,
    report_to_record,
    run_managed_ingest,
    workspaces,
)
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge, redacted
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import SOURCE_MANAGED_SCAN
from forgd_verdict.store.query import build_summary

KEY = "sk-ant-api03-" + "x" * 90
WS_KEY = "ws-7f3a9c"


def ago(**kw) -> str:
    return (datetime.now(UTC) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


def history(secret_in_result: str = f"ssn {FAKE_SSN}"):
    return [
        {"type": "user.message", "id": "sevt_1", "content": [{"type": "text", "text": "summarise notes"}]},
        {"type": "agent.tool_use", "id": "sevt_2", "name": "read", "input": {"file_path": "notes.txt"}},
        {"type": "agent.tool_result", "id": "sevt_3", "tool_use_id": "sevt_2",
         "content": [{"type": "text", "text": secret_in_result}]},
        {"type": "session.status_idle", "id": "sevt_4", "stop_reason": {"type": "end_turn"}},
    ]


class FakeClient:
    def __init__(self, sessions, events):
        self.sessions, self.events, self.fetched = sessions, events, []

    def list_sessions(self, limit=100):
        yield from self.sessions

    def session_events(self, sid, limit=100, log_as=None, status=None):
        self.fetched.append(sid)
        ev = self.events[sid]
        if isinstance(ev, Exception):
            raise ev
        yield from ev


def policy(**managed):
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": "s"},
        "managed_agents": {"workspaces": [{"key": WS_KEY, "label": "prod", "api_key": KEY}],
                           **managed},
    }))


def session(sid, created=None, updated=None):
    return {"id": sid, "agent": {"id": "agent_01", "version": 1}, "status": "idle",
            "created_at": created or ago(hours=2), "updated_at": updated or ago(hours=1)}


@pytest.fixture(autouse=True)
def _cursor_in_tmp(tmp_path, monkeypatch):
    """With no store the cursor is a file in the working directory."""
    monkeypatch.chdir(tmp_path)


def scanner(sessions, events, store=None, **managed):
    return ManagedScanner(policy(**managed), {"key": WS_KEY, "label": "prod", "api_key": KEY},
                          store=store, client=FakeClient(sessions, events))


# -- translation ------------------------------------------------------------


def test_events_become_frame_messages():
    msgs = events_to_messages(history())
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    assert msgs[1]["content"][0] == {"type": "tool_use", "id": "sevt_2",
                                     "tool_name": "read", "input": {"file_path": "notes.txt"}}
    assert msgs[2]["content"][0]["tool_use_id"] == "sevt_2"


def test_an_unknown_event_is_scanned_and_never_trusted():
    (m,) = events_to_messages([{"type": "agent.new_thing", "id": "x", "payload": FAKE_AWS_KEY}])
    assert m["role"] == "synthetic" and m["content"][0]["payload"] == FAKE_AWS_KEY


def test_control_events_are_not_content():
    assert events_to_messages([
        {"type": "user.tool_confirmation", "tool_use_id": "t", "result": "deny",
         "deny_message": "ours"},
        {"type": "session.error", "id": "e", "error": {"message": "upstream"}}]) == []


# -- scanning ---------------------------------------------------------------


def test_a_secret_in_a_tool_result_is_found():
    (rep,) = scanner([session("sesn_1")], {"sesn_1": history()}).scan()
    assert any(f.detector == "regex:ssn" for f in rep.findings)
    assert rep.events == 4 and rep.agent_id == "agent_01"


def test_an_unchanged_session_is_not_fetched_again(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    s = [session("sesn_1", updated="2099-01-01T00:00:00Z")]
    first = scanner(s, {"sesn_1": history()}, store=store)
    list(first.scan())
    first.commit()
    again = scanner(s, {"sesn_1": history()}, store=store)
    assert list(again.scan()) == [] and again.client.fetched == []
    s[0]["updated_at"] = "2099-01-02T00:00:00Z"
    assert len(list(scanner(s, {"sesn_1": history()}, store=store).scan())) == 1


def test_nothing_is_marked_seen_until_commit(tmp_path):
    """The records are written between the two. Otherwise a failed write
    leaves sessions marked seen that were never recorded."""
    store = LocalFileStore(tmp_path, instance="t")
    s = [session("sesn_1")]
    list(scanner(s, {"sesn_1": history()}, store=store).scan())
    assert len(list(scanner(s, {"sesn_1": history()}, store=store).scan())) == 1


def test_a_session_with_no_updated_at_is_scanned_once(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    s = [{**session("sesn_1"), "updated_at": None}]
    first = scanner(s, {"sesn_1": history()}, store=store)
    list(first.scan())
    first.commit()
    assert list(scanner(s, {"sesn_1": history()}, store=store).scan()) == []


def test_the_walk_stops_at_the_window_edge():
    s = [session("new"), session("old", created=ago(days=40))]
    sc = scanner(s, {"new": history(), "old": history()}, window_days=30)
    assert [r.session_id for r in sc.scan()] == ["new"] and sc.client.fetched == ["new"]


def test_a_session_deleted_mid_pass_is_skipped():
    sc = scanner([session("gone"), session("here")],
                 {"gone": ComplianceError(404, "", "u"), "here": history()})
    assert [r.session_id for r in sc.scan()] == ["here"]


def test_one_unreadable_session_does_not_block_the_rest(tmp_path):
    """If it failed the whole pass, before the cursor was saved, every
    later pass would stop at the same session."""
    store = LocalFileStore(tmp_path, instance="t")
    s = [session("bad"), session("good")]
    sc = scanner(s, {"bad": ComplianceError(413, "", "u"), "good": history()}, store=store)
    assert [r.session_id for r in sc.scan()] == ["good"] and sc.failed == 1
    sc.commit()
    again = scanner(s, {"bad": history(), "good": history()}, store=store)
    assert [r.session_id for r in again.scan()] == ["bad"]


# -- records ----------------------------------------------------------------


def test_the_record_is_post_hoc_and_carries_no_content():
    (rep,) = scanner([session("sesn_1")], {"sesn_1": history(f"key {FAKE_AWS_KEY}")}).scan()
    rec = report_to_record(rep, "s", "prod")
    assert rec.source == SOURCE_MANAGED_SCAN and rec.surface == SURFACE
    assert not rec.is_inline
    blob = rec.to_json()
    assert FAKE_AWS_KEY not in blob and "agent_01" not in blob and "prod" not in blob


def test_the_dashboard_counts_it_as_its_own_column():
    (rep,) = scanner([session("sesn_1")], {"sesn_1": history()}).scan()
    s = build_summary([report_to_record(rep, "s", "prod")])
    (row,) = s.surfaces
    assert row.managed == 1 and row.post_hoc == 0 and not row.inline_coverage
    assert s.managed_sessions == 1 and s.scanned_sessions == 0
    # Both session scans are the detection rate's denominator.
    assert s.detection_rate == 1.0


def test_rescans_of_one_session_are_counted_once():
    sc = scanner([session("sesn_1")], {"sesn_1": history()})
    (rep,) = sc.scan()
    recs = [report_to_record(rep, "s", "prod") for _ in range(3)]
    for i, r in enumerate(recs):
        r.observed_at = f"2026-09-2{i}T00:00:00Z"
    s = build_summary(recs)
    assert s.managed_sessions == 1 and s.surfaces[0].managed == 1


def test_a_workspace_label_resolves_as_a_workspace_and_not_an_org():
    p = policy()
    assert "prod" not in p.org_labels().values()
    from forgd_verdict.models import pseudonym

    assert dict(p.workspace_labels()) == {pseudonym(WS_KEY, "s", "workspace"): "prod"}


def test_ingest_writes_records_per_workspace(tmp_path, monkeypatch):
    store = LocalFileStore(tmp_path, instance="t")
    fake = FakeClient([session("sesn_1")], {"sesn_1": history()})
    monkeypatch.setattr("forgd_verdict.managed.scanner.ManagedAgentsClient",
                        lambda **kw: fake)
    summary = run_managed_ingest(policy(), store)
    assert summary["workspaces"] == [{"workspace": "prod", "ok": True, "sessions_scanned": 1,
                                      "sessions_failed": 0, "verdicts_written": 1}]
    (rec,) = store.read_verdicts("1990-01-01T00:00:00Z", None)
    assert rec.source == SOURCE_MANAGED_SCAN


# -- configuration ----------------------------------------------------------


@pytest.mark.parametrize("ws", [
    [{"key": "a", "label": "a", "api_key": KEY}, {"key": "b", "label": "a", "api_key": KEY}],
    [{"key": "a", "api_key": KEY}],
    [{"key": "a", "label": "../x", "api_key": KEY}],
    [{"key": "a", "label": "a.b", "api_key": KEY}],
    [{"key": "../x", "label": "a", "api_key": KEY}],
    [{"key": "a.b", "label": "a", "api_key": KEY}],
    [{"key": "a", "label": "a", "api_key": KEY}, {"key": "a", "label": "b", "api_key": KEY}],
])
def test_workspace_labels_and_keys_must_be_unique_and_safe(ws):
    p = Policy(raw=_deep_merge(DEFAULT_POLICY, {"managed_agents": {"workspaces": ws}}))
    with pytest.raises(ValueError):
        workspaces(p)


def test_a_workspace_whose_key_is_unset_is_reported(tmp_path, monkeypatch):
    """The chart marks the key optional, so a secret missing from the vault
    was zero coverage and a clean summary."""
    monkeypatch.delenv("FORGD_MA_KEY_UNSET", raising=False)
    p = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": "s"},
        "managed_agents": {"workspaces": [
            {"key": "a", "label": "a", "api_key": "$FORGD_MA_KEY_UNSET"}]}}))
    out = run_managed_ingest(p, LocalFileStore(tmp_path, instance="t"))
    assert out["workspaces"] == [{"workspace": "a", "ok": False, "error": "no api key"}]


def test_a_bad_managed_block_does_not_stop_the_compliance_pass(tmp_path, monkeypatch, capsys):
    from forgd_verdict.cli import main

    ran = []
    monkeypatch.setattr("forgd_verdict.compliance.ingest.run_ingest",
                        lambda *a, **kw: ran.append(1) or {"orgs": []})
    p = tmp_path / "p.json"
    p.write_text(json.dumps({
        "server": {"store": str(tmp_path / "findings"), "csv_path": None},
        "privacy": {"hash_salt": "s"},
        "compliance": {"api_key": KEY},
        "managed_agents": {"workspaces": [{"label": "bad label", "api_key": KEY}]}}))
    assert main(["--policy", str(p), "ingest"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert ran and out["managed_agents"]["error"] == "invalid managed_agents.workspaces"


def test_the_key_never_reaches_the_policy_tab():
    assert KEY not in json.dumps(redacted(policy()), default=str)


def test_requests_carry_the_beta_header():
    headers = ManagedAgentsClient(api_key=KEY)._headers()
    assert headers["anthropic-beta"] == BETA and headers["x-api-key"] == KEY


def test_event_pages_follow_has_more_when_no_cursor_is_given(monkeypatch):
    c = ManagedAgentsClient(api_key=KEY)
    pages = [{"data": [{"id": "e1"}], "has_more": True},
             {"data": [{"id": "e2"}], "has_more": False}]
    seen = []

    def get(path, params):
        seen.append(dict(params))
        return pages[len(seen) - 1]

    monkeypatch.setattr(c, "get", get)
    assert [e["id"] for e in c.session_events("s")] == ["e1", "e2"]
    assert seen[1] == {"limit": 100, "after_id": "e1"}


def test_a_page_that_does_not_advance_is_not_scanned_twice(monkeypatch):
    """A server that ignores the cursor returns page one again."""
    c = ManagedAgentsClient(api_key=KEY)
    monkeypatch.setattr(c, "get", lambda path, params: {"data": [{"id": "e1"}], "has_more": True})
    assert [e["id"] for e in c.session_events("s")] == ["e1"]


def test_paging_that_cycles_between_two_pages_ends(monkeypatch):
    c = ManagedAgentsClient(api_key=KEY)
    pages = [{"data": [{"id": "e1"}], "has_more": True}, {"data": [{"id": "e2"}], "has_more": True}]
    n = []

    def get(path, params):
        n.append(1)
        assert len(n) < 10, "did not stop"
        return pages[(len(n) - 1) % 2]

    monkeypatch.setattr(c, "get", get)
    assert [e["id"] for e in c.session_events("s")] == ["e1", "e2"]


def test_ingest_runs_managed_agents_alone_without_a_compliance_key(tmp_path, monkeypatch, capsys):
    """A Platform-only deployment has no Enterprise org and no Compliance key."""
    from forgd_verdict.cli import main

    fake = FakeClient([session("sesn_1")], {"sesn_1": history()})
    monkeypatch.setattr("forgd_verdict.managed.scanner.ManagedAgentsClient", lambda **kw: fake)
    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", raising=False)
    p = tmp_path / "p.json"
    p.write_text(json.dumps({
        "server": {"store": str(tmp_path / "findings"), "csv_path": None},
        "privacy": {"hash_salt": "s"},
        "managed_agents": {"workspaces": [{"key": "prod", "label": "prod", "api_key": KEY}]}}))
    assert main(["--policy", str(p), "ingest"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["managed_agents"]["workspaces"][0]["sessions_scanned"] == 1


# -- workspace identity -----------------------------------------------------

ORG_ID = "00000000-0000-4000-8000-000000000000"


def ws_policy(*entries, **extra):
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": "s"},
        "managed_agents": {"workspaces": [{"api_key": KEY, **e} for e in entries]},
        **extra}))


def ingest(p, store, monkeypatch, sessions):
    fake = FakeClient(sessions, {s["id"]: history() for s in sessions})
    monkeypatch.setattr("forgd_verdict.managed.scanner.ManagedAgentsClient",
                        lambda **kw: fake)
    return run_managed_ingest(p, store), fake


def partitions(store):
    return {r.session_id: r.tenant_hash
            for r in store.read_verdicts("1990-01-01T00:00:00Z", None)}


def test_records_are_filed_under_the_workspace_key_and_prefix():
    (rep,) = scanner([session("sesn_1")], {"sesn_1": history()}).scan()
    from forgd_verdict.models import pseudonym

    assert report_to_record(rep, "s", WS_KEY).tenant_hash == pseudonym(WS_KEY, "s", "workspace")


def test_a_label_equal_to_an_org_id_does_not_land_in_that_orgs_partition(
        tmp_path, monkeypatch):
    from forgd_verdict.models import pseudonym

    store = LocalFileStore(tmp_path, instance="t")
    p = ws_policy({"key": ORG_ID, "label": ORG_ID}, orgs=[{"id": ORG_ID, "label": "Prod"}])
    ingest(p, store, monkeypatch, [session("sesn_1")])
    (tenant,) = partitions(store).values()
    assert tenant != pseudonym(ORG_ID, "s", "org") and tenant.startswith("workspace_")


def test_renaming_a_label_keeps_history_and_cursor_in_one_partition(tmp_path, monkeypatch):
    store = LocalFileStore(tmp_path, instance="t")
    first = session("sesn_1")
    ingest(ws_policy({"key": "support", "label": "support"}), store, monkeypatch, [first])
    _, fake = ingest(ws_policy({"key": "support", "label": "helpdesk"}), store, monkeypatch,
                     [session("sesn_2"), first])
    assert fake.fetched == ["sesn_2"]
    found = partitions(store)
    assert set(found) == {"sesn_1", "sesn_2"} and len(set(found.values())) == 1


def test_a_reused_label_does_not_merge_two_workspaces(tmp_path, monkeypatch):
    store = LocalFileStore(tmp_path, instance="t")
    ingest(ws_policy({"key": "a", "label": "shared"}), store, monkeypatch, [session("sesn_a")])
    ingest(ws_policy({"key": "a", "label": "retired"}, {"key": "b", "label": "shared"}),
           store, monkeypatch, [session("sesn_b")])
    found = partitions(store)
    assert found["sesn_a"] != found["sesn_b"]


def _seen(store, name, sessions):
    from forgd_verdict.compliance.scanner import State

    st = State(name, store=store)
    st.data["sessions"] = sessions
    st.save()


def test_the_cursor_is_seeded_from_the_one_the_label_named(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    s = [session("sesn_1")]
    _seen(store, "managed-prod.json", {"sesn_1": s[0]["updated_at"]})
    sc = scanner(s, {"sesn_1": history()}, store=store)
    assert list(sc.scan()) == [] and sc.client.fetched == []
    sc.commit()
    assert store.get_state(f"managed-{WS_KEY}.json") is not None


def test_the_cursor_is_seeded_only_when_the_keys_own_is_absent(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    s = [session("sesn_1")]
    _seen(store, "managed-prod.json", {"sesn_1": s[0]["updated_at"]})
    _seen(store, f"managed-{WS_KEY}.json", {})
    assert [r.session_id for r in scanner(s, {"sesn_1": history()}, store=store).scan()] \
        == ["sesn_1"]


def test_two_keys_with_one_pseudonym_are_refused(monkeypatch):
    monkeypatch.setattr("forgd_verdict.orgregistry.pseudonym",
                        lambda value, salt, prefix: f"{prefix}_0000000000")
    with pytest.raises(ValueError) as exc:
        workspaces(ws_policy({"key": "a", "label": "first"}, {"key": "b", "label": "second"}))
    assert "'first'" in str(exc.value) and "'second'" in str(exc.value)


MISSING_KEY = (
    "managed_agents.workspaces entry 'support-agents' has no `key`. Add "
    "`key: support-agents` to it. The key names the workspace's findings "
    "partition and cursor, so it must never change and never be reused by "
    "another workspace; the label can then be renamed freely.")


def test_a_workspace_with_no_key_is_refused_by_label_with_what_to_add(tmp_path, caplog):
    p = ws_policy({"label": "support-agents"})
    with pytest.raises(ValueError) as exc:
        workspaces(p)
    assert str(exc.value) == MISSING_KEY
    out = run_managed_ingest(p, LocalFileStore(tmp_path, instance="t"))
    assert out == {"workspaces": [], "error": "invalid managed_agents.workspaces",
                   "detail": MISSING_KEY}
    assert any(getattr(r, "fields", {}).get("detail") == MISSING_KEY for r in caplog.records)


@pytest.mark.parametrize("entries", [
    [{"key": "Kx-secret-name", "label": "a"}, {"key": "Kx-secret-name", "label": "b"}],
    [{"key": "Kx-secret.name", "label": "a"}],
])
def test_a_refusal_never_names_the_key(entries):
    with pytest.raises(ValueError) as exc:
        workspaces(ws_policy(*entries))
    assert "Kx-secret" not in str(exc.value)


def test_the_key_reaches_no_log_summary_or_record(tmp_path, monkeypatch, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    key = "Kx-7f3a9c"
    store = LocalFileStore(tmp_path, instance="t")
    store.put_state(f"managed-{key}.json", b"{not json")
    summary, _ = ingest(ws_policy({"key": key, "label": "prod"}), store, monkeypatch,
                        [session("sesn_1")])
    assert summary["workspaces"][0]["verdicts_written"] == 1
    assert "ingest cursor did not parse" in caplog.text
    logged = caplog.text + json.dumps([getattr(r, "fields", {}) for r in caplog.records])
    records = [r.to_json() for r in store.read_verdicts("1990-01-01T00:00:00Z", None)]
    assert key not in logged and key not in json.dumps(summary) and key not in "".join(records)


@pytest.mark.parametrize("pages", [
    [{"data": [{"id": "e1"}], "has_more": True}] * 2,
    [{"data": [{"id": "e1"}], "has_more": True}, {"data": [], "has_more": True}],
], ids=["stuck", "empty-page"])
def test_a_history_paging_could_not_finish_reports_itself_incomplete(monkeypatch, pages):
    c = ManagedAgentsClient(api_key=KEY)
    it = iter(pages)
    monkeypatch.setattr(c, "get", lambda path, params: next(it))
    status = {"complete": True}
    assert [e["id"] for e in c.session_events("s", status=status)] == ["e1"]
    assert status["complete"] is False


def test_a_partly_read_history_is_marked_and_never_replaces_a_whole_one():
    from forgd_verdict.store.query import latest_per_session

    class Partial(FakeClient):
        def session_events(self, sid, limit=100, log_as=None, status=None):
            status["complete"] = False
            yield from history()[:1]

    whole = scanner([session("sesn_1")], {"sesn_1": history()})
    (full,) = whole.scan()
    part = ManagedScanner(policy(), {"key": WS_KEY, "label": "prod", "api_key": KEY},
                          client=Partial([session("sesn_1")], {}))
    (rep,) = part.scan()
    assert "unscanned:partial" in rep.tiers_dropped
    early = report_to_record(full, "", WS_KEY)
    late = report_to_record(rep, "", WS_KEY)
    late.observed_at = "2999-01-01T00:00:00Z"
    (kept,) = latest_per_session([early, late])
    assert kept is early


def test_fields_of_a_recognised_event_the_message_does_not_carry_are_scanned():
    msgs = events_to_messages([
        {"type": "user.message", "id": "e", "content": [{"type": "text", "text": "hi"}],
         "attachments": [{"text": FAKE_AWS_KEY}]},
        {"type": "agent.message", "id": "f", "content": {"text": FAKE_AWS_KEY}},
    ])
    assert msgs[0]["role"] == "user"
    assert msgs[0]["content"][1] == {"type": "managed_event",
                                     "attachments": [{"text": FAKE_AWS_KEY}]}
    assert msgs[1]["content"][0] == {"type": "managed_content",
                                     "content": {"text": FAKE_AWS_KEY}}
    from forgd_verdict.core import scan
    from forgd_verdict.detectors.t0_regex import T0RegexDetector
    from forgd_verdict.extract import frame_units

    found = scan(frame_units(msgs), [T0RegexDetector()]).findings
    assert {f.locator.split(".")[0] for f in found} == {"msg[0]", "msg[1]"}


def test_two_workspace_keys_differing_only_in_case_are_refused():
    p = policy()
    p.raw["managed_agents"]["workspaces"] = [
        {"label": "a", "key": "Prod", "api_key": KEY},
        {"label": "b", "key": "prod", "api_key": KEY}]
    with pytest.raises(ValueError, match="without regard to case"):
        workspaces(p)
