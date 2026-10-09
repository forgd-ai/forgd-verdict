"""The metadata guard on the hook spool and the two ingest jobs includes
gitleaks as a subprocess, so a credential only gitleaks recognises does not
reach a record through a session id, a model name or a tool name."""

from __future__ import annotations

import shutil

import pytest

from forgd_verdict.metadata import MetadataGuard, guard_detectors
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge, load_policy
from forgd_verdict.store import LocalFileStore

pytestmark = pytest.mark.skipif(not shutil.which("gitleaks"),
                                reason="gitleaks binary not installed")

# A GitLab PAT: gitleaks has a rule for it and T0 does not.
GITLAB_PAT = "glpat-" + "x7Kq2mNp9wRt4vZs8bLc"
SALT = "metadata-gitleaks-test-salt"


def _files(root) -> str:
    return "\n".join(p.read_text(errors="replace") for p in root.rglob("*") if p.is_file())


def _subprocess_gitleaks(detectors):
    (g,) = [d for d in detectors if d.name == "gitleaks"]
    assert not g.uses_daemon
    return g


def test_the_fixture_is_gitleaks_only():
    detectors = load_policy("policy.yaml").build_detectors()
    _subprocess_gitleaks(detectors)
    assert MetadataGuard(detectors).matches({"v": GITLAB_PAT}) == set()
    assert MetadataGuard(detectors, allow_subprocess=True).matches({"v": GITLAB_PAT}) == {"v"}


def test_subprocess_gitleaks_is_opt_in():
    detectors = load_policy("policy.yaml").build_detectors()
    assert "gitleaks" not in {d.name for d in guard_detectors(detectors)}
    assert "gitleaks" in {d.name for d in guard_detectors(detectors, allow_subprocess=True)}


def test_one_record_is_one_gitleaks_call(monkeypatch):
    detectors = load_policy("policy.yaml").build_detectors()
    g = _subprocess_gitleaks(detectors)
    calls = []
    real = g.scan

    def scan(units):
        units = list(units)
        calls.append(len(units))
        return real(units)

    monkeypatch.setattr(g, "scan", scan)
    guard = MetadataGuard(detectors, SALT, allow_subprocess=True)
    out = guard.clean({"session_id": f"sess_{GITLAB_PAT}", "model": f"m-{GITLAB_PAT}",
                       "surface": "claude-code"})
    assert len(calls) == 1 and calls[0] > 3
    assert GITLAB_PAT not in repr(out) and out["surface"] == "claude-code"


def test_a_failing_subprocess_replaces_every_value(monkeypatch):
    from forgd_verdict.detectors.base import DetectorFailed

    detectors = load_policy("policy.yaml").build_detectors()
    g = _subprocess_gitleaks(detectors)

    def scan(units):
        raise DetectorFailed("gitleaks: timeout")

    monkeypatch.setattr(g, "scan", scan)
    out = MetadataGuard(detectors, SALT, allow_subprocess=True).clean(
        {"a": "claude-code", "b": "ordinary"})
    assert out["a"].startswith("redacted_") and out["b"].startswith("redacted_")


def test_the_hook_spool_replaces_a_gitleaks_only_tool_name_and_session(tmp_path):
    from forgd_verdict.hook.cli import run

    spool = tmp_path / "spool"
    policy = Policy(raw=_deep_merge(load_policy("policy.yaml").raw, {
        "hook": {"spool": str(spool), "spool_enabled": True, "scan_endpoint": "",
                 "ship_mode": "off",
                 "detectors": {"gitleaks": {"binary": shutil.which("gitleaks")}}}}))
    payload = {"hook_event_name": "PreToolUse", "tool_name": f"run_{GITLAB_PAT}",
               "tool_use_id": "toolu_01", "session_id": f"sess_{GITLAB_PAT}",
               "tool_input": {"command": "ls"}}
    run(payload, policy)
    spooled = _files(spool)
    assert spooled.strip()
    assert GITLAB_PAT not in spooled


def test_the_compliance_ingest_replaces_a_gitleaks_only_session_and_model(
        tmp_path, monkeypatch):
    import forgd_verdict.compliance.ingest as mod
    from forgd_verdict.compliance.scanner import ChatReport, SessionReport

    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": SALT},
        "compliance": {"orgs": [{"id": "org-a", "api_key": "k"}]}}))
    built = policy.for_profile("compliance").build_detectors(profile="compliance")
    _subprocess_gitleaks(built)

    class Scanner:
        detectors = built

        def __init__(self, policy, org=None, client=None, store=None, detectors=None):
            self.org_id = str((org or {}).get("id") or "")
            self.org_label = self.org_id

        def scan_sessions(self, **kw):
            yield SessionReport(session_id=f"sess_{GITLAB_PAT}", product_surface="claude-code",
                                user_id="u", created_at="2026-09-19T00:00:00Z",
                                updated_at="2026-09-19T00:00:00Z", action="allow")

        def scan_chats(self, **kw):
            yield ChatReport(chat_id=f"chat_{GITLAB_PAT}", model=f"claude-{GITLAB_PAT}",
                             user_id="u")

        def denials(self, **kw):
            return iter(())

        def extract_reference_id(self, activity):
            return None

        def commit(self):
            pass

    monkeypatch.setattr(mod, "ComplianceScanner", Scanner)
    store = LocalFileStore(tmp_path, instance="t")
    mod.run_ingest(policy, store, include_denials=False, include_chats=True)
    rows = [r.to_json() for r in store.read_verdicts("1990-01-01T00:00:00Z", None)]
    assert len(rows) == 2
    assert GITLAB_PAT not in "\n".join(rows)


def test_the_managed_ingest_replaces_a_gitleaks_only_session_and_tool_name(
        tmp_path, monkeypatch, caplog):
    from test_managed_agents import KEY, FakeClient, session

    from forgd_verdict.managed.scanner import run_managed_ingest

    sid = f"sesn_{GITLAB_PAT}"
    events = [
        {"type": "user.message", "id": "sevt_1",
         "content": [{"type": "text", "text": "summarise notes"}]},
        {"type": "agent.tool_use", "id": "sevt_2", "name": f"read_{GITLAB_PAT}",
         "input": {"file_path": "notes.txt"}},
        {"type": "agent.tool_result", "id": "sevt_3", "tool_use_id": "sevt_2",
         "content": [{"type": "text", "text": "ssn 123-45-6789"}]},
    ]
    fake = FakeClient([session(sid)], {sid: events})
    monkeypatch.setattr("forgd_verdict.managed.scanner.ManagedAgentsClient", lambda **kw: fake)
    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": SALT},
        "managed_agents": {"workspaces": [{"key": "ws-1", "label": "prod", "api_key": KEY}]}}))
    store = LocalFileStore(tmp_path, instance="t")
    caplog.set_level("DEBUG")
    run_managed_ingest(policy, store)
    rows = [r.to_json() for r in store.read_verdicts("1990-01-01T00:00:00Z", None)]
    assert len(rows) == 1
    logged = "\n".join(f"{r.getMessage()} {getattr(r, 'fields', '')}" for r in caplog.records)
    assert GITLAB_PAT not in rows[0]
    assert GITLAB_PAT not in logged


def test_the_scanners_log_guards_include_subprocess_gitleaks(tmp_path):
    from test_managed_agents import scanner

    from forgd_verdict.compliance.scanner import ComplianceScanner

    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": SALT},
        "compliance": {"orgs": [{"id": "org-a", "api_key": "k"}]}}))
    (org,) = policy.compliance_orgs()
    compliance = ComplianceScanner(policy, client=object(), org=org,
                                   store=LocalFileStore(str(tmp_path)))
    managed = scanner([], {})
    for s in (compliance, managed):
        assert GITLAB_PAT not in s.meta.one(f"sess_{GITLAB_PAT}")
