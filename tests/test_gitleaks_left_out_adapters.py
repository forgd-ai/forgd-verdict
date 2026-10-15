"""Every adapter that records a verdict reports gitleaks in `tiers_dropped`
when the policy enables it (`enabled: auto`) and its binary was not found.

Without that, a block-severity tier that never ran is recorded as a clean
scan. `test_every_verdict_adapter_is_covered` fails when a module that
builds detectors from a policy is neither checked here nor listed as one
that records no verdict.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest
from conftest import WHSEC, ASGIClient, frame, make_policy, sign
from test_compliance import SESSION, ChatStub, StubClient, chat_with

from forgd_verdict.models import ACTION_DENY

SRC = Path(__file__).resolve().parent.parent / "src" / "forgd_verdict"
MISSING = {"enabled": "auto", "binary": "/nonexistent/gitleaks", "severity": "block"}

# Modules that build detectors from a policy and record a verdict: each has
# a test below. intake, the CLI scan and the hook have their own.
COVERED = {
    "server/app.py", "otel/app.py", "compliance/scanner.py", "managed/scanner.py",
    "intake/app.py", "cli.py", "hook/cli.py",
}
# Modules that build detectors only to screen labels, log values or names,
# or, in policycheck.py, to check a policy without scanning.
NO_VERDICT = {
    "compliance/ingest.py", "connector/app.py", "dashboard/app.py", "policycheck.py",
}


@pytest.fixture(autouse=True)
def _no_gitleaks_daemon(monkeypatch):
    monkeypatch.delenv("FORGD_GITLEAKS_SOCKET", raising=False)


def test_every_verdict_adapter_is_covered():
    building = {str(p.relative_to(SRC)) for p in SRC.rglob("*.py")
                if re.search(r"\.build_detectors\(", p.read_text())}
    building.discard("policy.py")
    assert building <= COVERED | NO_VERDICT, building - COVERED - NO_VERDICT


class _MemStore:
    def __init__(self):
        self.records = []

    def write_verdicts(self, records):
        self.records.extend(records)
        return len(records)

    def __getattr__(self, name):
        return lambda *a, **k: None


def test_the_verdict_server_records_gitleaks_dropped():
    from forgd_verdict.server.app import VerdictServer

    store = _MemStore()
    policy = make_policy(server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None,
                                 "store_batch_size": 1, "store_flush_s": 0.01},
                         detectors={"gitleaks": MISSING})
    srv = VerdictServer(policy, store=store)
    assert "gitleaks" not in [d.name for d in srv.detectors]

    async def go():
        body = json.dumps(frame([{"role": "user", "content": "hello world"}])).encode()
        status, _ = await ASGIClient(srv).post("/hook", body, sign(body))
        assert status == 200

    try:
        asyncio.run(go())
    finally:
        srv.close()
    assert store.records
    assert all("gitleaks" in (r.tiers_dropped or []) for r in store.records)


def test_the_verdict_server_denies_under_on_tier_dropped_deny():
    from forgd_verdict.server.app import VerdictServer

    policy = make_policy(server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None,
                                 "on_tier_dropped": "deny"},
                         detectors={"gitleaks": MISSING})
    srv = VerdictServer(policy)

    async def go():
        body = json.dumps(frame([{"role": "user", "content": "hello world"}])).encode()
        return await ASGIClient(srv).post("/hook", body, sign(body))

    try:
        status, verdict = asyncio.run(go())
    finally:
        srv.close()
    assert status == 200 and verdict["action"] == ACTION_DENY


def test_the_collector_records_gitleaks_dropped():
    from forgd_verdict.otel.collect import collect
    from forgd_verdict.otel.payload import OtelRecord

    policy = make_policy(detectors={"gitleaks": MISSING}).for_profile("otel")
    detectors = policy.build_detectors(profile="collector")
    record = OtelRecord(kind="log", name="claude_code.user_prompt",
                        attributes={"prompt": "hello world there", "session.id": "s-1"},
                        resource={"service.name": "claude-code"})
    skipped = []
    out, _ = collect([record], detectors, budget_ms=10_000, salt="x", org_id="o",
                     policy=policy, on_group=lambda *a: skipped.append(a[3]))
    assert out and all("gitleaks" in r.tiers_dropped for r in out)
    assert skipped and all("gitleaks" in s for s in skipped)


def _compliance_policy(tmp_path):
    return make_policy(detectors={"gitleaks": MISSING},
                       compliance={"state_path": str(tmp_path / "s.json"),
                                   "api_key": "sk-ant-api01-x"})


def test_the_compliance_session_scan_records_gitleaks_dropped(tmp_path):
    from forgd_verdict.compliance.scanner import ComplianceScanner

    messages = [{"type": "compliance_local_session_message", "id": "clsm_1",
                 "role": "user", "provenance": None,
                 "content": [{"type": "text", "text": "hello world"}]}]
    stub = StubClient(sessions=[SESSION], messages={SESSION["id"]: messages})
    (report,) = ComplianceScanner(_compliance_policy(tmp_path), client=stub).scan_sessions()
    assert "gitleaks" in report.tiers_dropped


def test_the_compliance_chat_scan_records_gitleaks_dropped(tmp_path):
    from forgd_verdict.compliance.scanner import ComplianceScanner

    chat = chat_with("hello world")
    stub = ChatStub(chats=[chat], full={chat["id"]: chat})
    (report,) = ComplianceScanner(_compliance_policy(tmp_path),
                                  client=stub).scan_chats(include_artifacts=False)
    assert "gitleaks" in report.tiers_dropped


def test_the_managed_agents_scan_records_gitleaks_dropped(tmp_path, monkeypatch):
    from test_managed_agents import KEY, WS_KEY, FakeClient, session

    from forgd_verdict.managed.scanner import ManagedScanner

    monkeypatch.chdir(tmp_path)
    policy = make_policy(detectors={"gitleaks": MISSING})
    events = [{"type": "user.message", "id": "sevt_1",
               "content": [{"type": "text", "text": "hello world"}]}]
    scanner = ManagedScanner(policy, {"key": WS_KEY, "label": "prod", "api_key": KEY},
                             client=FakeClient([session("sesn_1")], {"sesn_1": events}))
    (report,) = scanner.scan()
    assert "gitleaks" in report.tiers_dropped


def test_gitleaks_disabled_is_not_reported_dropped(tmp_path):
    from forgd_verdict.compliance.scanner import ComplianceScanner

    policy = make_policy(detectors={"gitleaks": {"enabled": False}},
                         compliance={"state_path": str(tmp_path / "s.json"),
                                     "api_key": "sk-ant-api01-x"})
    messages = [{"type": "compliance_local_session_message", "id": "clsm_1",
                 "role": "user", "provenance": None,
                 "content": [{"type": "text", "text": "hello world"}]}]
    stub = StubClient(sessions=[SESSION], messages={SESSION["id"]: messages})
    (report,) = ComplianceScanner(policy, client=stub).scan_sessions()
    assert "gitleaks" not in report.tiers_dropped


def test_a_warn_severity_gitleaks_left_out_is_recorded_and_does_not_deny(tmp_path):
    from forgd_verdict.compliance.scanner import ComplianceScanner

    policy = make_policy(detectors={"gitleaks": {**MISSING, "severity": "warn"}},
                         server={"on_tier_dropped": "deny"},
                         compliance={"state_path": str(tmp_path / "s.json"),
                                     "api_key": "sk-ant-api01-x"})
    messages = [{"type": "compliance_local_session_message", "id": "clsm_1",
                 "role": "user", "provenance": None,
                 "content": [{"type": "text", "text": "hello world"}]}]
    stub = StubClient(sessions=[SESSION], messages={SESSION["id"]: messages})
    (report,) = ComplianceScanner(policy, client=stub).scan_sessions()
    assert "gitleaks" in report.tiers_dropped
    assert report.action != ACTION_DENY
