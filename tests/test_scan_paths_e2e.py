"""Every adapter's scan path, end to end, with many matched dict keys.

A tool input whose keys are credentials puts each key into its own unit
and into the locator of every value beneath it. On the verdict server and
the hook, the key path rewrite and the locator scrub are held to their
structural bounds and the decision to its caller's deadline; intake, the
Compliance API scanner and the Managed Agents scanner are shown to reach
`scan`.
"""

from __future__ import annotations

import json
import time

import pytest
from conftest import ASGIClient, frame, make_policy, sign
from test_compliance import SESSION, StubClient
from test_key_path_rewrite import RewriteSpy
from test_scrub_bounds import HOOK_TIMEOUT_S, SCRUBS_PER_SCAN, VERDICT_TIMEOUT_S, ProbeSpy

from forgd_verdict import core
from forgd_verdict.hook.cli import run
from forgd_verdict.server.app import VerdictServer

# Two tests here bound wall-clock time, which a parallel run's load breaks.
pytestmark = pytest.mark.serial

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _aws_key(i: int) -> str:
    return "AKIA" + "".join(_B32[(i >> (5 * j)) & 31] for j in range(16))


def _keys(n: int) -> dict[str, str]:
    return {_aws_key(i): "v" for i in range(n)}


def _spy(monkeypatch, module) -> list:
    """Replace `module.scan` with a wrapper that records each result."""
    results: list = []

    def spy(*args, **kwargs):
        result = core.scan(*args, **kwargs)
        results.append(result)
        return result

    monkeypatch.setattr(module, "scan", spy)
    return results


@pytest.fixture
def server(policy):
    app = VerdictServer(policy)
    yield app
    app.close()


async def test_the_verdict_server_denies_many_matched_keys_quickly(server, monkeypatch):
    messages = [{"role": "assistant", "content": [
        {"type": "tool_use", "id": "toolu_1", "name": "mcp__x__y", "input": _keys(40_000)}]}]
    raw = json.dumps(frame(messages)).encode()
    rewrites, probes = RewriteSpy(monkeypatch), ProbeSpy(monkeypatch)
    start = time.perf_counter()
    status, verdict = await ASGIClient(server).post("/hook", raw, sign(raw))
    elapsed = time.perf_counter() - start
    assert status == 200
    assert verdict["action"] == "deny"
    assert "AKIA" not in json.dumps(verdict)
    rewrites.assert_bounded(locators=3 * core.MAX_SCAN_FINDINGS)
    probes.assert_bounded(scrubs=SCRUBS_PER_SCAN)
    assert elapsed < VERDICT_TIMEOUT_S, f"the server took {elapsed:.2f}s"


def test_the_hook_denies_many_matched_keys_quickly(monkeypatch):
    policy = make_policy(detectors={"gitleaks": {"enabled": False, "severity": "block"}})
    event = {"session_id": "abc123", "hook_event_name": "PreToolUse",
             "tool_name": "mcp__x__y", "tool_input": {"data": _keys(20_000)},
             "tool_use_id": "toolu_01ABC", "permission_mode": "default"}
    rewrites, probes = RewriteSpy(monkeypatch), ProbeSpy(monkeypatch)
    start = time.perf_counter()
    code, out = run(event, policy)
    elapsed = time.perf_counter() - start
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "AKIA" not in out
    rewrites.assert_bounded(locators=3 * core.MAX_SCAN_FINDINGS)
    probes.assert_bounded(scrubs=SCRUBS_PER_SCAN)
    assert elapsed < HOOK_TIMEOUT_S, f"the hook took {elapsed:.2f}s"


async def test_intake_scan_goes_through_scan(tmp_path, monkeypatch):
    from test_intake import TOKEN, _policy

    from forgd_verdict.intake import app as intake_app
    from forgd_verdict.store import LocalFileStore

    results = _spy(monkeypatch, intake_app)
    intake = intake_app.Intake(_policy(), store=LocalFileStore(tmp_path, instance="t"))
    try:
        body = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "mcp__x__y",
                           "tool_input": _keys(5_000)}).encode()
        status, verdict = await ASGIClient(intake).post(
            "/scan", body, {"authorization": f"Bearer {TOKEN}",
                            "content-type": "application/json"})
    finally:
        intake.close()
    assert status == 200
    assert verdict["action"] == "deny"
    assert results and results[0].findings
    assert "AKIA" not in json.dumps(verdict)


def test_the_compliance_session_scan_goes_through_scan(tmp_path, monkeypatch):
    from forgd_verdict.compliance import scanner as compliance_scanner

    results = _spy(monkeypatch, compliance_scanner)
    messages = [{
        "type": "compliance_local_session_message", "id": "clsm_1", "role": "assistant",
        "provenance": None,
        "content": [{"type": "tool_use", "id": "toolu_1", "name": "mcp__x__y",
                     "input": json.dumps(_keys(5_000)), "truncated": False}],
    }]
    stub = StubClient(sessions=[SESSION], messages={SESSION["id"]: messages})
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(tmp_path / "state.json"), "api_key": "sk-ant-api01-x"},
    )
    (report,) = compliance_scanner.ComplianceScanner(policy, client=stub).scan_sessions()
    assert report.action == "deny"
    assert results and results[0].findings
    assert not any("AKIA" in (f.locator or "") for f in report.findings)


def test_the_managed_agents_scan_goes_through_scan(tmp_path, monkeypatch):
    from test_managed_agents import scanner, session

    from forgd_verdict.managed import scanner as managed_scanner

    monkeypatch.chdir(tmp_path)
    results = _spy(monkeypatch, managed_scanner)
    events = [{"type": "agent.tool_use", "id": "sevt_1", "name": "mcp__x__y",
               "input": _keys(5_000)}]
    (report,) = scanner([session("sesn_1")], {"sesn_1": events}).scan()
    assert results and results[0].findings
    assert any(f.detector == "regex:aws-access-key" for f in report.findings)
    assert not any("AKIA" in (f.locator or "") for f in report.findings)
