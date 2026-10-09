"""Every metadata guard a request path builds probes with gitleaks when it
runs as a subprocess, so a credential only gitleaks recognises does not
reach a record, `/stats`, `/metrics` or a log line through an identity or
attribution value."""

from __future__ import annotations

import ast
import json
import logging
import shutil
from pathlib import Path

import pytest
from conftest import GITLEAKS_FIXTURES, WHSEC, ASGIClient, frame, make_policy, sign

from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store.local import LocalFileStore

pytestmark = pytest.mark.skipif(not shutil.which("gitleaks"),
                                reason="gitleaks binary not installed")

TOKEN = GITLEAKS_FIXTURES["shopify-access-token"]
SALT = "guard-subprocess-test-salt"
ORG = "org-guard-subprocess"
OTEL_TOKEN = "otel-token-for-the-guard-subprocess-tests"
SRC = Path(__file__).parent.parent / "src" / "forgd_verdict"


def _detectors():
    gl = GitleaksDetector()
    assert gl.available() and not gl.uses_daemon
    return [T0RegexDetector(), gl]


@pytest.fixture(autouse=True)
def _propagate(monkeypatch):
    """`configure_logging` stops `forgd_verdict` propagating, which hides its
    records from caplog for every later test in the process."""
    monkeypatch.setattr(logging.getLogger("forgd_verdict"), "propagate", True)


def _logged(caplog, capsys) -> str:
    out = capsys.readouterr()
    records = [f"{r.getMessage()} {getattr(r, 'fields', '')}" for r in caplog.records]
    return "\n".join([out.out, out.err, *records])


def _stored(store) -> str:
    return "\n".join(r.to_json() for r in store.read_verdicts("1990-01-01T00:00:00Z", None))


def _files(root) -> str:
    return "\n".join(p.read_text(errors="replace") for p in root.rglob("*") if p.is_file())


def test_the_fixture_is_gitleaks_only():
    dets = _detectors()
    assert MetadataGuard(dets).matches({"v": TOKEN}) == set()
    assert MetadataGuard(dets, allow_subprocess=True).matches({"v": TOKEN}) == {"v"}


# -- adapter 4 -----------------------------------------------------------

def _otel_batches():
    """Batches that put TOKEN in every identity or attribution value the
    collector reads: the resource's service and host names, the agent and
    app names and the event-name prefix an unattributed record is reported
    by, and the session, prompt, model and an ordinary record attribute."""
    from test_otel_payload import logs_json

    attrs = {"session.id": TOKEN, "prompt.id": TOKEN, "model": TOKEN, "note": TOKEN,
             "organization.id": ORG}
    return [
        logs_json([{"attributes": {**attrs, "event.name": "claude_code.user_prompt",
                                   "prompt": "hello there"}, "body": ""}],
                  {"service.name": TOKEN, "host.name": TOKEN}),
        *(logs_json([{"attributes": {**attrs, "event.name": "x.event", key: TOKEN,
                                     "prompt": "hello there"}, "body": ""}],
                    {"host.name": TOKEN})
          for key in ("agent.type", "agent.name", "app.name")),
        logs_json([{"attributes": {**attrs, "event.name": f"{TOKEN}.event",
                                   "prompt": "hello there"}, "body": ""}],
                  {"host.name": TOKEN}),
    ]


async def test_the_collector_keeps_a_gitleaks_only_value_out_of_every_sink(
        tmp_path, caplog, capsys):
    from forgd_verdict.otel.app import Collector

    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": SALT},
        "otel": {"orgs": [{"id": ORG, "label": "primary", "token": OTEL_TOKEN}]}}))
    store = LocalFileStore(tmp_path / "store", instance="t")
    app = Collector(policy, store=store, detectors=_detectors())
    caplog.set_level(logging.DEBUG)
    try:
        for body in _otel_batches():
            status, out = await ASGIClient(app).post(
                "/v1/logs", body, {"authorization": f"Bearer {OTEL_TOKEN}",
                                   "content-type": "application/json"})
            assert status == 200, out
            assert TOKEN not in json.dumps(out)
        # Metric names and refused origins reach /stats without being scanned.
        metrics = json.dumps({"resourceMetrics": [{"scopeMetrics": [
            {"metrics": [{"name": f"m.{TOKEN}"}]}]}]}).encode()
        status, _ = await ASGIClient(app).post(
            "/v1/metrics", metrics, {"authorization": f"Bearer {OTEL_TOKEN}",
                                     "content-type": "application/json"})
        assert status == 200
        await ASGIClient(app).request("OPTIONS", "/v1/logs",
                                      headers={"origin": f"https://{TOKEN}.example.com"})
        stats = json.dumps(app.stats())
        app.sink.close()
        stored = _stored(store)
    finally:
        app.close()
    assert stored.count('"source"') == 5
    assert TOKEN not in stored
    assert TOKEN not in stats and f"unattributed:{TOKEN}" not in stats
    assert TOKEN not in _logged(caplog, capsys)


def test_collect_without_a_guard_builds_one_that_includes_subprocess_gitleaks():
    """The token is only in values the scan does not read, so only the
    guard `collect` builds can replace it."""
    from test_otel_payload import logs_json

    from forgd_verdict.otel.collect import collect
    from forgd_verdict.otel.payload import decode

    batches = [
        logs_json([{"attributes": {"event.name": f"{TOKEN}.event", "prompt": "hello there"},
                    "body": ""}], {"host.name": "h"}),
        logs_json([{"attributes": {"event.name": "claude_code.user_prompt",
                                   "prompt": "hello there"}, "body": ""}],
                  {"service.name": TOKEN}),
    ]
    records = [r for b in batches for r in decode(b, "application/json", "logs")]
    out, unknown = collect(records, _detectors(), budget_ms=5000, salt=SALT, org_id=ORG)
    assert len(out) == 2
    assert TOKEN not in json.dumps([r.to_json() for r in out])
    assert TOKEN not in json.dumps(unknown)


# -- adapter 1 -----------------------------------------------------------

@pytest.mark.parametrize("position", ["request_id", "tenant_id", "source.application",
                                      "model"])
async def test_the_verdict_server_keeps_a_gitleaks_only_value_out_of_every_sink(
        position, tmp_path, caplog, capsys):
    from forgd_verdict.server.app import VerdictServer

    store = LocalFileStore(tmp_path / "store", instance="t")
    policy = make_policy(server={"mode": "enforce", "secrets": [WHSEC],
                                 "csv_path": str(tmp_path / "t.csv")})
    server = VerdictServer(policy, store=store, detectors=_detectors())
    body = frame()
    if position == "source.application":
        body["source"] = {"application": TOKEN}
    else:
        body[position] = TOKEN
    raw = json.dumps(body).encode()
    caplog.set_level(logging.DEBUG)
    try:
        status, resp = await ASGIClient(server).post("/hook", raw,
                                                     sign(raw, webhook_id="msg_guard"))
        assert status == 200, resp
        metrics = json.dumps(server._metrics_body())
    finally:
        server.close()
    assert TOKEN not in json.dumps(resp)
    assert TOKEN not in metrics
    assert TOKEN not in _stored(store)
    assert TOKEN not in _files(tmp_path)
    assert TOKEN not in _logged(caplog, capsys)
    # `tenant_id` is pseudonymised before every sink, so for it this counter
    # is the only output the guard changes; the construction itself is
    # pinned by test_every_metadata_guard_construction_allows_subprocess_gitleaks.
    assert json.loads(metrics)["counters"]["metadata_redacted"] >= 1


# -- the connector -------------------------------------------------------

async def test_the_connector_screens_a_refused_origin_with_subprocess_gitleaks(
        tmp_path, caplog):
    pytest.importorskip("mcp", reason="needs forgd-verdict[connector]")
    from test_connector_server import _call, _cfg, create_app

    app = create_app(_cfg(tmp_path))
    caplog.set_level(logging.DEBUG)
    status, _, _ = await _call(app, "POST", "/mcp", {},
                               {"origin": f"https://{TOKEN}.example.com"})
    assert status == 403
    logged = [getattr(r, "fields", {}) for r in caplog.records
              if r.getMessage() == "connector request refused"]
    assert logged and logged[0]["reason"] == "origin not allowed"
    assert TOKEN not in caplog.text
    assert TOKEN not in json.dumps(logged, default=str)


# -- the ingest jobs' label refusals -------------------------------------

def test_the_managed_ingest_refuses_a_gitleaks_only_workspace_label(
        tmp_path, monkeypatch, caplog):
    from test_managed_agents import KEY, FakeClient

    from forgd_verdict.managed.scanner import run_managed_ingest

    monkeypatch.setattr("forgd_verdict.managed.scanner.ManagedAgentsClient",
                        lambda **kw: FakeClient([], {}))
    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": SALT},
        "managed_agents": {"workspaces": [{"key": "ws-1", "label": TOKEN, "api_key": KEY}]}}))
    caplog.set_level(logging.DEBUG)
    summary = run_managed_ingest(policy, LocalFileStore(tmp_path, instance="t"))
    assert TOKEN not in json.dumps(summary, default=str)
    messages = [r.getMessage() for r in caplog.records]
    assert "managed_agents.workspaces is misconfigured; skipped" in messages
    assert TOKEN not in "\n".join(f"{r.getMessage()} {getattr(r, 'fields', '')}"
                                  for r in caplog.records)


def test_the_compliance_ingest_refuses_a_gitleaks_only_org_label(tmp_path, monkeypatch):
    import forgd_verdict.compliance.ingest as mod

    def reached(*a, **kw):
        raise AssertionError("the ingest scanned an org whose label matches gitleaks")

    monkeypatch.setattr(mod, "ComplianceScanner", reached)
    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": SALT},
        "compliance": {"orgs": [{"id": "org-a", "label": TOKEN, "api_key": "k"}]}}))
    with pytest.raises(ValueError, match="compliance org entry 0") as exc:
        mod.run_ingest(policy, LocalFileStore(tmp_path, instance="t"), include_denials=False)
    assert TOKEN not in str(exc.value)


# -- every construction --------------------------------------------------

# Constructions under src/ that may omit `allow_subprocess=True`, with why.
GUARD_ALLOWLIST: dict[str, str] = {}


def _constructions():
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "MetadataGuard"):
                yield path.relative_to(SRC).as_posix(), node


def test_every_metadata_guard_construction_allows_subprocess_gitleaks():
    missing = []
    for rel, node in _constructions():
        opted = any(k.arg == "allow_subprocess" and isinstance(k.value, ast.Constant)
                    and k.value.value is True for k in node.keywords)
        if not opted and rel not in GUARD_ALLOWLIST:
            missing.append(f"{rel}:{node.lineno}")
    assert missing == []


def test_the_guard_allowlist_has_no_stale_entries():
    seen = {rel for rel, node in _constructions()
            if not any(k.arg == "allow_subprocess" for k in node.keywords)}
    assert set(GUARD_ALLOWLIST) <= seen
