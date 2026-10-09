"""The dashboard's JSON summary, event log and overview, pinned byte for byte.

A seeded store, a frozen clock, and one digest per response in
tests/pinned/dashboard_views.json. Any change to what `/api/summary`,
`/events` or `/` returns fails here, which is the point: the query layer and
the topology code are shared with other readers, and a refactor of them must
not move a number. The overview carries the delivery diagram, so its cases
cover the topology code, heartbeats from scan cursors included.

`FORGD_REGEN_GOLDEN=1` rewrites the digests. On a mismatch the actual body
is written beside the test's tmp_path for diffing.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import DETECTORS, OVERRIDES_KEY

from forgd_verdict.dashboard import app as dashboard_app
from forgd_verdict.dashboard.admin import AdminConfig
from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.entitlements import MODE_OIDC_JWT, Entitlements, Principal
from forgd_verdict.overrides import ACTION_INIT, KEY_MODE, Change, RuntimeOverrides, apply_change
from forgd_verdict.store import FindingRow, LocalFileStore, VerdictRecord
from forgd_verdict.store.base import (
    SOURCE_AGENT_SCAN,
    SOURCE_CODE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    SOURCE_OTEL_COLLECT,
    DenialRecord,
)

GOLDEN = Path(__file__).with_name("pinned") / "dashboard_views.json"
NOW = datetime(2026, 9, 20, 12, 0, 0, tzinfo=UTC)
NOW_S = "2026-09-20T12:00:00Z"
ORG_A = "org_aaaaaaaaaa"
ORG_B = "org_bbbbbbbbbb"


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: D102
        return NOW if tz is not None else NOW.replace(tzinfo=None)


@pytest.fixture
def frozen(monkeypatch):
    """Freeze every clock the summary and the event log read.

    Patched wherever the name is bound, not in one module, so the pin
    survives code moving between modules.
    """
    for name, mod in list(sys.modules.items()):
        if not name.startswith("forgd_verdict") or mod is None:
            continue
        if getattr(mod, "utcnow", None) is not None and callable(mod.utcnow):
            monkeypatch.setattr(mod, "utcnow", lambda: NOW_S)
        if getattr(mod, "datetime", None) is datetime:
            monkeypatch.setattr(mod, "datetime", _FrozenDatetime)


def _f(detector, severity, locator, ch, tool=None):
    return FindingRow(detector, severity, locator, ch * 64, tool)


def _seed(root: Path) -> LocalFileStore:
    store = LocalFileStore(root, instance="pin")
    store.write_verdicts([
        # Inside 24h.
        VerdictRecord(
            source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-20T10:00:00Z",
            request_id="req-1", surface="claude-ai", tenant_hash=ORG_A,
            actor_hash="usr_1111111111", action="allow", shadow_action="deny",
            reference_id="fv_awsaccesske_01A", total_ms=480.0, scan_ms=470.0,
            cache_hit=True, findings_count=1,
            findings=[_f("regex:aws-access-key", "block", "msg[2].content[0]", "a")],
        ),
        VerdictRecord(
            source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-20T10:05:00Z",
            request_id="req-2", surface="claude-ai", tenant_hash=ORG_B,
            action="deny", reference_id="fv_ssn_01B", total_ms=520.0,
            scan_ms=500.0, cache_hit=False, findings_count=1,
            findings=[_f("regex:ssn", "block", "msg[0]", "b")],
        ),
        VerdictRecord(
            source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-20T10:06:00Z",
            request_id="req-3", surface="cowork", tenant_hash=ORG_A,
            action="allow", total_ms=300.0, scan_ms=290.0,
        ),
        VerdictRecord(
            source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-20T10:07:00Z",
            request_id="req-excluded", surface="claude-ai", tenant_hash=ORG_A,
            action="deny", findings_count=1,
            findings=[_f("regex:aws-access-key", "block", "msg[1]", "c")],
        ),
        VerdictRecord(
            source=SOURCE_CODE_HOOK, observed_at="2026-09-20T09:00:00Z",
            surface="claude-code", tenant_hash=ORG_A, action="deny",
            findings_count=1,
            findings=[_f("regex:github-pat", "block", "tool_input.command",
                         "d", tool="Bash")],
        ),
        VerdictRecord(
            source=SOURCE_AGENT_SCAN, observed_at="2026-09-20T08:00:00Z",
            surface="agent:payroll", tenant_hash=ORG_B, action="allow",
        ),
        # 3 days old: in 7d and 30d.
        VerdictRecord(
            source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T09:00:00Z",
            session_id="clls_01", surface="claude_code", tenant_hash=ORG_A,
            messages_total=12, messages_scanned=12, findings_count=2,
            findings=[_f("regex:ssn", "block", "msg[1]", "e"),
                      _f("ner:person", "warn", "msg[3]", "f")],
        ),
        # A later scan of the same session, which must collapse with it.
        VerdictRecord(
            source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T15:00:00Z",
            session_id="clls_01", surface="claude_code", tenant_hash=ORG_A,
            messages_total=20, messages_scanned=20, findings_count=2,
            findings=[_f("regex:ssn", "block", "msg[1]", "e"),
                      _f("regex:ssn", "block", "msg[14]", "a")],
        ),
        VerdictRecord(
            source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-18T09:00:00Z",
            session_id="clls_02", surface="claude-ai", tenant_hash=ORG_B,
            findings_count=1, findings=[_f("ner:person", "warn", "msg[0]", "g")],
        ),
        # 20 days old: in 30d only.
        VerdictRecord(
            source=SOURCE_OTEL_COLLECT, observed_at="2026-08-31T09:00:00Z",
            surface="cowork", tenant_hash=ORG_A, reported_as="cowork",
            findings_count=1,
            findings=[_f("entropy:assignment", "warn", "attr.prompt", "h")],
        ),
        # 60 days old: in `all` only.
        VerdictRecord(
            source=SOURCE_INFERENCE_HOOK, observed_at="2026-07-22T09:00:00Z",
            request_id="req-old", surface="claude-ai", tenant_hash=ORG_B,
            action="deny", reference_id="fv_old_01", findings_count=1,
            findings=[_f("regex:aws-access-key", "block", "msg[0]", "i")],
        ),
    ])
    store.write_denials([
        DenialRecord(activity_id="act-1", created_at="2026-09-20T10:00:01Z",
                     reference_id="fv_awsaccesske_01A", tenant_hash=ORG_A),
        DenialRecord(activity_id="act-2", created_at="2026-09-20T10:05:01Z",
                     reference_id="fv_ssn_01B", tenant_hash=ORG_B),
        DenialRecord(activity_id="act-3", created_at="2026-09-19T10:00:00Z",
                     tenant_hash=ORG_A),
    ])
    store.set_excluded(["req-excluded"])
    return store


class _SignedIn(AuthConfig):
    """A verified caller in group `g-a`, without a token to verify."""

    def authenticate(self, headers):
        return Principal(name="viewer@example.com", groups=("g-a",),
                         issuer="https://idp.example.com")


def _open(tmp_path, **dashboard):
    return Dashboard(_seed(tmp_path / "store"), **dashboard)


def _topology(tmp_path, **dashboard):
    """Every control point configured, and two scan cursors, so the
    delivery diagram draws each state it can and reads heartbeats."""
    import json as _json

    from forgd_verdict.store.base import SOURCES

    store = _seed(tmp_path / "store")
    store.put_state("scan-a", _json.dumps({
        "last_run_started_at": "2026-09-20T06:00:00Z",
        "run_gaps_min": [360, 355, 362]}).encode())
    store.put_state("scan-b", _json.dumps({
        "last_run_started_at": "2026-09-19T19:20:00Z",
        "run_gaps_min": [720, 715, 725]}).encode())
    configured = {src: True for src in SOURCES}
    return Dashboard(store, configured=configured, scan_state_keys=["scan-a", "scan-b"],
                     sink_name="siem", **dashboard)


def _entitled(tmp_path):
    return Dashboard(
        _seed(tmp_path / "store"),
        auth=_SignedIn(mode=MODE_OIDC_JWT),
        entitlements=Entitlements(by_group={"g-a": frozenset({ORG_A})}),
        org_labels={ORG_A: "Prod", ORG_B: "Dev"},
    )


CASES = [
    *[(f"summary-{w}", "open", f"/api/summary?window={w}")
      for w in ("24h", "7d", "30d", "all")],
    ("summary-entitled-all", "entitled", "/api/summary?window=all"),
    ("summary-entitled-org", "entitled", f"/api/summary?window=all&org={ORG_A}"),
    *[(f"events-{w}", "open", f"/events?window={w}")
      for w in ("24h", "7d", "30d", "all")],
    ("events-source-inference", "open", "/events?window=all&source=inference_hook"),
    ("events-source-compliance", "open", "/events?window=all&source=compliance_scan"),
    ("events-source-code-hook", "open", "/events?window=all&source=code_hook"),
    ("events-action-deny", "open", "/events?window=all&action=deny"),
    ("events-source-and-deny", "open",
     "/events?window=30d&source=inference_hook&action=deny"),
    ("events-entitled-all", "entitled", "/events?window=all"),
    ("events-entitled-org", "entitled", f"/events?window=all&org={ORG_A}"),
    ("events-entitled-org-deny", "entitled",
     f"/events?window=all&org={ORG_A}&action=deny"),
    *[(f"overview-{w}", "open", f"/?window={w}") for w in ("24h", "7d", "30d", "all")],
    ("overview-entitled-all", "entitled", "/?window=all"),
    ("overview-entitled-org", "entitled", f"/?window=all&org={ORG_A}"),
    *[(f"overview-topology-{w}", "topology", f"/?window={w}") for w in ("24h", "7d", "all")],
]


async def _get(app, path: str) -> tuple[int, bytes]:
    """Status and the body exactly as sent. conftest's client parses it."""
    path, _, query = path.partition("?")
    scope = {"type": "http", "method": "GET", "path": path,
             "query_string": query.encode("latin-1"), "headers": []}
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status, b"".join(m.get("body", b"") for m in sent
                            if m["type"] == "http.response.body")


def _digest(body: bytes) -> dict:
    return {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}


class _Admin(AuthConfig):
    """A verified caller in the admin group, without a token to verify."""

    def authenticate(self, headers):
        return Principal(name="admin@example.com", groups=("ops",), subject="admin-1",
                         issuer="https://idp.example.com")


def _admin(tmp_path, **dashboard):
    store = _seed(tmp_path / "store")
    auth = _Admin(mode=MODE_OIDC_JWT)
    admins = AdminConfig.parse({"groups": [{"group": "ops"}],
                                "allowed_origins": ["https://dash.example.com"],
                                "form_key": "k" * 40}, auth)
    apply_change(store, {"name": "ops"}, Change(ACTION_INIT), detectors=DETECTORS,
                 signing_key=OVERRIDES_KEY)
    overrides = RuntimeOverrides(store, "dashboard", baseline={KEY_MODE: "observe"})
    overrides.refresh()
    return Dashboard(store, auth=auth, admins=admins, overrides=overrides, **dashboard)


# Page name, the app that serves it, and its path.
PAGES = [
    ("overview-7d.html", "open", "/?window=7d"),
    ("overview-all.html", "open", "/?window=all"),
    ("overview-topology-7d.html", "topology", "/?window=7d"),
    ("overview-topology-all.html", "topology", "/?window=all"),
    ("events-all.html", "open", "/events?window=all"),
    ("policy.html", "open", "/policy"),
    ("overview-admin-all.html", "admin", "/?window=all"),
    ("events-admin-all.html", "admin", "/events?window=all"),
    ("policy-admin.html", "admin", "/policy"),
]

# The policy the policy tab renders, fixed so that edits to policy.yaml do
# not move a render.
POLICY_TEXT = """\
server:
  mode: observe
detectors:
  gitleaks:
    enabled: false
dashboard:
  auth:
    mode: none
"""


async def _get_typed(app, path: str) -> tuple[int, str, bytes]:
    """Status, content type and body. `_get` drops the headers."""
    path, _, query = path.partition("?")
    scope = {"type": "http", "method": "GET", "path": path,
             "query_string": query.encode("latin-1"), "headers": []}
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    ctype = dict(start.get("headers") or []).get(b"content-type", b"").decode("latin-1")
    return start["status"], ctype, b"".join(m.get("body", b"") for m in sent
                                            if m["type"] == "http.response.body")


@pytest.fixture
def fixed_policy(tmp_path, monkeypatch):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY_TEXT)
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(path))
    monkeypatch.setattr(dashboard_app, "POLICY_CACHE", dashboard_app._PolicyCache())


@pytest.fixture
def frozen_time(monkeypatch):
    """Admin form tokens carry `int(time.time())`."""
    monkeypatch.setattr(dashboard_app.time, "time", lambda: NOW.timestamp())


async def test_views_are_pinned(tmp_path, frozen):
    apps = {"open": _open(tmp_path / "open"), "entitled": _entitled(tmp_path / "ent"),
            "topology": _topology(tmp_path / "topo")}
    got: dict[str, dict] = {}
    bodies: dict[str, bytes] = {}
    for name, which, path in CASES:
        status, body = await _get(apps[which], path)
        assert status == 200, (name, status, body[:200])
        # The store's root is a tmp path and varies per run.
        body = body.replace(str(tmp_path).encode(), b"<tmp>")
        got[name] = _digest(body)
        bodies[name] = body

    if os.environ.get("FORGD_REGEN_GOLDEN") == "1":
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_text(json.dumps(got, indent=2, sort_keys=True) + "\n")
        pytest.skip("golden digests rewritten")

    want = json.loads(GOLDEN.read_text())
    assert set(want) == {c[0] for c in CASES}
    changed = [n for n in want if want[n] != got[n]]
    for n in changed:
        (tmp_path / f"{n}.actual").write_bytes(bodies[n])
    assert not changed, f"changed: {changed}; actual bodies in {tmp_path}"


async def test_the_seed_exercises_every_filter(tmp_path, frozen):
    """Every filter narrows the seeded data, so a filter that stopped
    working changes an answer rather than matching a digest by accident."""
    apps = {"open": _open(tmp_path / "open"), "entitled": _entitled(tmp_path / "ent"),
            "topology": _topology(tmp_path / "topo")}

    async def summary(which, query):
        return json.loads((await _get(apps[which], f"/api/summary?{query}"))[1])

    async def rows(which, query):
        return (await _get(apps[which], f"/events?{query}"))[1].count(b'<tr><td class="ts">')

    totals = [(await summary("open", f"window={w}"))["total_requests"]
              for w in ("24h", "7d", "30d", "all")]
    assert totals == sorted(totals) and len(set(totals)) == 4, totals
    assert (await summary("entitled", "window=all"))["total_requests"] \
        < totals[-1]
    everything = await rows("open", "window=all")
    counts = [await rows(w, q) for w, q in (
        ("open", "window=24h"), ("open", "window=7d"), ("open", "window=30d"),
        ("open", "window=all&source=inference_hook"),
        ("open", "window=all&source=compliance_scan"),
        ("open", "window=all&source=code_hook"),
        ("open", "window=all&action=deny"),
        ("entitled", "window=all"),
    )]
    assert all(0 < c < everything for c in counts), (everything, counts)
    assert await rows("entitled", f"window=all&org={ORG_A}&action=deny") \
        < await rows("entitled", f"window=all&org={ORG_A}")
