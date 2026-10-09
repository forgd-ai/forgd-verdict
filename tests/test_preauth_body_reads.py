"""Every place a service under src/forgd_verdict reads a request body, and
what stands between an unauthenticated caller and that read.

A body read is a `receive()` call, a call to anything named `_read_body`,
or `receive` handed to a callable the module does not define (a framework's
handler). Each one found is listed in SITES with what makes it safe:

  lifespan  the ASGI lifespan loop; no request body
  helper    the read itself, called only from a classified site
  auth      the route authenticates the caller before it reads
  budget    the route reads before it can authenticate, under a byte budget

`auth` and `budget` sites each have a probe in PROBES that drives the real
app without a credential and checks the body is not read, or is refused
unread once the budget is full. A new read anywhere fails
`test_every_body_read_is_classified` until it is listed here with a probe.
"""

from __future__ import annotations

import ast
import json
import time
from collections import Counter
from pathlib import Path

import pytest
from conftest import WHSEC, make_policy

SRC = Path(__file__).resolve().parent.parent / "src" / "forgd_verdict"

LIFESPAN, HELPER, AUTH, BUDGET = "lifespan", "helper", "auth", "budget"

# (module, enclosing function, kind of read) -> (count, classification)
SITES: dict[tuple[str, str, str], tuple[int, str]] = {
    ("connector/app.py", "ConnectorApp.__call__", "receive->self.inner"): (1, LIFESPAN),
    ("connector/app.py", "ConnectorApp.__call__", "receive->self.handler"): (1, AUTH),
    ("dashboard/app.py", "Dashboard.__call__", "receive()"): (1, LIFESPAN),
    ("dashboard/app.py", "Dashboard._admin_post", "_read_body"): (1, AUTH),
    ("dashboard/app.py", "_read_body", "receive()"): (1, HELPER),
    ("intake/app.py", "Intake._lifespan", "receive()"): (1, LIFESPAN),
    ("intake/app.py", "Intake._accept", "_read_body"): (1, AUTH),
    ("intake/app.py", "Intake._scan", "_read_body"): (1, AUTH),
    ("intake/app.py", "_read_body", "receive()"): (1, HELPER),
    ("otel/app.py", "Collector._lifespan", "receive()"): (1, LIFESPAN),
    ("otel/app.py", "Collector._read_body", "_read_body"): (1, HELPER),
    ("otel/app.py", "Collector._read_export", "_read_body"): (1, AUTH),
    ("otel/app.py", "Collector._read_metrics", "_read_body"): (1, AUTH),
    ("otel/app.py", "_read_body", "receive()"): (1, HELPER),
    ("server/app.py", "VerdictServer._lifespan", "receive()"): (1, LIFESPAN),
    ("server/app.py", "VerdictServer._receive_verified", "_read_body"): (1, BUDGET),
    ("server/app.py", "_read_body", "receive()"): (1, HELPER),
}


def _body_reads() -> Counter:
    found: Counter = Counter()
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        defined = {n.name for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        module = path.relative_to(SRC).as_posix()

        def visit(node: ast.AST, stack: list[str], module=module, defined=defined) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    visit(child, [*stack, child.name])
                    continue
                if isinstance(child, ast.Call):
                    func = child.func
                    name = (func.id if isinstance(func, ast.Name)
                            else func.attr if isinstance(func, ast.Attribute) else None)
                    args = [*child.args, *(k.value for k in child.keywords)]
                    passes_receive = any(isinstance(a, ast.Name) and a.id == "receive"
                                         for a in args)
                    where = ".".join(stack)
                    if name == "receive" and not args:
                        found[(module, where, "receive()")] += 1
                    elif name == "_read_body":
                        found[(module, where, "_read_body")] += 1
                    elif passes_receive and name not in defined:
                        found[(module, where, f"receive->{ast.unparse(func)}")] += 1
                visit(child, stack)

        visit(tree, [])
    return found


def test_every_body_read_is_classified():
    found = _body_reads()
    expected = Counter({site: count for site, (count, _) in SITES.items()})
    assert found == expected, (
        "a request body is read somewhere SITES does not list, or no longer "
        "where it does. A route that reads before it authenticates needs a "
        "bounded pre-auth budget; list the site and add a probe.\n"
        f"unlisted: {sorted(found - expected)}\nmissing: {sorted(expected - found)}")


def test_every_auth_and_budget_site_has_a_probe():
    needing = {site for site, (_, kind) in SITES.items() if kind in (AUTH, BUDGET)}
    assert set(PROBES) == needing


# -- probes ---------------------------------------------------------------------


class _CountingReceive:
    """An ASGI `receive` that counts the body messages it hands out."""

    def __init__(self, body: bytes = b'{"x": 1}'):
        self.body = body
        self.reads = 0

    async def __call__(self) -> dict:
        self.reads += 1
        return {"type": "http.request", "body": self.body, "more_body": False}


async def _drive(app, method: str, path: str, headers: dict[str, str]) -> tuple[int, int]:
    """(status, body reads) for one request without a credential."""
    receive = _CountingReceive()
    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": path, "query_string": b"",
             "headers": [(k.encode("latin-1"), v.encode("latin-1"))
                         for k, v in headers.items()]}
    await app(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status, receive.reads


async def _verdict_server(tmp_path, monkeypatch) -> None:
    from forgd_verdict.server.app import VerdictServer

    server = VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None,
                "max_body_bytes": 1024, "preauth_body_budget_bytes": 1024}))
    forged = {"webhook-id": "msg_forged", "webhook-timestamp": str(int(time.time())),
              "webhook-signature": "v1,AAAA", "content-type": "application/json"}
    status, reads = await _drive(server, "POST", "/hook", forged)
    assert (status, reads) == (401, 1)
    assert server.preauth.peak <= server.preauth.limit
    held = server.preauth.hold()
    assert held.take(server.preauth.limit)
    status, reads = await _drive(server, "POST", "/hook", forged)
    assert (status, reads) == (503, 0)
    held.release()
    assert server.preauth.in_use == 0


def _intake(tmp_path):
    from forgd_verdict.intake.app import Intake
    from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
    from forgd_verdict.store import LocalFileStore

    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "laptop", "token": "intake-token-0123456789abcdef"}]},
        "privacy": {"hash_salt": "s"}}))
    return Intake(policy, store=LocalFileStore(tmp_path, instance="t"))


async def _intake_accept(tmp_path, monkeypatch) -> None:
    app = _intake(tmp_path)
    try:
        assert await _drive(app, "POST", "/intake", {}) == (401, 0)
        assert await _drive(app, "POST", "/intake",
                            {"authorization": "Bearer " + "wrong-token-0123456789abc"}) == (401, 0)
    finally:
        app.close()


async def _intake_scan(tmp_path, monkeypatch) -> None:
    app = _intake(tmp_path)
    try:
        assert await _drive(app, "POST", "/scan", {}) == (401, 0)
    finally:
        app.close()


def _collector(tmp_path, monkeypatch):
    from forgd_verdict.otel.app import Collector
    from forgd_verdict.policy import Policy, load_policy

    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    raw = json.loads(json.dumps(load_policy(str(SRC.parent.parent / "policy.yaml")).raw,
                                default=str))
    raw["otel"].update({"orgs": [{"id": "org-probe", "label": "primary",
                                  "token": "otel-token-0123456789abcdef"}]})
    return Collector(Policy(raw=raw), store=None)


async def _collector_logs(tmp_path, monkeypatch) -> None:
    app = _collector(tmp_path, monkeypatch)
    try:
        status, reads = await _drive(app, "POST", "/v1/logs",
                                     {"content-type": "application/json"})
        assert (status, reads) == (401, 0)
    finally:
        app.close()


async def _collector_metrics(tmp_path, monkeypatch) -> None:
    app = _collector(tmp_path, monkeypatch)
    try:
        status, reads = await _drive(app, "POST", "/v1/metrics",
                                     {"content-type": "application/json"})
        assert (status, reads) == (401, 0)
    finally:
        app.close()


async def _dashboard_admin(tmp_path, monkeypatch) -> None:
    pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")
    from forgd_verdict.dashboard.admin import PATH_ACTIONS, AdminConfig
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.dashboard.auth import AuthConfig
    from forgd_verdict.entitlements import MODE_OIDC_JWT
    from forgd_verdict.overrides import KEY_MODE, RuntimeOverrides
    from forgd_verdict.store import LocalFileStore

    origin = "https://dash.example.com"
    auth = AuthConfig.parse({"mode": MODE_OIDC_JWT, "header": "authorization",
                             "jwks_url": "https://example.invalid/keys",
                             "issuer": "https://login.example/v2.0",
                             "audience": "api://forgd-dashboard"})
    admins = AdminConfig.parse({"groups": [{"group": "forgd-operators"}],
                                "allowed_origins": [origin], "form_key": "k" * 40}, auth)
    store = LocalFileStore(tmp_path / "s", instance="t")
    overrides = RuntimeOverrides(store, "dashboard", baseline={KEY_MODE: "observe"})
    overrides.refresh()
    app = Dashboard(store, auth=auth, admins=admins, overrides=overrides,
                    baseline_mode="observe")
    headers = {"content-type": "application/x-www-form-urlencoded", "origin": origin,
               "sec-fetch-site": "same-origin"}
    assert await _drive(app, "POST", PATH_ACTIONS, headers) == (401, 0)


async def _connector(tmp_path, monkeypatch) -> None:
    pytest.importorskip("mcp", reason="needs forgd-verdict[connector]")
    import yaml

    from forgd_verdict.connector import config
    from forgd_verdict.connector.app import MCP_PATH, create_app
    from forgd_verdict.connector.tools import Reader
    from forgd_verdict.policy import load_policy
    from forgd_verdict.store import LocalFileStore

    resource = "https://connector.example.com/mcp"
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"connector": {
        "enabled": True, "resource": resource, "scopes": [f"{resource}/findings.read"],
        "required_scope": "findings.read",
        "auth": {"mode": "oidc_jwt", "issuer": "https://login.example.com/tenant/v2.0",
                 "jwks_url": "https://login.example.com/tenant/discovery/v2.0/keys",
                 "audience": [resource]}}}))
    cfg = config.load(load_policy(path))
    app = create_app(cfg, Reader(store=LocalFileStore(tmp_path / "store", instance="t"),
                                 auth=cfg.auth, entitlements=cfg.entitlements))
    headers = {"content-type": "application/json", "accept": "application/json"}
    assert await _drive(app, "POST", MCP_PATH, headers) == (401, 0)


PROBES = {
    ("connector/app.py", "ConnectorApp.__call__", "receive->self.handler"): _connector,
    ("dashboard/app.py", "Dashboard._admin_post", "_read_body"): _dashboard_admin,
    ("intake/app.py", "Intake._accept", "_read_body"): _intake_accept,
    ("intake/app.py", "Intake._scan", "_read_body"): _intake_scan,
    ("otel/app.py", "Collector._read_export", "_read_body"): _collector_logs,
    ("otel/app.py", "Collector._read_metrics", "_read_body"): _collector_metrics,
    ("server/app.py", "VerdictServer._receive_verified", "_read_body"): _verdict_server,
}


@pytest.mark.parametrize("site", sorted(PROBES), ids=lambda s: f"{s[0]}:{s[1]}")
async def test_no_body_is_read_for_an_unauthenticated_caller_past_its_bound(
        site, tmp_path, monkeypatch, control_identity):
    await PROBES[site](tmp_path, monkeypatch)
