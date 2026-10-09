"""Deeply nested JSON sent to every HTTP route of every ASGI app is never
answered with a 5xx and never escapes the app.

`json.loads` raises RecursionError, not ValueError, past the interpreter's
recursion limit, and a handler catching only ValueError answered 500 --
which an OTLP exporter and Anthropic both retry. JSON just under the limit
parses, and is then walked by code that may itself recurse.

Bodies, the ndjson lines of /intake, a dashboard cursor and the JSON halves
of a bearer token or platform assertion are each sent nested. The routes of
each app are the path literals in its module, so a route added later is
covered.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from pathlib import Path

import pytest
from conftest import WHSEC, ASGIClient, frame, make_policy, sign

# Megabyte bodies to every route of five apps: CPU-bound, run alone.
pytestmark = pytest.mark.serial

SRC = Path(__file__).resolve().parent.parent / "src" / "forgd_verdict"
FAR = 200_000
# Parses on Python 3.12 and later, and is past the recursion limit of any
# Python code that walks it.
MID = 5_000
NEAR = 900


def _deep(n: int, leaf: str = "1") -> str:
    return '{"a":' * n + leaf + "}" * n


def _deep_list(n: int) -> str:
    return "[" * n + "]" * n


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _token(n: int) -> str:
    """A three-part bearer token whose header and claims are nested JSON."""
    return f"{_b64(_deep(n))}.{_b64(_deep_list(n))}.{_b64('x' * 64)}"


def _jwt_text() -> str:
    """A JSON string holding a JWT-shaped token whose header is nested past
    the recursion limit, which T0 decodes to check it is a JWT."""
    header = _b64(_deep(FAR))
    return json.dumps(f"see {header}.{_b64('{}')}abcdefgh.{'s' * 43} AKIAIOSFODNN7EXAMPLE")


def _routes(module: str, *extra: str) -> list[str]:
    text = (SRC / module).read_text()
    found = set(re.findall(r'"(/[A-Za-z0-9_./-]*)"', text)) | set(extra)
    return sorted(found | {f"{p}x" for p in found if p.endswith("/")})


def _bodies(*shaped: str) -> list[bytes]:
    """The bodies sent to every route: far past the recursion limit, just
    under it, and nested inside each JSON shape in `shaped`."""
    plain = [_deep(FAR), _deep_list(FAR), _deep(MID), _deep_list(MID), _deep(NEAR),
             _deep_list(NEAR)]
    nested = [s.replace("NESTED", n) for s in shaped
              for n in (_deep(FAR), _deep(MID), _deep_list(MID), _deep(NEAR),
                        _deep_list(NEAR), _jwt_text())]
    return [b.encode() for b in (*plain, *nested)]


def _assert_no_5xx(app, routes, bodies, headers, *, methods=("GET", "POST"),
                   queries=("",), sign_body=None):
    async def go():
        client = ASGIClient(app)
        bad = []
        for route in routes:
            for method in methods:
                for query in queries:
                    for body in (bodies if method == "POST" else [b""]):
                        h = dict(headers)
                        if sign_body is not None and method == "POST":
                            h.update(sign_body(body))
                        path = f"{route}?{query}" if query else route
                        try:
                            status, *_ = await client.request(method, path, body, h)
                        except Exception as exc:  # noqa: BLE001 - reported below
                            bad.append((method, path, len(body), type(exc).__name__))
                            continue
                        if status >= 500:
                            bad.append((method, path, len(body), status))
        return bad

    bad = asyncio.run(go())
    assert bad == [], bad[:10]


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    monkeypatch.delenv("FORGD_GITLEAKS_SOCKET", raising=False)


def test_the_verdict_server(tmp_path):
    from forgd_verdict.server.app import VerdictServer

    policy = make_policy(server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None,
                                 "on_internal_error": "allow"},
                         detectors={"gitleaks": {"enabled": False}})
    app = VerdictServer(policy)
    shaped = json.dumps(frame([{"role": "user", "content": "NESTED"}])).replace(
        '"NESTED"', "NESTED")
    tool = json.dumps(frame([{"role": "assistant", "content": [
        {"type": "tool_use", "id": "toolu_1", "name": "x", "input": "NESTED"}]}])).replace(
        '"NESTED"', "NESTED")
    try:
        _assert_no_5xx(app, _routes("server/app.py", "/hook"), _bodies(shaped, tool), {},
                       sign_body=sign)
    finally:
        app.close()


def test_the_collector(tmp_path):
    from test_otel_collector import auth
    from test_otel_collector import make_policy as otel_policy

    from forgd_verdict.otel.app import Collector
    from forgd_verdict.store.local import LocalFileStore

    app = Collector(otel_policy(), store=LocalFileStore(tmp_path / "f", instance="t"))
    record = ('{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":'
              '[{"key":"prompt","value":NESTED}],"body":NESTED}]}]}]}')
    array = ('{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":'
             '[{"key":"prompt","value":{"arrayValue":{"values":[NESTED]}}}]}]}]}]}')
    try:
        _assert_no_5xx(app, _routes("otel/app.py"), _bodies(record, array), auth())
    finally:
        app.close()


def test_the_intake(tmp_path):
    from test_intake import TOKEN, _policy

    from forgd_verdict.intake import app as intake_app
    from forgd_verdict.store import LocalFileStore

    app = intake_app.Intake(_policy(), store=LocalFileStore(tmp_path / "s", instance="t"))
    hook = '{"hook_event_name":"PreToolUse","tool_name":"x","tool_input":NESTED}'
    prompt = '{"hook_event_name":"UserPromptSubmit","prompt":NESTED}'
    frame_ = '{"type":"prompt","messages":[{"role":"user","content":NESTED}]}'
    lines = "\n".join(['{"source":"code_hook","observed_at":"2026-10-06T00:00:00Z"}',
                       "NESTED", '{"findings":[NESTED]}'])
    headers = {"authorization": f"Bearer {TOKEN}", "content-type": "application/json"}
    try:
        _assert_no_5xx(app, _routes("intake/app.py", "/intake", "/scan"),
                       _bodies(hook, prompt, frame_, lines), headers)
        _assert_no_5xx(app, ["/intake"], _bodies(lines),
                       {**headers, "content-type": "application/x-ndjson"},
                       methods=("POST",))
    finally:
        app.close()


def _dashboard_routes():
    from forgd_verdict.dashboard.admin import PATH_ACTIONS

    return _routes("dashboard/app.py", PATH_ACTIONS, "/assets/logo.png")


def _cursor_queries():
    return ("", f"before={_b64(_deep_list(1000))}", f"before={_b64(_deep(250))}",
            "org=" + "%5B" * 1000)


def test_the_dashboard_without_auth(tmp_path):
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.store import LocalFileStore

    app = Dashboard(LocalFileStore(tmp_path / "d", instance="t"))
    _assert_no_5xx(app, _dashboard_routes(), _bodies(), {}, queries=_cursor_queries())


@pytest.mark.parametrize("platform", ["", "alb_oidc", "iap"])
def test_the_dashboard_with_a_nested_token(tmp_path, platform):
    pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.dashboard.auth import AuthConfig
    from forgd_verdict.entitlements import MODE_OIDC_JWT
    from forgd_verdict.store import LocalFileStore

    raw = {"mode": MODE_OIDC_JWT, "issuer": "https://idp.example/", "audience": "dash",
           "jwks_url": "https://idp.example/keys"}
    if platform == "alb_oidc":
        raw["platform"] = platform
    if platform == "iap":
        raw = {"mode": MODE_OIDC_JWT, "platform": "iap",
               "audience": "/projects/123/global/backendServices/456"}
    if platform == "alb_oidc":
        raw["alb_arn"] = ("arn:aws:elasticloadbalancing:eu-west-1:123456789012:"
                          "loadbalancer/app/dash/0123456789abcdef")
    auth = AuthConfig.parse(raw)
    app = Dashboard(LocalFileStore(tmp_path / "d", instance="t"), auth=auth)
    for n in (FAR, MID, NEAR):
        token = _token(n)
        headers = {"authorization": f"Bearer {token}", "x-amzn-oidc-data": token,
                   "x-goog-iap-jwt-assertion": token, "cookie": f"session={token}"}
        _assert_no_5xx(app, _dashboard_routes(), [_deep(n).encode()], headers)


def test_the_connector(tmp_path, jwks, signing_key):
    pytest.importorskip("mcp", reason="needs forgd-verdict[connector]")
    from test_connector_server import _cfg, create_app
    from test_connector_server import _token as signed_token

    from forgd_verdict.connector.config import MCP_PATH

    routes = _routes("connector/app.py", MCP_PATH, "/.well-known/oauth-protected-resource/mcp")
    good = signed_token(signing_key)
    rpc = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
           '{"name":"find_findings","arguments":NESTED}}')
    bodies = _bodies(rpc)

    async def go():
        bad = []
        for route in routes:
            for method in ("GET", "POST"):
                for headers in ({"authorization": f"Bearer {good}"},
                                {"authorization": f"Bearer {_token_nested(FAR)}"},
                                {"authorization": f"Bearer {_token_nested(MID)}"},
                                {"authorization": f"Bearer {_token_nested(NEAR)}"}):
                    for body in (bodies if method == "POST" else [None]):
                        app = create_app(_cfg(tmp_path))
                        try:
                            status = await _raw_call(app, method, route, body, headers)
                        except Exception as exc:  # noqa: BLE001 - reported below
                            bad.append((method, route, type(exc).__name__))
                            continue
                        if status >= 500:
                            bad.append((method, route, status))
        return bad

    assert asyncio.run(go()) == []


def _token_nested(n: int) -> str:
    return _token(n)


async def _raw_call(app, method, path, raw, headers):
    """(status, headers, body) from one ASGI request to the connector, the
    way `test_connector_server._call` makes it, with a raw body."""
    hdrs = {"content-type": "application/json",
            "accept": "application/json, text/event-stream", **headers}
    scope = {"type": "http", "method": method, "path": path, "query_string": b"",
             "http_version": "1.1", "scheme": "https",
             "server": ("connector.example.com", 443), "client": ("203.0.113.9", 1),
             "root_path": "",
             "headers": [(k.encode(), v.encode()) for k, v in hdrs.items()]
             + [(b"host", b"connector.example.com")]}
    sent: list[dict] = []
    done = False

    async def receive():
        nonlocal done
        if done:
            return {"type": "http.disconnect"}
        done = True
        return {"type": "http.request", "body": raw or b"", "more_body": False}

    async def send(message):
        sent.append(message)

    async with app.running():
        await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"]
