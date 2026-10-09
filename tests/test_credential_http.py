"""A request that carries a credential follows no redirect, puts upstream
ids in its path percent-encoded, and goes over https:// or to loopback."""

from __future__ import annotations

import ast
import json
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from forgd_verdict.compliance.client import ComplianceClient, ComplianceError
from forgd_verdict.managed.client import ManagedAgentsClient
from forgd_verdict.safehttp import scheme_refusal, segment

KEY = "sk-ant-api01-SYNTHETIC-not-a-key"
SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "forgd_verdict"


class Server:
    """A loopback HTTP server recording each request's raw path and headers.
    `routes` maps a path to (status, body, headers)."""

    def __init__(self):
        self.requests: list[tuple[str, dict[str, str]]] = []
        self.routes: dict[str, tuple[int, bytes, dict[str, str]]] = {}
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                server.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
                status, body, headers = server.routes.get(
                    self.path.split("?")[0], (200, b'{"data": [], "next_page": null}', {}))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, args=(0.05,), daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def servers():
    api, other = Server(), Server()
    yield api, other
    api.close()
    other.close()


@pytest.mark.parametrize("client_class", [ComplianceClient, ManagedAgentsClient])
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_refused_and_the_key_never_reaches_its_target(
        servers, client_class, status):
    api, other = servers
    api.routes["/v1/compliance/activities"] = (
        status, b"", {"Location": f"{other.base}/steal"})
    client = client_class(api_key=KEY, base_url=api.base, per_minute=10**9, max_retries=0)
    with pytest.raises(ComplianceError) as exc:
        client.get("/v1/compliance/activities")
    assert exc.value.status == status
    assert other.requests == []
    assert KEY not in str(exc.value)


def test_upstream_ids_are_one_encoded_path_segment(servers):
    api, _ = servers
    client = ComplianceClient(api_key=KEY, base_url=api.base, per_minute=10**9, max_retries=0)
    crafted = "../../../v1/organizations/me?probe=1#x"
    list(client.session_messages(crafted, "local", limit=5))
    path = api.requests[-1][0]
    assert path.startswith("/v1/compliance/apps/sessions/local/"
                           "..%2F..%2F..%2Fv1%2Forganizations%2Fme%3Fprobe%3D1%23x/messages?")
    api.routes["/v1/compliance/apps/chats/a%2Fb/messages"] = (200, b'{"chat_messages": []}', {})
    assert client.chat_messages("a/b") == {"chat_messages": []}
    client.artifact_content("v 1/..")
    assert api.requests[-1][0] == "/v1/compliance/apps/artifacts/v%201%2F../content"
    managed = ManagedAgentsClient(api_key=KEY, base_url=api.base, per_minute=10**9,
                                  max_retries=0)
    list(managed.session_events("s/../x"))
    assert api.requests[-1][0].startswith("/v1/sessions/s%2F..%2Fx/events?")


@pytest.mark.parametrize("bad", ["", ".", ".."])
def test_an_id_that_cannot_be_a_segment_is_an_unreadable_item(servers, bad):
    api, _ = servers
    client = ComplianceClient(api_key=KEY, base_url=api.base, per_minute=10**9, max_retries=0)
    with pytest.raises(ComplianceError) as exc:
        client.chat_messages(bad)
    assert exc.value.status == 400
    assert api.requests == []


@pytest.mark.parametrize("url", [
    "http://api.anthropic.com", "http://10.0.0.5:8080", "ftp://api.anthropic.com",
    "https://user:pw@api.anthropic.com", "api.anthropic.com", "https://",
])
@pytest.mark.parametrize("client_class", [ComplianceClient, ManagedAgentsClient])
def test_a_base_url_the_key_must_not_go_to_is_refused(url, client_class):
    with pytest.raises(ValueError, match="refused") as exc:
        client_class(api_key=KEY, base_url=url)
    assert "pw" not in str(exc.value)


@pytest.mark.parametrize("url", ["https://api.anthropic.com", "http://127.0.0.1:9",
                                 "http://localhost:9", "http://[::1]:9"])
def test_https_and_loopback_base_urls_are_accepted(url):
    assert scheme_refusal(url) is None
    ComplianceClient(api_key=KEY, base_url=url)


def test_a_base_url_off_the_anthropic_api_is_logged_by_host(caplog):
    ComplianceClient(api_key=KEY, base_url="https://compliance-proxy.example/base")
    lines = [r for r in caplog.records if "not the Anthropic API" in r.getMessage()]
    assert lines and lines[0].fields["host"] == "compliance-proxy.example/base"


def test_the_scanner_refuses_an_http_base_url_from_the_policy(tmp_path):
    from conftest import make_policy

    from forgd_verdict.compliance.scanner import ComplianceScanner

    policy = make_policy(compliance={"base_url": "http://api.anthropic.com",
                                     "api_key": "sk-ant-api01-x",
                                     "state_path": str(tmp_path / "s.json")})
    with pytest.raises(ValueError, match="https://"):
        ComplianceScanner(policy)


def test_segment_keeps_every_character_inside_the_segment():
    for raw in ("a/b", "a?b", "a#b", "a%2Fb", "a b", "..x", "é"):
        assert "/" not in segment(raw) and "?" not in segment(raw) and "#" not in segment(raw)


def test_the_arm_fetch_stays_on_the_arm_host(monkeypatch):
    from forgd_verdict.lockout_evidence import azure

    with pytest.raises(ValueError):
        azure._get("https://management.azure.com@evil.example/x", "t")  # noqa: SLF001
    with pytest.raises(ValueError):
        azure._get("https://evil.example/subscriptions/x", "t")  # noqa: SLF001


def test_the_proxied_sink_transport_refuses_a_redirect(servers, monkeypatch):
    from forgd_verdict.sink.transport import HttpTransport

    api, other = servers
    monkeypatch.setenv("http_proxy", api.base)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    transport = HttpTransport("http://sink.example/v1/logs", 5.0)
    assert transport.proxied
    from forgd_verdict.safehttp import RefuseRedirect

    assert any(isinstance(h, RefuseRedirect) for h in transport._opener.handlers)  # noqa: SLF001


# -- standing: every outbound HTTP call site is a known one --------------------

# Modules that open URLs, each with why it may: the shared credential
# opener, the hook's own refusing opener, and the dashboard's key fetches,
# which carry no credential and go to fixed https hosts or the operator's
# JWKS URL.
_ALLOWED = {
    "safehttp.py": "the credential opener",
    "hook/endpoint.py": "refuses redirects and http:// itself",
    "dashboard/auth.py": "signing-key fetches carry no credential",
}
_OPENERS = {"urlopen", "build_opener", "HTTPRedirectHandler"}


def _calls(path: pathlib.Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Attribute) and node.attr in _OPENERS:
            found.add(node.attr)
        elif isinstance(node, ast.Name) and node.id in _OPENERS:
            found.add(node.id)
        elif isinstance(node, ast.ImportFrom):
            found |= {a.name for a in node.names if a.name in _OPENERS}
    return found


def test_no_module_opens_urls_except_through_a_known_opener():
    offenders = {}
    for path in SRC.rglob("*.py"):
        rel = path.relative_to(SRC).as_posix()
        if rel in _ALLOWED or rel.startswith("testing/"):
            continue
        calls = _calls(path)
        if calls:
            offenders[rel] = sorted(calls)
    assert offenders == {}, (
        "open credentialed URLs with forgd_verdict.safehttp.credential_opener, which "
        f"follows no redirect: {json.dumps(offenders)}")
