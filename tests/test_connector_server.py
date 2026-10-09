"""The connector's HTTP surface: metadata, the 401 challenge, and who gets in.

Tokens are signed here with a key generated per module, and the JWKS client
is given that key's JWKS instead of fetching one. Nothing touches the
network.
"""

from __future__ import annotations

import json
import time

import pytest

pytest.importorskip("mcp", reason="needs forgd-verdict[connector]")
jwt = pytest.importorskip("jwt", reason="needs forgd-verdict[connector]")

import yaml  # noqa: E402
from conftest import CONNECTOR_JWKS_URL as JWKS_URL  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from forgd_verdict.connector import __main__ as entry  # noqa: E402
from forgd_verdict.connector import config  # noqa: E402
from forgd_verdict.connector.app import create_app as _create_app  # noqa: E402
from forgd_verdict.connector.tools import TOOL_NAMES, Reader  # noqa: E402
from forgd_verdict.policy import load_policy  # noqa: E402

ISSUER = "https://login.example.com/tenant/v2.0"
OTHER_ISSUER = "https://okta.example.com/oauth2/default"
RESOURCE = "https://connector.example.com/mcp"
API_CLIENT = "11111111-2222-4333-8444-555555555555"
SCOPE_FULL = f"{RESOURCE}/findings.read"
PRM_URL = "https://connector.example.com/.well-known/oauth-protected-resource/mcp"
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-11-25", "capabilities": {},
    "clientInfo": {"name": "test", "version": "1"}}}


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _token(key, kid="k1", **over):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": API_CLIENT, "sub": "user-1",
              "preferred_username": "dana@example.com", "azp": "claude-client",
              "scp": "findings.read", "exp": now + 600, "iat": now - 10}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, _pem(key), algorithm="RS256", headers={"kid": kid})


def create_app(cfg):
    from forgd_verdict.store import LocalFileStore

    return _create_app(cfg, Reader(store=LocalFileStore(cfg._store_root, instance="t"),
                                   auth=cfg.auth, entitlements=cfg.entitlements))


def _cfg(tmp_path, **over):
    block = {"enabled": True, "resource": RESOURCE, "scopes": [SCOPE_FULL],
             "required_scope": "findings.read",
             "auth": {"mode": "oidc_jwt", "issuer": ISSUER, "jwks_url": JWKS_URL,
                      "audience": [RESOURCE, API_CLIENT]}}
    block.update(over)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"connector": block}))
    cfg = config.load(load_policy(path))
    cfg._store_root = tmp_path / "store"
    return cfg


async def _call(app, method, path, body=None, headers=None):
    """(status, headers, body) from one ASGI request."""
    raw = json.dumps(body).encode() if body is not None else b""
    hdrs = {"content-type": "application/json",
            "accept": "application/json, text/event-stream", **(headers or {})}
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
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message):
        sent.append(message)

    async with app.running():
        await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    out_headers = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], out_headers, payload


def _bearer(token):
    return {"authorization": f"Bearer {token}"}


def _assert_challenge(status, headers, body, presented=True):
    assert status == 401, (status, body)
    assert "location" not in headers
    challenge = headers["www-authenticate"]
    assert challenge.startswith(f'Bearer resource_metadata="{PRM_URL}"'), challenge
    assert f'scope="{SCOPE_FULL}"' in challenge
    assert ('error="invalid_token"' in challenge) == presented
    # The reason is logged, never returned.
    assert json.loads(body) == {"error": "unauthorized"}


# --- open routes -----------------------------------------------------------

async def test_the_protected_resource_metadata(tmp_path):
    status, headers, body = await _call(create_app(_cfg(tmp_path)), "GET",
                                        "/.well-known/oauth-protected-resource/mcp")
    assert status == 200
    assert json.loads(body) == {
        "resource": RESOURCE, "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"], "scopes_supported": [SCOPE_FULL]}


async def test_the_first_issuer_is_listed_first(tmp_path):
    auth = {"mode": "oidc_jwt", "issuers": [
        {"issuer": OTHER_ISSUER, "jwks_url": JWKS_URL, "audience": RESOURCE},
        {"issuer": ISSUER, "jwks_url": JWKS_URL, "audience": RESOURCE}]}
    app = create_app(_cfg(tmp_path, auth=auth))
    _s, _h, body = await _call(app, "GET", "/.well-known/oauth-protected-resource/mcp")
    assert json.loads(body)["authorization_servers"] == [OTHER_ISSUER, ISSUER]


async def test_healthz_is_open(tmp_path):
    status, _h, body = await _call(create_app(_cfg(tmp_path)), "GET", "/healthz")
    assert status == 200 and json.loads(body)["status"] == "ok"


@pytest.mark.parametrize("path", ["/", "/mcp/", "/MCP", "/.well-known/oauth-protected-resource",
                                  "/api/summary"])
async def test_every_other_path_is_a_404_not_a_redirect(tmp_path, path):
    status, headers, _b = await _call(create_app(_cfg(tmp_path)), "POST", path, INITIALIZE)
    assert status == 404 and "location" not in headers


# --- the challenge ----------------------------------------------------------

async def test_no_token_is_a_401_with_the_challenge(tmp_path):
    status, headers, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp",
                                        INITIALIZE)
    _assert_challenge(status, headers, body, presented=False)


async def test_a_get_without_a_token_is_a_401_too(tmp_path):
    status, headers, body = await _call(create_app(_cfg(tmp_path)), "GET", "/mcp")
    _assert_challenge(status, headers, body, presented=False)


@pytest.mark.parametrize("case", [
    "wrong-audience", "wrong-issuer", "expired", "unknown-kid", "wrong-key", "no-exp",
    "string-exp", "infinite-exp", "nan-exp",
])
async def test_a_bad_token_is_a_401(tmp_path, jwks, signing_key, case):
    key = signing_key
    over: dict = {}
    kid = "k1"
    if case == "wrong-audience":
        over["aud"] = "https://other.example.com/mcp"
    elif case == "wrong-issuer":
        over["iss"] = OTHER_ISSUER
    elif case == "expired":
        over["exp"] = int(time.time()) - 60
    elif case == "unknown-kid":
        kid = "k2"
    elif case == "wrong-key":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif case == "no-exp":
        over["exp"] = None
    elif case == "string-exp":
        over["exp"] = str(int(time.time()) + 600)
    elif case == "infinite-exp":
        over["exp"] = float("inf")
    elif case == "nan-exp":
        over["exp"] = float("nan")
    status, headers, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp",
                                        INITIALIZE, _bearer(_token(key, kid, **over)))
    _assert_challenge(status, headers, body)


async def test_the_reason_is_logged_and_not_returned(tmp_path, jwks, signing_key, caplog):
    token = _token(signing_key, exp=int(time.time()) - 60)
    with caplog.at_level("INFO", logger="forgd_verdict.connector"):
        _s, _h, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp",
                                   INITIALIZE, _bearer(token))
    reasons = [getattr(r, "fields", {}).get("reason") for r in caplog.records]
    assert "token rejected: ExpiredSignatureError" in reasons
    assert b"Expired" not in body


@pytest.mark.parametrize(("exp", "reason"), [
    # The authenticator refuses a time claim past year 9999 before the
    # connector reads exp itself.
    (10**400, "token rejected: time claim"),
    # PyJWT compares the int with the clock and refuses it first.
    (-10**400, "token rejected: ExpiredSignatureError"),
], ids=["above", "below"])
async def test_an_exp_outside_the_float_range_is_a_401(tmp_path, jwks, signing_key, caplog,
                                                       exp, reason):
    token = _token(signing_key, exp=exp)
    with caplog.at_level("INFO", logger="forgd_verdict.connector"):
        status, _h, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp",
                                       INITIALIZE, _bearer(token))
    reasons = [getattr(r, "fields", {}).get("reason") for r in caplog.records]
    assert status == 401, body
    assert reason in reasons


@pytest.mark.parametrize("value", [
    "Bearer " + "sk-org-wide-0123456789abcdef", "sk-org-wide-0123456789abcdef",
    "Basic " + "dXNlcjpwYXNz", "Bearer ", "Bearer a.b.c",
])
async def test_an_opaque_or_static_credential_is_a_401(tmp_path, jwks, value):
    status, headers, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp",
                                        INITIALIZE, {"authorization": value})
    _assert_challenge(status, headers, body)


@pytest.mark.parametrize("scp", [None, "findings.write profile", "findings.read.all"])
async def test_a_valid_token_without_the_scope_is_a_403(tmp_path, jwks, signing_key, scp):
    status, headers, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp",
                                        INITIALIZE, _bearer(_token(signing_key, scp=scp)))
    assert status == 403, (status, body)
    assert "location" not in headers
    assert headers["www-authenticate"] == (
        f'Bearer error="insufficient_scope", scope="{SCOPE_FULL}", '
        f'resource_metadata="{PRM_URL}"')
    assert json.loads(body) == {"error": "insufficient_scope"}


async def test_the_scope_claim_is_also_read_as_rfc_9068_scope(tmp_path, jwks, signing_key):
    token = _token(signing_key, scp=None, scope="openid findings.read")
    status, _h, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp",
                                   INITIALIZE, _bearer(token))
    assert status == 200, body


def test_an_empty_required_scope_refuses_to_start(tmp_path):
    """Without it an ID token, or a dashboard token from the same app
    registration, would be accepted wherever the audience matches."""
    with pytest.raises(ValueError, match="connector.required_scope is empty"):
        _cfg(tmp_path, required_scope="")


async def test_a_token_with_no_scope_claim_is_refused(tmp_path, jwks, signing_key):
    status, _h, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp", INITIALIZE,
                                   _bearer(_token(signing_key, scp=None)))
    assert status == 403, body


# --- origin -----------------------------------------------------------------

@pytest.mark.parametrize("origin", ["https://evil.example.com", "https://claude.ai.evil.com",
                                    "http://claude.ai", "null"])
async def test_a_foreign_origin_is_refused_even_with_a_valid_token(
        tmp_path, jwks, signing_key, origin):
    status, headers, body = await _call(
        create_app(_cfg(tmp_path)), "POST", "/mcp", INITIALIZE,
        {**_bearer(_token(signing_key)), "origin": origin})
    assert status == 403 and json.loads(body) == {"error": "origin_not_allowed"}
    assert "location" not in headers


async def test_an_allowed_origin_passes(tmp_path, jwks, signing_key):
    status, _h, body = await _call(
        create_app(_cfg(tmp_path)), "POST", "/mcp", INITIALIZE,
        {**_bearer(_token(signing_key)), "origin": "https://claude.ai"})
    assert status == 200, body


# --- in ---------------------------------------------------------------------

async def test_a_valid_token_initializes(tmp_path, jwks, signing_key):
    status, headers, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp",
                                        INITIALIZE, _bearer(_token(signing_key)))
    assert status == 200, body
    assert headers["content-type"].startswith("application/json")
    result = json.loads(body)["result"]
    assert result["serverInfo"]["name"] == "forgd-verdict findings"


async def test_a_valid_token_lists_the_six_read_only_tools(tmp_path, jwks, signing_key):
    request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    status, _h, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp", request,
                                   {**_bearer(_token(signing_key)),
                                    "mcp-protocol-version": "2025-11-25"})
    assert status == 200, body
    tools = json.loads(body)["result"]["tools"]
    assert sorted(t["name"] for t in tools) == sorted(TOOL_NAMES)
    for t in tools:
        assert t["annotations"]["readOnlyHint"] is True, t
        assert t["annotations"]["destructiveHint"] is False, t


async def test_the_resource_is_accepted_as_an_audience(tmp_path, jwks, signing_key):
    status, _h, body = await _call(create_app(_cfg(tmp_path)), "POST", "/mcp", INITIALIZE,
                                   _bearer(_token(signing_key, aud=RESOURCE)))
    assert status == 200, body


# --- refusing to start --------------------------------------------------------

@pytest.fixture
def no_serve(monkeypatch):
    import uvicorn

    def refuse(*_a, **_k):
        raise AssertionError("uvicorn.run was called")

    monkeypatch.setattr(uvicorn, "run", refuse)


@pytest.mark.parametrize("policy,expect", [
    ({}, "connector.enabled is not true"),
    ({"connector": {"enabled": False, "resource": RESOURCE}}, "connector.enabled is not true"),
    ({"connector": {"enabled": True, "resource": RESOURCE}}, "connector.auth is not set"),
    ({"connector": {"enabled": True, "resource": "http://connector.example.com/mcp",
                    "auth": {"mode": "oidc_jwt", "issuer": ISSUER, "jwks_url": JWKS_URL,
                             "audience": RESOURCE}}}, "scheme must be https"),
    ({"connector": {"enabled": True, "resource": RESOURCE,
                    "auth": {"mode": "trusted_header"}}}, "must be 'oidc_jwt'"),
])
def test_main_refuses_to_start(tmp_path, capsys, no_serve, policy, expect):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy))
    assert entry.main(["--policy", str(path)]) == 2
    lines = capsys.readouterr().err.strip().splitlines()
    assert len(lines) == 1, lines
    assert lines[0].startswith("refusing to start the connector:") and expect in lines[0]


def test_main_refuses_without_a_store(tmp_path, capsys, no_serve, monkeypatch):
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"connector": {
        "enabled": True, "resource": RESOURCE, "required_scope": "findings.read",
        "auth": {"mode": "oidc_jwt", "issuer": ISSUER, "jwks_url": JWKS_URL,
                 "audience": RESOURCE}}}))
    assert entry.main(["--policy", str(path)]) == 2
    assert "no findings store" in capsys.readouterr().err


def test_main_refuses_without_a_policy_file(tmp_path, capsys, monkeypatch, no_serve):
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)
    assert entry.main([]) == 2
    assert "connector.enabled is not true" in capsys.readouterr().err


def test_main_refuses_a_named_policy_file_that_is_missing(tmp_path, capsys, no_serve):
    missing = tmp_path / "absent.yaml"
    assert entry.main(["--policy", str(missing)]) == 2
    err = capsys.readouterr().err
    assert str(missing) in err and "--policy" in err


def test_main_serves_a_valid_config(tmp_path, monkeypatch):
    import uvicorn

    served = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: served.update(app=app, **kw))
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"connector": {
        "enabled": True, "resource": RESOURCE, "required_scope": "findings.read",
        "auth": {"mode": "oidc_jwt", "issuer": ISSUER, "jwks_url": JWKS_URL,
                 "audience": RESOURCE}}}))
    assert entry.main(["--policy", str(path), "--port", "9000",
                       "--store", str(tmp_path / "store")]) == 0
    assert served["port"] == 9000 and served["app"].cfg.resource == RESOURCE
