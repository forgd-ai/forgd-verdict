"""Key fetches for dashboard token verification stay off the event loop and
are bounded: a stream of forged tokens with fresh kids neither stalls
/healthz nor ties up more than a fixed number of fetches and threads."""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import ASGIClient

from forgd_verdict.dashboard import app as dapp
from forgd_verdict.dashboard import auth as authmod
from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.dashboard.auth import AuthConfig, AuthError
from forgd_verdict.store import LocalFileStore

jwt = pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

pytestmark = pytest.mark.serial

ISSUER = "https://idp.example/"
ARN = ("arn:aws:elasticloadbalancing:us-east-1:123456789012:"
       "loadbalancer/app/dash/0123456789abcdef")
SLOW_S = 1.5


class _JWKS:
    """A JWKS endpoint that answers after `delay` seconds, counting fetches
    and the most it served at once."""

    def __init__(self, doc: dict, delay: float):
        self.doc, self.delay = doc, delay
        self.fetches = 0
        self.inflight = 0
        self.peak = 0
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                with outer.lock:
                    outer.fetches += 1
                    outer.inflight += 1
                    outer.peak = max(outer.peak, outer.inflight)
                try:
                    time.sleep(outer.delay)
                    body = json.dumps(outer.doc).encode()
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    with outer.lock:
                        outer.inflight -= 1

            def log_message(self, *a):
                pass

        from socketserver import ThreadingMixIn

        class Server(ThreadingMixIn, HTTPServer):
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/jwks"

    def close(self):
        self.server.shutdown()


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _jwks_doc(key, kid="real"):
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return {"keys": [dict(public, kid=kid, use="sig", alg="RS256")]}


def _signed(key, kid="real"):
    return jwt.encode({"iss": ISSUER, "aud": "dash", "sub": "u1",
                       "preferred_username": "dana@example.com",
                       "exp": int(time.time()) + 600, "iat": int(time.time()) - 5},
                      _pem(key), algorithm="RS256", headers={"kid": kid})


def _forged(kid):
    return jwt.encode({"iss": ISSUER, "aud": "dash", "exp": 2**31}, "x" * 32,
                      algorithm="HS256", headers={"kid": kid})


def _oidc(url):
    return AuthConfig.parse({"mode": "oidc_jwt", "issuer": ISSUER, "jwks_url": url,
                             "audience": "dash", "header": "authorization"})


async def _healthz_while(client, attack):
    """Start `attack`, then time /healthz while it runs."""
    t0 = time.monotonic()
    task = asyncio.create_task(attack)
    await asyncio.sleep(0.05)
    status, _ = await client.get("/healthz")
    waited = time.monotonic() - t0
    results = await task
    return status, waited, results


async def test_a_slow_jwks_fetch_does_not_block_healthz(tmp_path, rsa_key):
    server = _JWKS({"keys": []}, SLOW_S)
    try:
        client = ASGIClient(Dashboard(LocalFileStore(tmp_path / "f", instance="t"),
                                      auth=_oidc(server.url)))
        attack = client.get("/", {"authorization": f"Bearer {_forged('nope')}"})
        status, waited, (att_status, _) = await _healthz_while(client, attack)
    finally:
        server.close()
    assert status == 200 and att_status == 401
    assert waited < 0.6, f"/healthz waited {waited:.2f}s behind a key fetch"


async def test_concurrent_forged_kids_cost_one_fetch_and_never_stall_healthz(
        tmp_path, rsa_key):
    server = _JWKS(_jwks_doc(rsa_key), SLOW_S)
    try:
        client = ASGIClient(Dashboard(LocalFileStore(tmp_path / "f", instance="t"),
                                      auth=_oidc(server.url)))
        before = threading.active_count()

        async def attack():
            return await asyncio.gather(*[
                client.get("/", {"authorization": f"Bearer {_forged(f'fresh-{i}')}"})
                for i in range(60)])

        t0 = time.monotonic()
        status, waited, results = await _healthz_while(client, attack())
        elapsed = time.monotonic() - t0
        threads = threading.active_count() - before
        assert status == 200 and waited < 0.6
        assert all(s == 401 for s, _ in results)
        assert server.fetches <= 1, server.fetches
        assert elapsed < SLOW_S + authmod.KEY_FETCH_TIMEOUT_S + 2
        assert threads <= dapp.AUTH_WORKERS + 2, threads

        # A real token signed with the published key still verifies.
        status, _ = await client.get("/", {"authorization": f"Bearer {_signed(rsa_key)}"})
        assert status == 200
        assert server.fetches <= 1
    finally:
        server.close()


async def test_a_rotated_key_is_fetched_once_the_refetch_interval_has_passed(
        tmp_path, rsa_key, monkeypatch):
    server = _JWKS(_jwks_doc(rsa_key, kid="old"), 0)
    try:
        cfg = _oidc(server.url)
        client = ASGIClient(Dashboard(LocalFileStore(tmp_path / "f", instance="t"), auth=cfg))
        assert (await client.get("/", {"authorization": f"Bearer {_signed(rsa_key, 'old')}"}))[0] == 200
        server.doc = _jwks_doc(rsa_key, kid="new")
        token = f"Bearer {_signed(rsa_key, 'new')}"
        assert (await client.get("/", {"authorization": token}))[0] == 401
        monkeypatch.setattr(authmod, "JWKS_REFETCH_S", 0.0)
        assert (await client.get("/", {"authorization": token}))[0] == 200
        assert server.fetches == 2
    finally:
        server.close()


def test_requests_during_the_first_fetch_wait_for_it_rather_than_fail(rsa_key):
    server = _JWKS(_jwks_doc(rsa_key), 0.5)
    try:
        cfg = _oidc(server.url)
        out: list = []

        def call():
            try:
                out.append(cfg.authenticate({"authorization": _signed(rsa_key)}).name)
            except AuthError as exc:
                out.append(str(exc))

        threads = [threading.Thread(target=call) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert out == ["dana@example.com"] * 5, out
        assert server.fetches == 1
    finally:
        server.close()


def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def _alb_token(kid):
    header = {"alg": "ES256", "signer": ARN, "client": "client-id", "kid": kid}
    sig = base64.urlsafe_b64encode(b"0" * 64).decode().rstrip("=")
    return f"{_b64(header)}.{_b64({'sub': 'x'})}.{sig}"


async def test_alb_fresh_kids_are_fetched_at_most_a_few_at_a_time(tmp_path, monkeypatch):
    cfg = AuthConfig.parse({"mode": "oidc_jwt", "platform": "alb_oidc", "alb_arn": ARN,
                            "issuer": ISSUER, "audience": "client-id"})
    state = {"inflight": 0, "peak": 0, "calls": 0}
    lock = threading.Lock()

    def slow_urlopen(url, timeout=None):
        with lock:
            state["calls"] += 1
            state["inflight"] += 1
            state["peak"] = max(state["peak"], state["inflight"])
        try:
            time.sleep(0.5)
            raise OSError("404")
        finally:
            with lock:
                state["inflight"] -= 1

    monkeypatch.setattr(authmod, "urlopen", slow_urlopen)
    client = ASGIClient(Dashboard(LocalFileStore(tmp_path / "f", instance="t"), auth=cfg))
    before = threading.active_count()

    async def attack():
        return await asyncio.gather(*[
            client.get("/", {"x-amzn-oidc-data": _alb_token(f"fresh-{i}")})
            for i in range(80)])

    status, waited, results = await _healthz_while(client, attack())
    assert status == 200 and waited < 0.6
    assert all(s == 401 for s, _ in results)
    assert state["peak"] <= authmod.KEY_FETCHES_MAX
    assert state["calls"] < 80
    assert threading.active_count() - before <= dapp.AUTH_WORKERS + 2


async def test_iap_key_fetches_stay_off_the_event_loop(tmp_path, monkeypatch):
    cfg = AuthConfig.parse({"mode": "oidc_jwt", "platform": "iap",
                            "audience": "/projects/1/global/backendServices/2"})

    def slow_urlopen(url, timeout=None):
        time.sleep(SLOW_S)
        raise OSError("unreachable")

    monkeypatch.setattr(authmod, "urlopen", slow_urlopen)
    client = ASGIClient(Dashboard(LocalFileStore(tmp_path / "f", instance="t"), auth=cfg))
    sig = base64.urlsafe_b64encode(b"0" * 64).decode().rstrip("=")
    forged = f"{_b64({'alg': 'ES256', 'kid': 'k1', 'typ': 'JWT'})}.{_b64({'iss': 'x'})}.{sig}"
    attack = client.get("/", {"x-goog-iap-jwt-assertion": forged})
    status, waited, (att_status, _) = await _healthz_while(client, attack)
    assert status == 200 and att_status == 401
    assert waited < 0.6
