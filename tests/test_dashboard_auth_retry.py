"""A key fetch that fails is retried soon, and a flood of forged kids still
costs at most one fetch per retry interval.

A JWKS fetch that raised anything but AuthError -- an unreachable IdP, a
reset connection, a body that is not a key set -- left the refetch window
set, so every login for that issuer failed with "unknown kid" for
JWKS_REFETCH_S. A failed fetch now waits JWKS_RETRY_S, doubling with each
failure in a row up to JWKS_REFETCH_S, and a success restores the window.
"""

from __future__ import annotations

import contextlib

import pytest

from forgd_verdict.dashboard import auth as auth_mod
from forgd_verdict.dashboard.auth import AuthError, GatedJWKS

jwt = pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _doc(key, kid="real"):
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return {"keys": [dict(public, kid=kid, use="sig", alg="RS256")]}


def _token(key, kid="real"):
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return jwt.encode({"sub": "u"}, pem, algorithm="RS256", headers={"kid": kid})


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Endpoint:
    """`fetch_data` for a GatedJWKS: fails while `down`, else serves `doc`."""

    def __init__(self, gated, doc):
        self.gated, self.doc, self.down, self.calls = gated, doc, True, 0

    def __call__(self):
        self.calls += 1
        if self.down:
            raise jwt.PyJWKClientConnectionError("unreachable")
        if self.gated._client.jwk_set_cache is not None:
            self.gated._client.jwk_set_cache.put(self.doc)
        return self.doc


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(auth_mod.time, "monotonic", c)
    return c


@pytest.fixture
def gated(rsa_key, clock, monkeypatch):
    g = GatedJWKS("https://idp.example/jwks", contextlib.nullcontext)
    endpoint = Endpoint(g, _doc(rsa_key))
    monkeypatch.setattr(g._client, "fetch_data", endpoint)
    g.endpoint = endpoint
    return g


def _try(g, token):
    try:
        return g.get_signing_key_from_jwt(token)
    except Exception:  # noqa: BLE001 - AuthError or the fetch's own error
        return None


def test_a_failed_fetch_is_retried_after_the_retry_interval(gated, clock, rsa_key):
    token = _token(rsa_key)
    assert _try(gated, token) is None and gated.endpoint.calls == 1
    gated.endpoint.down = False
    assert _try(gated, token) is None and gated.endpoint.calls == 1   # still waiting
    clock.now += auth_mod.JWKS_RETRY_S
    assert _try(gated, token) is not None and gated.endpoint.calls == 2


def test_a_flood_of_forged_kids_costs_one_fetch_per_retry_interval(gated, clock, rsa_key):
    for i in range(200):
        _try(gated, _token(rsa_key, kid=f"forged-{i}"))
        clock.now += 0.01
    # Two seconds of flood: the first fetch, one after JWKS_RETRY_S, and the
    # next waits twice that.
    assert gated.endpoint.calls <= 2, gated.endpoint.calls


def test_the_retry_interval_doubles_up_to_the_refetch_window(gated, clock, rsa_key):
    token = _token(rsa_key)
    waits = []
    last = None
    for _ in range(12):
        before = gated.endpoint.calls
        while gated.endpoint.calls == before:
            _try(gated, token)
            clock.now += 0.25
        if last is not None:
            waits.append(round(clock.now - last))
        last = clock.now
    assert waits == sorted(waits)
    assert waits[0] <= 2 * auth_mod.JWKS_RETRY_S
    assert max(waits) <= auth_mod.JWKS_REFETCH_S + 1
    assert waits[-1] >= auth_mod.JWKS_REFETCH_S - 1


def test_a_success_restores_the_refetch_window_for_unknown_kids(gated, clock, rsa_key):
    for _ in range(4):           # a few failures in a row
        _try(gated, _token(rsa_key))
        clock.now += auth_mod.JWKS_REFETCH_S
    gated.endpoint.down = False
    assert _try(gated, _token(rsa_key)) is not None
    calls = gated.endpoint.calls
    clock.now += auth_mod.JWKS_RETRY_S * 2
    assert _try(gated, _token(rsa_key, kid="new")) is None
    assert gated.endpoint.calls == calls   # within the refetch window
    clock.now += auth_mod.JWKS_REFETCH_S
    _try(gated, _token(rsa_key, kid="new"))
    assert gated.endpoint.calls == calls + 1


def test_a_body_that_is_not_a_key_set_counts_as_a_failure(gated, clock, rsa_key):
    gated.endpoint.down = False
    gated.endpoint.doc = {"keys": "nope"}
    assert _try(gated, _token(rsa_key)) is None
    calls = gated.endpoint.calls
    for _ in range(20):
        _try(gated, _token(rsa_key, kid="x"))
    assert gated.endpoint.calls == calls


def test_no_free_fetch_slot_is_retried_on_the_next_request(rsa_key, clock, monkeypatch):
    busy = {"on": True}

    @contextlib.contextmanager
    def slot():
        if busy["on"]:
            raise AuthError("token rejected: key fetch busy")
        yield

    g = GatedJWKS("https://idp.example/jwks", slot)
    endpoint = Endpoint(g, _doc(rsa_key))
    endpoint.down = False
    monkeypatch.setattr(g._client, "fetch_data", endpoint)
    with pytest.raises(AuthError):
        g.get_signing_key_from_jwt(_token(rsa_key))
    busy["on"] = False
    assert g.get_signing_key_from_jwt(_token(rsa_key)) is not None


# -- the same class on the other platforms -------------------------------------


def _alb_cfg():
    from forgd_verdict.dashboard.auth import AuthConfig

    return AuthConfig.parse({
        "mode": "oidc_jwt", "platform": "alb_oidc",
        "alb_arn": "arn:aws:elasticloadbalancing:eu-west-1:123456789012:"
                   "loadbalancer/app/dash/0123456789abcdef",
        "issuer": "https://idp.example/", "audience": "dash-client"})


def test_an_alb_key_fetch_that_failed_on_the_network_is_retried_soon(monkeypatch):
    from urllib.error import URLError

    cfg = _alb_cfg()
    calls = []
    now = {"t": 1000.0}
    monkeypatch.setattr(auth_mod.time, "time", lambda: now["t"])

    def down(url, timeout):
        calls.append(url)
        raise URLError("unreachable")

    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", down)
    kid = "11111111-2222-3333-4444-555555555555"
    for _ in range(3):
        with pytest.raises(Exception):  # noqa: B017 - the fetch's own error
            cfg._alb_key("eu-west-1", kid)
    assert len(calls) == 1
    now["t"] += auth_mod.JWKS_RETRY_S
    with pytest.raises(Exception):  # noqa: B017
        cfg._alb_key("eu-west-1", kid)
    assert len(calls) == 2


def test_an_alb_kid_the_endpoint_does_not_have_waits_the_miss_ttl(monkeypatch):
    import io
    from urllib.error import HTTPError

    cfg = _alb_cfg()
    calls = []
    now = {"t": 1000.0}
    monkeypatch.setattr(auth_mod.time, "time", lambda: now["t"])

    def missing(url, timeout):
        calls.append(url)
        raise HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", missing)
    kid = "11111111-2222-3333-4444-555555555555"
    for _ in range(2):
        with pytest.raises(Exception):  # noqa: B017
            cfg._alb_key("eu-west-1", kid)
    now["t"] += auth_mod.ALB_MISS_TTL_S - 1
    with pytest.raises(AuthError):
        cfg._alb_key("eu-west-1", kid)
    assert len(calls) == 1


def test_an_iap_fetch_that_failed_is_retried_soon(monkeypatch):
    from forgd_verdict.dashboard.auth import AuthConfig

    cfg = AuthConfig.parse({"mode": "oidc_jwt", "platform": "iap",
                            "audience": "/projects/123456789012/global/backendServices/1"})
    calls = []
    now = {"t": 1000.0}
    monkeypatch.setattr(auth_mod.time, "time", lambda: now["t"])

    def down(url, timeout):
        calls.append(url)
        raise OSError("unreachable")

    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", down)
    for _ in range(3):
        with pytest.raises(Exception):  # noqa: B017
            cfg._iap_key("k1")
    assert len(calls) == 1
    now["t"] += auth_mod.JWKS_RETRY_S
    with pytest.raises(Exception):  # noqa: B017
        cfg._iap_key("k1")
    assert len(calls) == 2


def test_the_retry_interval_is_inside_the_refetch_window():
    assert 0 < auth_mod.JWKS_RETRY_S <= auth_mod.JWKS_REFETCH_S


def test_a_cache_holding_the_raw_jwks_document_still_resolves_the_key(rsa_key, clock, monkeypatch):
    """PyJWT before 2.15 caches the JWKS document as fetched, a dict, where
    2.15 caches a PyJWKSet. Reading `.keys` off the dict found no key, so
    every token was rejected on those versions."""
    g = GatedJWKS("https://idp.example/jwks", contextlib.nullcontext)
    endpoint = Endpoint(g, _doc(rsa_key))
    endpoint.down = False
    monkeypatch.setattr(g._client, "fetch_data", endpoint)
    cache = g._client.jwk_set_cache
    assert cache is not None
    doc = _doc(rsa_key)

    def put_raw(_data):
        # What PyJWT 2.14's fetch_data leaves in the cache: the document.
        cache.jwk_set_with_timestamp = type("Stamped", (), {
            "get_jwk_set": lambda self: doc,
            "get_timestamp": lambda self: float("inf")})()

    monkeypatch.setattr(cache, "put", put_raw)
    monkeypatch.setattr(cache, "is_expired", lambda: False)
    assert g.get_signing_key_from_jwt(_token(rsa_key)) is not None
    # The second lookup reads the dict straight from the cache.
    assert isinstance(cache.get(), dict)
    assert g.get_signing_key_from_jwt(_token(rsa_key)) is not None
