"""platform: iap -- Identity-Aware Proxy's x-goog-iap-jwt-assertion.

ES256 against IAP's published JWKS, `iss` fixed, `aud` naming the backend
IAP protects. Keys are a local EC key served by a patched urlopen; nothing
here calls Google.
"""

from __future__ import annotations

import json
import time

import pytest

from forgd_verdict.dashboard import auth as auth_mod
from forgd_verdict.dashboard.auth import IAP_ISSUER, IAP_JWKS_URL, AuthConfig, AuthError
from forgd_verdict.entitlements import MODE_OIDC_JWT, Entitlements, GroupsUnavailable

jwt = pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

AUD = "/projects/123456789012/global/backendServices/9876543210"
RUN_AUD = "/projects/123456789012/locations/europe-west2/services/forgd-dashboard"
KID = "iap-key-1"


@pytest.fixture(scope="module")
def key():
    return ec.generate_private_key(ec.SECP256R1())


def jwk_of(key, kid=KID):
    d = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    return {**d, "kid": kid, "alg": "ES256", "use": "sig"}


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def token(key, kid=KID, alg="ES256", drop=(), **claims):
    """`<claim>_in=seconds` sets that claim relative to now, when the token is made."""
    now = int(time.time())
    relative = {k[:-3]: now + claims.pop(k) for k in list(claims) if k.endswith("_in")}
    body = {"iss": IAP_ISSUER, "aud": AUD, "sub": "accounts.google.com:1234",
            "email": "dana@example.com", "iat": now - 5, "exp": now + 600,
            **claims, **relative}
    for k in drop:
        body.pop(k)
    return jwt.encode(body, pem(key) if alg != "HS256" else "s" * 32, algorithm=alg,
                      headers={"kid": kid})


class Served:
    """A fake urlopen serving one JWKS, recording every fetch."""

    def __init__(self, keys, fail=False, body=None):
        self.keys, self.fail, self.body = keys, fail, body
        self.calls: list[tuple[str, float]] = []

    def __call__(self, url, timeout):
        self.calls.append((url, timeout))
        if self.fail:
            raise OSError("unreachable")
        body = self.body if self.body is not None else json.dumps({"keys": self.keys}).encode()

        class R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return body if n < 0 else body[:n]
        return R()


@pytest.fixture
def served(key, monkeypatch):
    s = Served([jwk_of(key)])
    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", s)
    return s


@pytest.fixture
def cfg(served):
    return AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap", "audience": AUD})


def verify(cfg, tok):
    return cfg.authenticate({"x-goog-iap-jwt-assertion": tok})


def test_a_valid_token_verifies(cfg, key, served):
    p = verify(cfg, token(key))
    assert p.name == "dana@example.com" and p.issuer == IAP_ISSUER
    assert cfg.header == "x-goog-iap-jwt-assertion"
    assert served.calls == [(IAP_JWKS_URL, auth_mod.IAP_FETCH_TIMEOUT_S)]


def test_a_cloud_run_audience_verifies(served, key):
    c = AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap", "audience": RUN_AUD})
    assert verify(c, token(key, aud=RUN_AUD)).name == "dana@example.com"


@pytest.mark.parametrize("kw", [
    {"iss": "https://accounts.google.com"},
    {"iss": "https://cloud.google.com/iap/"},
    {"aud": "/projects/123456789012/global/backendServices/1111111111"},
    {"aud": "/projects/999999999999/global/backendServices/9876543210"},
    {"exp_in": -10},
    {"iat_in": 600},
    {"drop": ("exp",)},
    {"drop": ("iat",)},
    {"drop": ("aud",)},
    {"drop": ("email",)},
    {"drop": ("sub",)},
    {"email": ""},
    {"email": ["dana@example.com"]},
    {"kid": "unknown-kid"},
    {"kid": "../../evil"},
])
def test_refused(cfg, key, kw):
    with pytest.raises(AuthError):
        verify(cfg, token(key, **kw))


def test_the_gke_placeholder_audience_starts_and_refuses_every_token(served, key):
    """values-gke.example.yaml installs with this audience before the backend
    service exists. The app must start, and refuse a valid IAP token for the
    real backend."""
    placeholder = "/projects/0/global/backendServices/0"
    c = AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap", "audience": placeholder})
    with pytest.raises(AuthError):
        verify(c, token(key))
    assert verify(c, token(key, aud=placeholder)).name == "dana@example.com"


def test_a_token_signed_by_another_key_is_refused(cfg):
    with pytest.raises(AuthError):
        verify(cfg, token(ec.generate_private_key(ec.SECP256R1())))


def test_hs256_is_refused_before_any_fetch(cfg, served):
    with pytest.raises(AuthError):
        verify(cfg, token(None, alg="HS256"))
    assert served.calls == []


def test_rs256_is_refused_before_any_fetch(cfg, served):
    with pytest.raises(AuthError):
        verify(cfg, token(rsa.generate_private_key(public_exponent=65537, key_size=2048),
                          alg="RS256"))
    assert served.calls == []


def test_alg_none_is_refused(cfg, served):
    import base64

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    now = int(time.time())
    head = seg({"alg": "none", "kid": KID})
    body = seg({"iss": IAP_ISSUER, "aud": AUD, "sub": "s", "email": "admin@x",
                "iat": now, "exp": now + 60})
    for sig in ("", seg({})):
        with pytest.raises(AuthError):
            verify(cfg, f"{head}.{body}.{sig}")
    assert served.calls == []


def test_other_keys_in_the_set_are_skipped(key, monkeypatch):
    r = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_jwk = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(r.public_key())),
               "kid": "rsa-1", "alg": "RS256"}
    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen",
                        Served([rsa_jwk, {"kty": "oct", "kid": "x"}, "junk", jwk_of(key)]))
    c = AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap", "audience": AUD})
    assert verify(c, token(key)).name == "dana@example.com"


def test_an_ec_key_that_cannot_be_parsed_is_skipped(key, monkeypatch):
    good = jwk_of(key)
    bad = [{**good, "kid": "no-crv", "crv": None}, {**good, "kid": "odd-crv", "crv": "P-999"},
           {"kty": "EC", "kid": "no-coords", "crv": "P-256"}]
    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", Served([*bad, good]))
    c = AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap", "audience": AUD})
    assert verify(c, token(key)).name == "dana@example.com"


def test_a_p384_key_signing_as_es256_is_refused(monkeypatch):
    """Signed by hand: the key is in the set under the token's kid and the
    signature is valid for it, so only the curve check refuses it."""
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    p384 = ec.generate_private_key(ec.SECP384R1())
    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", Served([jwk_of(p384)]))
    c = AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap", "audience": AUD})

    def seg(raw):
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    now = int(time.time())
    head = seg(json.dumps({"alg": "ES256", "kid": KID}).encode())
    body = seg(json.dumps({"iss": IAP_ISSUER, "aud": AUD, "sub": "s", "email": "admin@x",
                           "iat": now - 5, "exp": now + 60}).encode())
    r, s_ = decode_dss_signature(p384.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
    with pytest.raises(AuthError):
        verify(c, f"{head}.{body}." + seg(r.to_bytes(48, "big") + s_.to_bytes(48, "big")))


def test_the_principal_carries_no_groups_and_entitlements_fail_closed(cfg, key):
    p = verify(cfg, token(key, groups=["admins"]))
    assert p.groups == () and p.groups_incomplete
    with pytest.raises(GroupsUnavailable):
        Entitlements(by_group={"admins": frozenset({"org"})}).allowed(p)


# -- startup ----------------------------------------------------------------


@pytest.mark.parametrize("raw", [
    {},                                                                  # no audience
    {"audience": "$FORGD_DASHBOARD_AUDIENCE_UNSET"},                     # unresolved
    {"audience": "1234567890-abc.apps.googleusercontent.com"},           # a client id
    {"audience": AUD + "\n"},
    {"audience": [AUD, "anything"]},
    {"audience": AUD, "issuer": "https://accounts.google.com"},
    {"audience": AUD, "jwks_url": "https://evil.example/keys"},
    {"audience": AUD, "issuers": [{"issuer": "b", "jwks_url": "c", "audience": "d"}]},
])
def test_an_incomplete_or_conflicting_config_refuses_to_start(raw):
    with pytest.raises(ValueError):
        AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap", **raw})


def test_the_audience_resolves_from_the_environment(monkeypatch, served, key):
    monkeypatch.setenv("FORGD_DASHBOARD_AUDIENCE", AUD)
    c = AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap",
                          "audience": "$FORGD_DASHBOARD_AUDIENCE"})
    assert c.describe() == {"mode": MODE_OIDC_JWT, "header": "x-goog-iap-jwt-assertion",
                            "issuer": IAP_ISSUER, "audience": AUD}
    assert verify(c, token(key)).name == "dana@example.com"


def test_iap_is_not_a_trusted_header():
    with pytest.raises(ValueError, match="only for oidc_jwt"):
        AuthConfig.parse({"mode": "trusted_header", "stripped_by": "IAP",
                          "header": "$FORGD_DASHBOARD_HEADER_UNSET", "platform": "iap"})


# -- fetching ---------------------------------------------------------------


def test_keys_are_cached_across_requests(cfg, key, served):
    for _ in range(5):
        verify(cfg, token(key))
    assert len(served.calls) == 1


def test_an_unknown_kid_refetches_at_most_once_per_window(cfg, key, served, monkeypatch):
    verify(cfg, token(key))
    for n in range(5):
        with pytest.raises(AuthError):
            verify(cfg, token(key, kid=f"fake-{n}"))
    assert len(served.calls) == 1
    later = [token(key, kid=f"later-{n}") for n in range(5)]
    clock = time.time() + auth_mod.IAP_REFETCH_S + 1
    monkeypatch.setattr(auth_mod.time, "time", lambda: clock)
    for tok in later:
        with pytest.raises(AuthError):
            verify(cfg, tok)
    assert len(served.calls) == 2


def test_a_failed_fetch_is_not_retried_within_the_window(key, monkeypatch):
    s = Served([], fail=True)
    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", s)
    c = AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap", "audience": AUD})
    for _ in range(3):
        with pytest.raises(AuthError):
            verify(c, token(key))
    assert len(s.calls) == 1


def test_a_rotated_key_is_picked_up_after_the_window(cfg, key, served, monkeypatch):
    verify(cfg, token(key))
    new = ec.generate_private_key(ec.SECP256R1())
    served.keys = [jwk_of(key), jwk_of(new, "iap-key-2")]
    with pytest.raises(AuthError):
        verify(cfg, token(new, kid="iap-key-2"))    # within the window: no refetch
    tok = token(new, kid="iap-key-2")
    # PyJWT reads the clock through datetime, so this moves only the cache's.
    clock = time.time() + auth_mod.IAP_REFETCH_S + 1
    monkeypatch.setattr(auth_mod.time, "time", lambda: clock)
    assert verify(cfg, tok).name == "dana@example.com"
    assert len(served.calls) == 2


def test_stale_keys_are_not_used_when_the_refetch_fails(cfg, key, served, monkeypatch):
    verify(cfg, token(key))
    served.fail = True
    tok = token(key)
    clock = time.time() + auth_mod.JWKS_TTL_S + 1
    monkeypatch.setattr(auth_mod.time, "time", lambda: clock)
    with pytest.raises(AuthError):
        verify(cfg, tok)
    assert len(served.calls) == 2


def test_an_oversized_key_set_is_refused(key, monkeypatch):
    body = json.dumps({"keys": [jwk_of(key)]}).encode()
    s = Served([], body=body + b" " * auth_mod.IAP_JWKS_MAX_BYTES)
    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", s)
    c = AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "iap", "audience": AUD})
    with pytest.raises(AuthError):
        verify(c, token(key))


async def test_the_dashboard_says_iap_carries_no_groups(tmp_path, cfg, key):
    from test_dashboard_auth import _get

    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.store.local import LocalFileStore

    app = Dashboard(LocalFileStore(tmp_path / "s", instance="t"), auth=cfg,
                    entitlements=Entitlements(by_group={"g1": frozenset({"org_x"})}))
    status, body = await _get(app, "/", {"x-goog-iap-jwt-assertion": token(key)})
    out = json.loads(body)
    assert status == 403 and out["error"] == "groups_unavailable"
    assert "Identity-Aware Proxy" in out["detail"] and "Entra" not in out["detail"]


@pytest.mark.parametrize("claim, value", [("exp", 10**400), ("exp", 10**20),
                                          ("nbf", -10**400), ("iat", -10**400),
                                          ("nbf", 10**400), ("iat", 10**400),
                                          ("exp", -10**400)],
                         ids=["exp-1e400", "exp-1e20", "nbf-minus-1e400", "iat-minus-1e400", "nbf-1e400",
                                           "iat-1e400", "exp-minus-1e400"])
def test_an_out_of_range_timestamp_claim_is_refused(cfg, key, caplog, claim, value):
    """PyJWT accepts an `exp` of 10**400, a token that never expires, and an
    `nbf` or `iat` of -10**400. Each time claim present must be a number of
    seconds between the epoch and the end of year 9999."""
    with caplog.at_level("DEBUG"), pytest.raises(AuthError) as exc:
        verify(cfg, token(key, **{claim: value}))
    assert str(exc.value).startswith("token rejected: ")
    assert "OverflowError" not in caplog.text and "OverflowError" not in str(exc.value)
