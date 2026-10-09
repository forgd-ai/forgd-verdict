"""platform: alb_oidc -- an AWS ALB's x-amzn-oidc-data token.

ALB publishes no JWKS and puts no `aud` in the token. It names the key in
the header's `kid`, serves it as PEM per region, and says who the token is
for in the header's `signer` (the load balancer ARN) and `client`.
"""

from __future__ import annotations

import time

import pytest

from forgd_verdict.dashboard.auth import AuthConfig, AuthError
from forgd_verdict.entitlements import MODE_OIDC_JWT

jwt = pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ARN = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/dash/0123456789abcdef"
OTHER = "arn:aws:elasticloadbalancing:eu-west-1:999999999999:loadbalancer/app/evil/fedcba9876543210"
ISS = "https://idp.example/"
CLIENT = "dash-client"
KID = "0b1f6a2c-1111-2222-3333-444455556666"


@pytest.fixture(scope="module")
def key():
    return ec.generate_private_key(ec.SECP256R1())


def token(key, signer=ARN, client=CLIENT, kid=KID, alg="ES256", iss=ISS, **claims):
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    body = {"iss": iss, "sub": "u1", "email": "dana@x", "exp": int(time.time()) + 60, **claims}
    return jwt.encode(body, pem, algorithm=alg,
                      headers={"kid": kid, "signer": signer, "client": client})


@pytest.fixture
def cfg(key, monkeypatch):
    c = AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "alb_oidc", "alb_arn": ARN,
                          "issuer": ISS, "audience": CLIENT})
    fetched = []

    def fake_urlopen(url, timeout):
        fetched.append(url)
        pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)

        class R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return pub
        return R()

    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", fake_urlopen)
    c.fetched = fetched
    return c


def verify(cfg, tok):
    return cfg.authenticate({"x-amzn-oidc-data": tok})


def test_a_token_from_our_load_balancer_verifies(cfg, key):
    p = verify(cfg, token(key))
    assert p.name == "dana@x" and p.issuer == ISS
    assert cfg.fetched == [f"https://public-keys.auth.elb.eu-west-1.amazonaws.com/{KID}"]
    verify(cfg, token(key))
    assert len(cfg.fetched) == 1, "the key is cached by kid"


def test_padded_segments_verify(cfg, key):
    """ALB's segments carry base64 padding, which most JWTs do not, and it
    signs the padded form. Built by hand, because jwt.encode never pads."""
    import base64
    import json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode()  # padded

    head = b64(json.dumps({"alg": "ES256", "typ": "JWT", "kid": KID, "signer": ARN,
                           "client": CLIENT}).encode())
    body = b64(json.dumps({"iss": ISS, "sub": "u", "email": "dana@x",
                           "exp": int(time.time()) + 60, "pad": "x"}).encode())
    assert "=" in head + body, "the fixture must actually be padded"
    r, s_ = decode_dss_signature(key.sign(f"{head}.{body}".encode(),
                                          ec.ECDSA(hashes.SHA256())))
    sig = b64(r.to_bytes(32, "big") + s_.to_bytes(32, "big"))
    assert verify(cfg, f"{head}.{body}.{sig}").name == "dana@x"


@pytest.mark.parametrize("kw", [
    {"signer": OTHER},               # another ALB, whose keys are at the same public URL
    {"client": "someone-else"},
    {"iss": "https://evil.example/"},
    {"kid": "../../evil"},
    {"kid": "a" * 200},
])
def test_refused(cfg, key, kw):
    with pytest.raises(AuthError):
        verify(cfg, token(key, **kw))


def test_a_token_signed_by_another_key_is_refused(cfg):
    with pytest.raises(AuthError):
        verify(cfg, token(ec.generate_private_key(ec.SECP256R1())))


def test_the_signer_is_checked_before_any_key_fetch(cfg, key):
    with pytest.raises(AuthError):
        verify(cfg, token(key, signer=OTHER))
    assert cfg.fetched == []


def test_an_expired_token_is_refused(cfg, key):
    with pytest.raises(AuthError):
        verify(cfg, token(key, exp=int(time.time()) - 10))


@pytest.mark.parametrize("raw", [
    {"issuer": ISS, "audience": CLIENT},                              # no ARN
    {"alb_arn": ARN, "audience": CLIENT},                             # no issuer
    {"alb_arn": ARN, "issuer": ISS},                                  # no client id
    {"alb_arn": "arn:aws:iam::123456789012:role/x", "issuer": ISS, "audience": CLIENT},
    {"alb_arn": ARN, "issuer": ISS, "audience": CLIENT,
     "issuers": [{"issuer": "b", "jwks_url": "c", "audience": "d"}]},
])
def test_an_incomplete_alb_config_refuses_to_start(raw):
    with pytest.raises(ValueError):
        AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "alb_oidc", **raw})


def test_a_tampered_payload_is_refused(cfg, key):
    import base64
    import json

    head, body, sig = token(key).split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["email"] = "admin@x"
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    with pytest.raises(AuthError):
        verify(cfg, f"{head}.{forged}.{sig}")


def test_junk_in_a_segment_is_refused(cfg, key):
    head, body, sig = token(key).split(".")
    with pytest.raises(AuthError):
        verify(cfg, f"{head}.{body[:5]}!{body[5:]}.{sig}")


def test_a_key_of_the_wrong_type_is_refused(cfg, key, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    monkeypatch.setattr(cfg, "_alb_key", lambda region, kid: rsa_pub)
    with pytest.raises(AuthError):
        verify(cfg, token(key))


def test_alg_none_is_refused(cfg):
    import base64
    import json

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    head = seg({"alg": "none", "kid": KID, "signer": ARN, "client": CLIENT})
    body = seg({"iss": ISS, "email": "admin@x", "exp": int(time.time()) + 60})
    for sig in ("", seg({})):
        with pytest.raises(AuthError):
            verify(cfg, f"{head}.{body}.{sig}")
    assert cfg.fetched == []


@pytest.mark.parametrize("platform", ["oauth2_proxy", "alb_oidc", "container_apps"])
def test_a_platform_cannot_change_the_trusted_header(platform):
    """Under trusted_header a platform swapped the header the stripped_by
    attestation was about: `oauth2_proxy` trusted any Authorization value."""
    with pytest.raises(ValueError, match="only for oidc_jwt"):
        AuthConfig.parse({"mode": "trusted_header", "stripped_by": "EasyAuth",
                          "header": "$FORGD_DASHBOARD_HEADER_UNSET", "platform": platform})


@pytest.mark.parametrize("arn", [
    "arn:aws-us-gov:elasticloadbalancing:us-gov-west-1:123456789012:loadbalancer/app/d/0123abcd",
    "arn:aws-cn:elasticloadbalancing:cn-north-1:123456789012:loadbalancer/app/d/0123abcd",
    ARN + "\n",
])
def test_other_partitions_refuse_to_start(arn):
    with pytest.raises(ValueError):
        AuthConfig.parse({"mode": MODE_OIDC_JWT, "platform": "alb_oidc", "alb_arn": arn,
                          "issuer": ISS, "audience": CLIENT})


def test_a_kid_that_failed_is_not_fetched_again(cfg, key, monkeypatch):
    calls = []

    def failing(url, timeout):
        calls.append(url)
        raise OSError("no such key")

    monkeypatch.setattr("forgd_verdict.dashboard.auth.urlopen", failing)
    for _ in range(3):
        with pytest.raises(AuthError):
            verify(cfg, token(key, kid="11111111-2222-3333-4444-555555555555"))
    assert len(calls) == 1


@pytest.mark.parametrize("exp", [float("nan"), float("inf")])
def test_a_non_finite_exp_is_refused(cfg, key, exp):
    import base64
    import json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    head = seg({"alg": "ES256", "kid": KID, "signer": ARN, "client": CLIENT})
    body = seg({"iss": ISS, "email": "x", "exp": exp})
    r, s_ = decode_dss_signature(key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
    sig = base64.urlsafe_b64encode(r.to_bytes(32, "big") + s_.to_bytes(32, "big")).decode()
    with pytest.raises(AuthError):
        verify(cfg, f"{head}.{body}.{sig}")


def test_a_partial_single_issuer_beside_a_list_is_named():
    with pytest.raises(ValueError, match="partly set"):
        AuthConfig.parse({"mode": MODE_OIDC_JWT, "issuer": ISS,
                          "issuers": [{"issuer": "b", "jwks_url": "c", "audience": "d"}]})


# -- where ALB puts exp and iss --------------------------------------------


def _signed(key, head: dict, body: dict) -> str:
    import base64
    import json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode()

    h, b = seg(head), seg(body)
    r, s_ = decode_dss_signature(key.sign(f"{h}.{b}".encode(), ec.ECDSA(hashes.SHA256())))
    return f"{h}.{b}." + base64.urlsafe_b64encode(r.to_bytes(32, "big") + s_.to_bytes(32, "big")).decode()


HEAD = {"alg": "ES256", "kid": KID, "signer": ARN, "client": CLIENT}


def test_exp_and_iss_in_the_header_only_verify(cfg, key):
    """AWS's documented shape: exp and iss in the signed header, the payload
    being the IdP's user-info claims. Reading them from the payload alone
    refused every real login."""
    tok = _signed(key, {**HEAD, "iss": ISS, "exp": int(time.time()) + 60},
                  {"sub": "u1", "email": "dana@x"})
    assert verify(cfg, tok).name == "dana@x"


@pytest.mark.parametrize("head_extra, body_extra", [
    ({"iss": ISS, "exp": -10}, {}),                                   # header expired
    ({"iss": "https://evil.example/", "exp": 60}, {}),               # header issuer wrong
    ({"iss": ISS, "exp": 60}, {"iss": "https://evil.example/"}),     # copies disagree
    ({"iss": ISS, "exp": 60}, {"exp": -10}),                         # payload copy expired
    ({}, {}),                                                         # neither carries them
])
def test_every_copy_of_exp_and_iss_must_pass(cfg, key, head_extra, body_extra):
    """`exp` in the parameters is seconds from now, resolved when the token is made."""
    now = int(time.time())

    def at(d):
        return {k: now + v if k == "exp" else v for k, v in d.items()}

    tok = _signed(key, {**HEAD, **at(head_extra)}, {"sub": "u1", **at(body_extra)})
    with pytest.raises(AuthError):
        verify(cfg, tok)


# -- timestamp claims out of range -----------------------------------------


@pytest.mark.parametrize("where", ["header", "payload"])
@pytest.mark.parametrize("claim, value", [("exp", 10**400), ("nbf", 10**400),
                                          ("exp", -10**400), ("exp", 10**20)],
                         ids=["exp-1e400", "nbf-1e400", "exp-minus-1e400", "exp-1e20"])
def test_an_out_of_range_timestamp_is_refused_with_an_auth_reason(cfg, key, caplog, where,
                                                                  claim, value):
    """JSON carries integers of any size and the signature covers them, so
    `exp=10**400` arrives as a Python int no float holds. It is refused as a
    malformed timestamp, never by an OverflowError."""
    now = int(time.time())
    head = {**HEAD, "iss": ISS, "exp": now + 60}
    body = {"sub": "u1", "email": "dana@x"}
    (head if where == "header" else body)[claim] = value
    if claim == "nbf" and where == "header":
        body["nbf"] = value
    with caplog.at_level("DEBUG"), pytest.raises(AuthError) as exc:
        verify(cfg, _signed(key, head, body))
    assert str(exc.value) in ("token rejected: expired", "token rejected: not yet valid")
    assert "OverflowError" not in caplog.text
