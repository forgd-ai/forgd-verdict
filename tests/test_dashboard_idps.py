"""Dashboard sign-in beyond Entra ID.

The same forgery discipline as test_dashboard_auth.py, extended to what a
non-Azure deployment brings: EC signatures, more than one issuer, the
proxies in front, and Entra's group overage.
"""

from __future__ import annotations

import json
import time

import pytest
from test_dashboard_auth import _get

from forgd_verdict.dashboard.auth import PLATFORM_HEADERS, AuthConfig, AuthError
from forgd_verdict.entitlements import MODE_OIDC_JWT, Entitlements, GroupsUnavailable, Principal

jwt = pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

A = ("https://idp-a.example/", "https://idp-a.example/jwks", "dash")
B = ("https://idp-b.example/", "https://idp-b.example/jwks", "dash-b")


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


@pytest.fixture(scope="module")
def keys():
    return {"ec": ec.generate_private_key(ec.SECP256R1()),
            "ec2": ec.generate_private_key(ec.SECP256R1()),
            "rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048)}


def tok(key, alg, iss=A[0], aud=A[2], **extra):
    claims = {"iss": iss, "aud": aud, "sub": "u", "preferred_username": "dana@x",
              "exp": int(time.time()) + 600, **extra}
    return jwt.encode(claims, _pem(key), algorithm=alg)


def config(monkeypatch, by_url, **raw):
    cfg = AuthConfig.parse({"mode": MODE_OIDC_JWT, "header": "authorization",
                            "issuer": A[0], "jwks_url": A[1], "audience": A[2], **raw})
    fetched = []

    class _Signing:
        def __init__(self, k):
            self.key = k

    class _Client:
        def __init__(self, url):
            self.url = url

        def get_signing_key_from_jwt(self, _t):
            return _Signing(by_url[self.url].public_key())

    def keys_for(url=""):
        fetched.append(url)
        return _Client(url)

    monkeypatch.setattr(cfg, "_keys", keys_for)
    cfg.fetched = fetched
    return cfg


def auth(cfg, token):
    return cfg.authenticate({"authorization": f"Bearer {token}"})


def test_an_es256_token_verifies(monkeypatch, keys):
    cfg = config(monkeypatch, {A[1]: keys["ec"]})
    assert auth(cfg, tok(keys["ec"], "ES256")).name == "dana@x"


def test_an_es256_token_from_the_wrong_key_does_not(monkeypatch, keys):
    cfg = config(monkeypatch, {A[1]: keys["ec"]})
    with pytest.raises(AuthError):
        auth(cfg, tok(keys["ec2"], "ES256"))


def test_hs256_signed_with_the_public_key_is_refused(monkeypatch, keys):
    """Algorithm confusion: the allowlist has no HMAC, so a public key used
    as a shared secret is never tried."""
    cfg = config(monkeypatch, {A[1]: keys["rsa"]})
    pub = keys["rsa"].public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
    forged = jwt.encode({"iss": A[0], "aud": A[2], "exp": int(time.time()) + 60},
                        pub.decode()[:64], algorithm="HS256")
    with pytest.raises(AuthError):
        auth(cfg, forged)


def test_a_second_issuer_verifies_against_its_own_keys(monkeypatch, keys):
    cfg = config(monkeypatch, {A[1]: keys["rsa"], B[1]: keys["ec"]},
                 issuers=[{"issuer": B[0], "jwks_url": B[1], "audience": B[2]}])
    assert auth(cfg, tok(keys["ec"], "ES256", iss=B[0], aud=B[2])).name == "dana@x"
    assert cfg.fetched == [B[1]]
    # Issuer B's token signed with A's key: the issuer chose B's keys.
    with pytest.raises(AuthError):
        auth(cfg, tok(keys["rsa"], "RS256", iss=B[0], aud=B[2]))
    # And B's audience is B's alone.
    with pytest.raises(AuthError):
        auth(cfg, tok(keys["ec"], "ES256", iss=B[0], aud=A[2]))


def test_an_unconfigured_issuer_is_refused_before_any_key_fetch(monkeypatch, keys):
    cfg = config(monkeypatch, {A[1]: keys["rsa"]})
    with pytest.raises(AuthError):
        auth(cfg, tok(keys["rsa"], "RS256", iss="https://evil.example/"))
    assert cfg.fetched == []


def test_an_audience_list_accepts_either(monkeypatch, keys):
    cfg = config(monkeypatch, {A[1]: keys["rsa"]}, audience=["dash", "dash-old"])
    assert auth(cfg, tok(keys["rsa"], "RS256", aud="dash-old"))


@pytest.mark.parametrize("entry", [
    {"issuer": B[0], "jwks_url": B[1]},
    {"issuer": B[0], "audience": B[2]},
    {"jwks_url": B[1], "audience": B[2]},
])
def test_an_incomplete_issuer_entry_refuses_to_start(entry):
    with pytest.raises(ValueError):
        AuthConfig.parse({"mode": MODE_OIDC_JWT, "issuer": A[0], "jwks_url": A[1],
                          "audience": A[2], "issuers": [entry]})


def test_the_issuers_list_alone_is_enough():
    cfg = AuthConfig.parse({"mode": MODE_OIDC_JWT, "header": "authorization",
                            "issuers": [{"issuer": B[0], "jwks_url": B[1], "audience": B[2]}]})
    assert [i.issuer for i in cfg.issuers] == [B[0]]


@pytest.mark.parametrize("platform, header", [
    ("oauth2_proxy", "authorization"),
    ("cloudflare_access", "cf-access-jwt-assertion"),
    ("pomerium", "x-pomerium-jwt-assertion"),
])
def test_proxy_presets(platform, header):
    assert PLATFORM_HEADERS[platform] == header


# -- Entra's group overage -------------------------------------------------

OVERAGE = {"_claim_names": {"groups": "src1"},
           "_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/v1.0/x"}}}


def test_an_overage_token_is_marked_incomplete(monkeypatch, keys):
    cfg = config(monkeypatch, {A[1]: keys["rsa"]})
    p = auth(cfg, tok(keys["rsa"], "RS256", **OVERAGE))
    assert p.groups == () and p.groups_incomplete


def test_an_overage_signal_marks_groups_incomplete_even_beside_groups(monkeypatch, keys):
    """Mutation: mark incomplete only when the token lists no groups."""
    cfg = config(monkeypatch, {A[1]: keys["rsa"]})
    for signal in (OVERAGE, {"hasgroups": True}):
        p = auth(cfg, tok(keys["rsa"], "RS256", groups=["g1"], **signal))
        assert p.groups == ("g1",) and p.groups_incomplete, signal


def test_a_token_with_groups_and_no_overage_signal_is_complete(monkeypatch, keys):
    cfg = config(monkeypatch, {A[1]: keys["rsa"]})
    p = auth(cfg, tok(keys["rsa"], "RS256", groups=["g1"], hasgroups=False))
    assert p.groups == ("g1",) and not p.groups_incomplete


def test_with_entitlements_on_an_incomplete_principal_is_refused_by_name():
    ent = Entitlements(by_group={"g1": frozenset({"org_x"})})
    with pytest.raises(GroupsUnavailable):
        ent.allowed(Principal("dana", groups_incomplete=True))
    # Off, it changes nothing: groups decide nothing.
    assert Entitlements().allowed(Principal("dana", groups_incomplete=True)) is None


async def test_the_dashboard_says_why(tmp_path, monkeypatch, keys):
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.store.local import LocalFileStore

    cfg = config(monkeypatch, {A[1]: keys["rsa"]})
    app = Dashboard(LocalFileStore(tmp_path / "s", instance="t"), auth=cfg,
                    entitlements=Entitlements(by_group={"g1": frozenset({"org_x"})}))
    status, body = await _get(app, "/", {"authorization": f"Bearer {tok(keys['rsa'], 'RS256', **OVERAGE)}"})
    assert status == 403 and json.loads(body)["error"] == "groups_unavailable"


# -- entitlements across issuers -------------------------------------------


def _ent_policy(entries, issuers=()):
    from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": "s"},
        "dashboard": {
            "auth": {"mode": MODE_OIDC_JWT, "issuer": A[0], "jwks_url": A[1],
                     "audience": A[2], "issuers": list(issuers)},
            "entitlements": {"map": entries}}}))


B_ENTRY = {"issuer": B[0], "jwks_url": B[1], "audience": B[2]}


def test_with_two_issuers_an_entry_must_name_its_issuer():
    with pytest.raises(ValueError, match="issuer"):
        _ent_policy([{"group": "prod-readers", "orgs": ["org-1"]}], [B_ENTRY]).entitlements()


def test_a_scoped_entry_matches_only_its_issuers_group():
    ent = _ent_policy([{"group": "prod-readers", "issuer": A[0], "orgs": ["org-1"]}],
                      [B_ENTRY]).entitlements()
    assert ent.allowed(Principal("a", ("prod-readers",), issuer=A[0]))
    # The same group name, created in the other IdP, grants nothing.
    assert ent.allowed(Principal("b", ("prod-readers",), issuer=B[0])) == frozenset()


def test_one_issuer_needs_no_issuer_on_entries():
    ent = _ent_policy([{"group": "g", "orgs": ["org-1"]}]).entitlements()
    assert ent.allowed(Principal("a", ("g",), issuer=A[0]))


def test_each_issuer_reads_its_own_groups_claim(monkeypatch, keys):
    cfg = config(monkeypatch, {A[1]: keys["rsa"], B[1]: keys["ec"]},
                 issuers=[{**B_ENTRY, "groups_claim": "https://b.example/groups"}])
    a = auth(cfg, tok(keys["rsa"], "RS256", groups=["ga"]))
    b = auth(cfg, tok(keys["ec"], "ES256", iss=B[0], aud=B[2],
                      **{"https://b.example/groups": ["gb"], "groups": ["not-this"]}))
    assert (a.groups, a.issuer) == (("ga",), A[0])
    assert (b.groups, b.issuer) == (("gb",), B[0])


def test_hasgroups_is_the_other_overage_signal(monkeypatch, keys):
    cfg = config(monkeypatch, {A[1]: keys["rsa"]})
    assert auth(cfg, tok(keys["rsa"], "RS256", hasgroups=True)).groups_incomplete


@pytest.mark.parametrize("claim, value", [("exp", 10**400), ("exp", 10**20),
                                          ("nbf", -10**400), ("iat", -10**400),
                                          ("exp", True)],
                         ids=["exp-1e400", "exp-1e20", "nbf-minus-1e400", "iat-minus-1e400", "exp-true"])
def test_an_out_of_range_timestamp_claim_is_refused(monkeypatch, keys, caplog, claim, value):
    """The issuer path decodes with PyJWT, which accepts an `exp` of 10**400."""
    cfg = config(monkeypatch, {A[1]: keys["ec"]})
    with caplog.at_level("DEBUG"), pytest.raises(AuthError) as exc:
        auth(cfg, tok(keys["ec"], "ES256", **{claim: value}))
    assert str(exc.value).startswith("token rejected: ")
    assert "OverflowError" not in caplog.text
