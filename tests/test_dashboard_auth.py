"""Dashboard authentication.

The point of these is the forgery cases. `trusted_header` is only an
authentication check where the platform's proxy strips inbound copies of
the header; anywhere the container is directly reachable the caller sets it
themselves, and the mode is named for that. `oidc_jwt` verifies a signature
instead, so a forged token has to survive RSA.
"""

from __future__ import annotations

import time

import pytest

from forgd_verdict.dashboard.auth import AuthConfig, AuthError
from forgd_verdict.entitlements import MODE_NONE, MODE_OIDC_JWT, MODE_TRUSTED_HEADER

jwt = pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

ISSUER = "https://login.microsoftonline.com/t/v2.0"
AUDIENCE = "api://forgd-verdict-dashboard"


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key, pem


def _token(pem, **overrides):
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-1",
        "preferred_username": "dana@example.com",
        "exp": int(time.time()) + 600,
        "iat": int(time.time()) - 10,
    }
    claims.update(overrides)
    return jwt.encode(claims, pem, algorithm="RS256")


@pytest.fixture
def verifying(keypair, monkeypatch):
    """An oidc_jwt config whose JWKS resolves to our test key."""
    key, _pem = keypair
    cfg = AuthConfig.parse({
        "mode": MODE_OIDC_JWT, "platform": "container_apps",
        "jwks_url": "https://example.invalid/keys",
        "issuer": ISSUER, "audience": AUDIENCE,
    })

    class _Signing:
        def __init__(self, k):
            self.key = k

    class _Client:
        def get_signing_key_from_jwt(self, _token):
            return _Signing(key.public_key())

    monkeypatch.setattr(cfg, "_keys", lambda *_: _Client())
    return cfg


# -- modes ---------------------------------------------------------------


def test_none_identifies_nobody_and_rejects_nobody():
    cfg = AuthConfig.parse({"mode": MODE_NONE})
    assert cfg.authenticate({}) is None


def test_trusted_header_accepts_whatever_it_is_given():
    """Stated as a test because it is the mode's actual security property:
    it trusts a network position, not a credential."""
    cfg = AuthConfig.parse({"mode": MODE_TRUSTED_HEADER,
                            "stripped_by": "a proxy checked in this test"})
    assert cfg.authenticate(
        {"x-ms-client-principal-name": "dana@example.com"}
    ).name == "dana@example.com"
    got = cfg.authenticate({"x-ms-client-principal-name": "anyone-at-all"})
    assert got.name == "anyone-at-all"
    # And no groups: there is no verified claim to read, which is why
    # entitlements are refused in this mode.
    assert got.groups == ()
    with pytest.raises(AuthError):
        cfg.authenticate({})


def test_oidc_jwt_accepts_a_properly_signed_token(verifying, keypair):
    _key, pem = keypair
    assert verifying.authenticate(
        {"x-ms-token-aad-id-token": _token(pem)}
    ).name == "dana@example.com"


def test_a_bearer_prefix_is_tolerated(verifying, keypair):
    _key, pem = keypair
    assert verifying.authenticate(
        {"x-ms-token-aad-id-token": f"Bearer {_token(pem)}"}
    ).name == "dana@example.com"


# -- forgeries -----------------------------------------------------------


def test_a_token_signed_by_the_wrong_key_is_rejected(verifying):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = other.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(AuthError):
        verifying.authenticate({"x-ms-token-aad-id-token": _token(pem)})


def test_an_unsigned_alg_none_token_is_rejected(verifying):
    """The classic JWT forgery. `algorithms=` must not include `none`."""
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "attacker",
         "exp": int(time.time()) + 600},
        key="", algorithm="none",
    )
    with pytest.raises(AuthError):
        verifying.authenticate({"x-ms-token-aad-id-token": forged})


def test_an_expired_token_is_rejected(verifying, keypair):
    _key, pem = keypair
    with pytest.raises(AuthError):
        verifying.authenticate(
            {"x-ms-token-aad-id-token": _token(pem, exp=int(time.time()) - 60)}
        )


def test_a_token_for_another_audience_is_rejected(verifying, keypair):
    """A token minted for a different application of the same tenant is a
    valid token. It is not a credential for this one."""
    _key, pem = keypair
    with pytest.raises(AuthError):
        verifying.authenticate(
            {"x-ms-token-aad-id-token": _token(pem, aud="api://some-other-app")}
        )


def test_a_token_from_another_issuer_is_rejected(verifying, keypair):
    _key, pem = keypair
    with pytest.raises(AuthError):
        verifying.authenticate(
            {"x-ms-token-aad-id-token": _token(pem, iss="https://evil.example/v2.0")}
        )


def test_the_rejection_reason_never_reaches_the_caller(verifying):
    """A verification oracle tells a forger which part to fix. The reason is
    logged; the response is a flat 401."""
    with pytest.raises(AuthError) as excinfo:
        verifying.authenticate({"x-ms-token-aad-id-token": "not-a-token"})
    # The exception carries a type name for the log, never token contents.
    assert "not-a-token" not in str(excinfo.value)


# -- configuration -------------------------------------------------------


def test_oidc_jwt_without_an_audience_refuses_to_start():
    """Missing `aud` verification accepts tokens minted for any application
    in the tenant, so this fails at startup rather than at request time."""
    with pytest.raises(ValueError, match="audience"):
        AuthConfig.parse({
            "mode": MODE_OIDC_JWT,
            "jwks_url": "https://example.invalid/keys",
            "issuer": ISSUER,
        })


def test_an_unknown_mode_refuses_to_start():
    with pytest.raises(ValueError, match="mode"):
        AuthConfig.parse({"mode": "trust-me"})


def test_platform_selects_the_header():
    for platform, header in (
        ("container_apps", "x-ms-token-aad-id-token"),
        ("cloud_run", "x-serverless-authorization"),
        ("alb_oidc", "x-amzn-oidc-data"),
    ):
        cfg = AuthConfig.parse({
            "mode": MODE_OIDC_JWT, "platform": platform,
            "jwks_url": "https://example.invalid/keys",
            "issuer": ISSUER, "audience": AUDIENCE,
            # alb_oidc also needs the load balancer; see test_dashboard_alb.py.
            "alb_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
                       "loadbalancer/app/dash/0123456789abcdef",
        })
        assert cfg.header == header


def test_describe_never_leaks_configuration_secrets():
    cfg = AuthConfig.parse({
        "mode": MODE_OIDC_JWT, "platform": "cloud_run",
        "jwks_url": "https://example.invalid/keys",
        "issuer": ISSUER, "audience": AUDIENCE,
    })
    assert cfg.describe() == {
        "mode": MODE_OIDC_JWT,
        "header": "x-serverless-authorization",
        "issuer": ISSUER,
        "audience": AUDIENCE,
    }


# -- through the app -----------------------------------------------------


async def _get(app, path, headers=None):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    raw = [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    await app({"type": "http", "method": "GET", "path": path,
               "query_string": b"", "headers": raw}, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


async def test_the_app_returns_a_flat_401_for_a_forged_token(tmp_path, verifying):
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.store.local import LocalFileStore

    app = Dashboard(LocalFileStore(tmp_path / "s", instance="t"), auth=verifying)
    status, body = await _get(app, "/", {"x-ms-token-aad-id-token": "forged"})
    assert status == 401
    assert b"authentication_required" in body
    # No detail about why: that is an oracle.
    assert b"Signature" not in body and b"forged" not in body


async def test_a_valid_token_reaches_the_page(tmp_path, verifying, keypair):
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.store.local import LocalFileStore

    _key, pem = keypair
    app = Dashboard(LocalFileStore(tmp_path / "s", instance="t"), auth=verifying)
    status, body = await _get(app, "/", {"x-ms-token-aad-id-token": _token(pem)})
    assert status == 200
    assert b"<!DOCTYPE html>" in body


async def test_healthz_stays_reachable_without_a_credential(tmp_path, verifying):
    """The platform's probe cannot authenticate."""
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.store.local import LocalFileStore

    app = Dashboard(LocalFileStore(tmp_path / "s", instance="t"), auth=verifying)
    status, _ = await _get(app, "/healthz")
    assert status == 200


# -- oidc config from the environment ------------------------------------

def test_oidc_fields_resolve_from_the_environment(monkeypatch):
    """Like every other deployment-specific value in the policy.

    They were read as literals, which meant an oidc_jwt deployment had to
    commit its tenant and application ids to policy.yaml, and a fork could
    not point the same policy at its own identity provider without editing
    it. A tenant and an application id are not secrets, but they name a
    customer's directory -- the same reason org ids are supplied rather
    than committed.
    """
    monkeypatch.setenv("FORGD_DASHBOARD_JWKS_URL", "https://idp/keys")
    monkeypatch.setenv("FORGD_DASHBOARD_ISSUER", "https://idp/")
    monkeypatch.setenv("FORGD_DASHBOARD_AUDIENCE", "an-app-id")
    cfg = AuthConfig.parse({
        "mode": "oidc_jwt",
        "jwks_url": "$FORGD_DASHBOARD_JWKS_URL",
        "issuer": "$FORGD_DASHBOARD_ISSUER",
        "audience": "$FORGD_DASHBOARD_AUDIENCE",
    })
    assert cfg.jwks_url == "https://idp/keys"
    assert cfg.issuer == "https://idp/"
    assert cfg.audience == "an-app-id"


def test_an_unset_oidc_variable_still_refuses_at_startup(monkeypatch):
    """Substitution must not turn a missing value into an empty one that
    passes. An unset audience would accept tokens minted for a DIFFERENT
    application, which is the failure the startup check exists for."""
    monkeypatch.setenv("FORGD_DASHBOARD_JWKS_URL", "https://idp/keys")
    monkeypatch.setenv("FORGD_DASHBOARD_ISSUER", "https://idp/")
    monkeypatch.delenv("FORGD_DASHBOARD_AUDIENCE", raising=False)
    with pytest.raises(ValueError, match="audience"):
        AuthConfig.parse({
            "mode": "oidc_jwt",
            "jwks_url": "$FORGD_DASHBOARD_JWKS_URL",
            "issuer": "$FORGD_DASHBOARD_ISSUER",
            "audience": "$FORGD_DASHBOARD_AUDIENCE",
        })


def test_the_header_also_resolves_from_the_environment(monkeypatch):
    """So a deployment behind a different proxy can name its header without
    editing the shared policy."""
    monkeypatch.setenv("FORGD_DASHBOARD_HEADER", "X-Auth-Request-Email")
    cfg = AuthConfig.parse({"mode": "trusted_header", "header": "$FORGD_DASHBOARD_HEADER", "stripped_by": "a proxy checked in this test"})
    assert cfg.header == "x-auth-request-email"


def test_the_shipped_policy_is_unaffected_while_the_variables_are_unset(monkeypatch):
    """policy.yaml now carries the placeholders unconditionally.

    They are only validated when the mode is oidc_jwt, so the Container Apps
    deployment -- which uses trusted_header -- must be entirely unchanged by
    their presence.
    """
    from pathlib import Path

    import yaml

    for name in ("JWKS_URL", "ISSUER", "AUDIENCE"):
        monkeypatch.delenv(f"FORGD_DASHBOARD_{name}", raising=False)
    root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("FORGD_DASHBOARD_STRIPPED_BY", "a proxy, checked here")
    policy = yaml.safe_load((root / "policy.yaml").read_text())
    cfg = AuthConfig.parse(policy["dashboard"]["auth"])
    assert cfg.mode == "trusted_header"
    assert cfg.header == "x-ms-client-principal-name"
    assert (cfg.jwks_url, cfg.issuer, cfg.audience) == ("", "", "")


def test_the_auth_header_can_be_supplied(monkeypatch):
    """The chart offers dashboard.auth.header and it did nothing.

    policy.yaml hardcoded `header: x-ms-client-principal-name` as a literal,
    so the env_or_literal substitution had nothing to substitute and
    FORGD_DASHBOARD_HEADER was inert -- the value rendered into the pod
    correctly and was ignored. In oidc_jwt mode that means the app looks for
    a BEARER TOKEN in an Azure EasyAuth header name and answers
    authentication_required with nothing pointing at the cause.
    """
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parents[1]
    raw = yaml.safe_load((root / "policy.yaml").read_text())["dashboard"]["auth"]
    assert raw["header"].startswith("$"), (
        "policy.yaml hardcodes the auth header again; a deployment behind a "
        "different proxy then cannot name its own"
    )

    monkeypatch.setenv("FORGD_DASHBOARD_STRIPPED_BY", "a proxy, checked here")
    monkeypatch.setenv("FORGD_DASHBOARD_HEADER", "authorization")
    assert AuthConfig.parse(raw).header == "authorization"

    monkeypatch.delenv("FORGD_DASHBOARD_HEADER", raising=False)
    assert AuthConfig.parse(raw).header == "x-ms-client-principal-name", (
        "unset must fall back to the Container Apps header, or that "
        "deployment breaks the moment this policy ships"
    )


# -- a broken policy.yaml ------------------------------------------------


def test_a_policy_that_will_not_parse_fails_startup(tmp_path, monkeypatch):
    """Otherwise the dashboard serves every route unauthenticated.

    A missing file is not an error -- `load_policy` returns the built-in
    defaults for one -- so the only thing `create_app` could swallow from
    `load_policy()` is a policy that EXISTS and will not parse. Swallowed,
    it leaves `policy = None`, which skips `dashboard.auth` entirely and
    falls through to mode `none`.
    """
    from forgd_verdict.dashboard.app import create_app

    bad = tmp_path / "policy.yaml"
    bad.write_text('privacy:\n  hash_salt: "unterminated\nserver: {}\n')
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(bad))
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "store"))

    with pytest.raises(Exception) as exc:
        create_app()
    assert "Unauthenticated" not in str(exc.value)


def test_no_policy_file_at_all_still_starts(tmp_path, monkeypatch):
    """The state the swallow claimed to be for. It never reached it."""
    from forgd_verdict.dashboard.app import create_app

    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "store"))
    assert create_app() is not None


def test_a_named_policy_file_that_is_missing_refuses_to_start(tmp_path, monkeypatch):
    from forgd_verdict.dashboard.app import create_app
    from forgd_verdict.policy import PolicyNotFound

    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(tmp_path / "nope.yaml"))
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "store"))
    with pytest.raises(PolicyNotFound, match="nope.yaml"):
        create_app()


def test_a_parser_error_never_quotes_the_policy():
    """PyYAML puts the offending source line in `str(exc)` with a caret
    under it, so an unterminated quote on the hash_salt line printed the
    salt onto the Policy tab."""
    import yaml

    from forgd_verdict.policy import policy_error

    source = 'privacy:\n  hash_salt: "s3cr3t-salt-value\nserver: {}\n'
    try:
        yaml.safe_load(source)
    except yaml.YAMLError as exc:
        assert "s3cr3t-salt-value" in str(exc), "premise: PyYAML quotes the line"
        safe = policy_error(exc)
        assert "s3cr3t-salt-value" not in safe
        assert "hash_salt" not in safe
        assert type(exc).__name__ in safe
        assert "line" in safe
    else:
        raise AssertionError("that YAML should not parse")


def test_oidc_without_pyjwt_is_refused_at_parse_time(monkeypatch):
    """The guarded import with its helpful message lives in `_keys()`, but
    a bare `import jwt` in `authenticate` ran first and `_keys()` was never
    reached -- so startup SUCCEEDED with mode oidc_jwt and the first
    protected request raised ImportError out of the ASGI app. The
    dashboard catches only AuthError, so uvicorn answered 500: an auth
    control selected, reported active, and unable to run.
    """
    import builtins

    real = builtins.__import__

    def no_jwt(name, *a, **kw):
        if name == "jwt":
            raise ImportError("No module named 'jwt'")
        return real(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_jwt)
    with pytest.raises(ValueError, match="PyJWT"):
        AuthConfig.parse({"mode": "oidc_jwt", "jwks_url": "https://x/jwks",
                          "issuer": "https://x", "audience": "aud"})


def test_oidc_with_pyjwt_still_parses():
    cfg = AuthConfig.parse({"mode": "oidc_jwt", "jwks_url": "https://x/jwks",
                            "issuer": "https://x", "audience": "aud"})
    assert cfg.mode == MODE_OIDC_JWT


def test_trusted_header_without_an_attestation_is_refused():
    """The mode is identity forgery anywhere the container is directly
    reachable -- any nonempty header value becomes an authenticated
    principal, with no validation.

    The Helm chart already refused it without an attestation. Terraform
    had none and neither did the app, so the guard held on one of the
    three ways to deploy.
    """
    with pytest.raises(ValueError, match="stripped_by"):
        AuthConfig.parse({"mode": MODE_TRUSTED_HEADER})


def test_the_shipped_policy_refuses_trusted_header_until_someone_attests():
    """`$FORGD_DASHBOARD_STRIPPED_BY` is deliberately unset in the
    committed file. Our defaults become a fork's defaults, and this is the
    one mode where the default was an open door."""
    from forgd_verdict.policy import load_policy

    raw = (load_policy("policy.yaml").raw["dashboard"] or {}).get("auth") or {}
    assert raw.get("mode") == "trusted_header"
    with pytest.raises(ValueError, match="stripped_by"):
        AuthConfig.parse(raw)


def test_an_open_dashboard_refuses_to_bind_a_public_interface(capsys, monkeypatch, tmp_path):
    """DEFAULT_POLICY has no `dashboard.auth` key, so a deployment with no
    policy file resolves to mode `none` -- and the entrypoint defaults to
    0.0.0.0. Every route then serves every finding to anyone who can
    reach the port.

    It warns, but a warning does not stop the bind.
    """
    # The state under test IS "no policy file", which is DEFAULT_POLICY.
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)
    from forgd_verdict.dashboard.__main__ import main

    rc = main(["--store", str(tmp_path / "store"), "--host", "0.0.0.0"])
    assert rc == 2
    assert "refusing to bind" in capsys.readouterr().err


def test_loopback_is_exempt(monkeypatch, tmp_path):
    """`--host 127.0.0.1` for a local look is why the mode exists."""
    started = {}

    def fake_run(app, **kw):
        started.update(kw)

    import sys as _sys
    import types

    monkeypatch.setitem(_sys.modules, "uvicorn",
                        types.SimpleNamespace(run=fake_run))
    from forgd_verdict.dashboard.__main__ import main

    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)
    assert main(["--store", str(tmp_path / "store"),
                 "--host", "127.0.0.1"]) == 0
    assert started["host"] == "127.0.0.1"


def test_serve_open_is_the_explicit_way_through(monkeypatch, tmp_path):
    started = {}
    import sys as _sys
    import types

    monkeypatch.setitem(_sys.modules, "uvicorn",
                        types.SimpleNamespace(run=lambda app, **kw: started.update(kw)))
    from forgd_verdict.dashboard.__main__ import main

    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)
    assert main(["--store", str(tmp_path / "store"),
                 "--host", "0.0.0.0", "--serve-open"]) == 0
    assert started["host"] == "0.0.0.0"
