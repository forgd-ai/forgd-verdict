"""The connector's startup validation: what it refuses, and what it leaves alone."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from forgd_verdict.connector import config
from forgd_verdict.dashboard.auth import AuthError
from forgd_verdict.policy import default_policy, load_policy

REPO = Path(__file__).resolve().parents[1]
ISSUER = "https://login.example.com/tenant/v2.0"
JWKS = "https://login.example.com/tenant/discovery/v2.0/keys"
RESOURCE = "https://connector.example.com/mcp"


def _auth(**over):
    auth = {"mode": "oidc_jwt", "issuer": ISSUER, "jwks_url": JWKS,
            "audience": [RESOURCE, "api-client-id"]}
    auth.update(over)
    return {k: v for k, v in auth.items() if v is not None}


def _connector(**over):
    block = {"enabled": True, "resource": RESOURCE,
             "scopes": [f"{RESOURCE}/findings.read"],
             "required_scope": "findings.read", "auth": _auth()}
    block.update(over)
    return {k: v for k, v in block.items() if v is not None}


def _policy(tmp_path, data):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data))
    return load_policy(path)


def _load(tmp_path, connector=None, **top):
    data = dict(top)
    if connector is not None:
        data["connector"] = connector
    return config.load(_policy(tmp_path, data))


# --- left alone ------------------------------------------------------------

def test_a_policy_without_a_connector_block_validates(tmp_path):
    assert _load(tmp_path) is None


def test_the_default_policy_validates():
    assert config.load(default_policy()) is None


def test_the_shipped_policy_validates():
    assert config.load(load_policy(REPO / "policy.yaml")) is None


def test_a_disabled_connector_is_not_validated(tmp_path):
    """Half-written config under enabled: false must not stop anything."""
    assert _load(tmp_path, {"enabled": False, "auth": {"mode": "none"},
                            "resource": "http://X/"}) is None


def test_a_complete_config_loads(tmp_path):
    cfg = _load(tmp_path, _connector())
    assert cfg.resource == RESOURCE
    assert cfg.scopes == (f"{RESOURCE}/findings.read",)
    assert cfg.required_scope == "findings.read"
    assert cfg.allowed_origins == ("https://claude.ai",)
    assert cfg.auth.header == "authorization"
    assert cfg.auth.issuers[0].audience == (RESOURCE, "api-client-id")
    assert not cfg.entitlements.enabled


def test_a_non_default_port_is_canonical(tmp_path):
    url = "https://connector.example.com:8443/mcp"
    assert _load(tmp_path, _connector(resource=url)).resource == url


# --- refusals --------------------------------------------------------------

def test_enabled_must_be_a_boolean(tmp_path):
    with pytest.raises(ValueError, match="connector.enabled must be true or false"):
        _load(tmp_path, _connector(enabled="$FORGD_CONNECTOR_ENABLED"))


@pytest.mark.parametrize("auth", [None, {}])
def test_enabled_without_auth_refuses(tmp_path, auth):
    block = _connector()
    block.pop("auth")
    if auth is not None:
        block["auth"] = auth
    with pytest.raises(ValueError, match="connector.auth is not set"):
        _load(tmp_path, block)


@pytest.mark.parametrize("mode", ["none", "trusted_header", "", None])
def test_any_mode_but_oidc_jwt_refuses(tmp_path, mode):
    auth = _auth()
    auth.pop("mode")
    if mode is not None:
        auth["mode"] = mode
    with pytest.raises(ValueError, match="connector.auth.mode must be 'oidc_jwt'"):
        _load(tmp_path, _connector(auth=auth))


@pytest.mark.parametrize("key,value", [
    ("platform", "oauth2_proxy"), ("platform", "container_apps"),
    ("alb_arn", "arn:aws:elasticloadbalancing:eu-west-1:123456789012:"
                "loadbalancer/app/x/0123456789abcdef"),
])
def test_a_platform_refuses(tmp_path, key, value):
    with pytest.raises(ValueError, match="takes no proxy platform"):
        _load(tmp_path, _connector(auth=_auth(**{key: value})))


@pytest.mark.parametrize("key,value", [
    ("header", "x-ms-client-principal-name"), ("header", "authorization"),
    ("stripped_by", "oauth2-proxy, checked"),
])
def test_a_header_setting_refuses(tmp_path, key, value):
    with pytest.raises(ValueError, match="trusts no other header"):
        _load(tmp_path, _connector(auth=_auth(**{key: value})))


@pytest.mark.parametrize("where,key", [
    ("connector", "static_headers"), ("connector", "token"),
    ("connector", "api_key"), ("auth", "static_token"), ("auth", "bearer"),
    ("auth", "client_secret"), ("issuer", "token"),
])
def test_a_static_credential_refuses(tmp_path, where, key):
    block = _connector()
    if where == "connector":
        block[key] = {"authorization": "Bearer sk-org-wide"}
    elif where == "auth":
        block["auth"][key] = "sk-org-wide"
    else:
        block["auth"] = {"mode": "oidc_jwt", "issuers": [
            {"issuer": ISSUER, "jwks_url": JWKS, "audience": RESOURCE,
             key: "sk-org-wide"}]}
    with pytest.raises(ValueError, match="does not accept a static credential"):
        _load(tmp_path, block)


def test_an_unknown_key_refuses(tmp_path):
    with pytest.raises(ValueError, match="connector.resouce is not a connector setting"):
        _load(tmp_path, _connector(resouce=RESOURCE))


def test_an_opaque_bearer_is_refused_per_request(tmp_path):
    """What Claude sends under static_headers: a bearer that is not a JWT
    from a configured issuer."""
    cfg = _load(tmp_path, _connector())
    for value in ("Bearer " + "sk-org-wide-0123456789", "sk-org-wide-0123456789",
                  "Bearer a.b.c"):
        with pytest.raises(AuthError):
            cfg.auth.authenticate({"authorization": value})


@pytest.mark.parametrize("url,reason", [
    (None, "is not set"),
    ("http://connector.example.com/mcp", "scheme must be https"),
    ("https://Connector.Example.com/mcp", "host must be lowercase"),
    ("https://connector.example.com/mcp/", "must not end with a slash"),
    ("https://connector.example.com/", "must not end with a slash"),
    ("https://connector.example.com:443/mcp", "default port must be omitted"),
    ("https://connector.example.com/mcp?x=1", "query or fragment"),
    ("https://connector.example.com/mcp#f", "query or fragment"),
    ("https://connector.example.com/mcp?", "query or fragment"),
    ("https://user@connector.example.com/mcp", "carries credentials"),
    ("https:///mcp", "there is no host"),
    ("$FORGD_CONNECTOR_TEST_UNSET", "is not set"),
    ("https://connector.example.com", "must end in /mcp"),
    ("https://connector.example.com/findings", "must end in /mcp"),
    ("https://connector.example.com/x/mcp", "must end in /mcp"),
])
def test_a_non_canonical_resource_refuses(tmp_path, url, reason):
    with pytest.raises(ValueError, match=reason):
        _load(tmp_path, _connector(resource=url))


@pytest.mark.parametrize("audience", [None, "", [], ["$FORGD_CONNECTOR_TEST_UNSET"]])
def test_an_issuer_without_an_audience_refuses(tmp_path, audience):
    auth = _auth()
    auth.pop("audience")
    if audience is not None:
        auth["audience"] = audience
    with pytest.raises(ValueError, match="audience not set"):
        _load(tmp_path, _connector(auth=auth))


def test_an_issuers_entry_without_an_audience_refuses(tmp_path):
    auth = {"mode": "oidc_jwt", "issuers": [
        {"issuer": ISSUER, "jwks_url": JWKS, "audience": RESOURCE},
        {"issuer": "https://okta.example.com", "jwks_url": JWKS}]}
    with pytest.raises(ValueError, match=r"issuers\[1\]: audience not set"):
        _load(tmp_path, _connector(auth=auth))


def test_no_issuer_at_all_refuses(tmp_path):
    with pytest.raises(ValueError, match="sets no issuer"):
        _load(tmp_path, _connector(auth={"mode": "oidc_jwt"}))


# --- entitlements and the environment ---------------------------------------

def _entitled(tmp_path, dashboard_auth):
    return _policy(tmp_path, {
        "privacy": {"hash_salt": "test-salt"},
        "dashboard": {"auth": dashboard_auth, "entitlements": {"map": [
            {"group": "g-prod", "orgs": ["org-one"]}]}},
        "connector": _connector(),
    })


def test_entitlements_are_validated_against_the_connector_auth(tmp_path):
    policy = _entitled(tmp_path, {"mode": "trusted_header", "stripped_by": "EasyAuth"})
    with pytest.raises(ValueError, match="requires dashboard.auth.mode 'oidc_jwt'"):
        policy.entitlements()
    cfg = config.load(policy)
    assert cfg.entitlements.enabled


def test_the_dashboard_entitlements_are_unchanged(tmp_path):
    policy = _entitled(tmp_path, _auth())
    assert policy.entitlements() == policy.entitlements(
        auth=policy.dashboard["auth"], auth_path="dashboard.auth")
    assert policy.entitlements() == config.load(policy).entitlements


def test_the_environment_configures_the_connector(tmp_path, monkeypatch):
    env = {
        "FORGD_CONNECTOR_ENABLED": "true",
        "FORGD_CONNECTOR_RESOURCE": RESOURCE,
        "FORGD_CONNECTOR_SCOPES": json.dumps([f"{RESOURCE}/findings.read"]),
        "FORGD_CONNECTOR_REQUIRED_SCOPE": "findings.read",
        "FORGD_CONNECTOR_ALLOWED_ORIGINS": json.dumps(["https://claude.ai"]),
        "FORGD_CONNECTOR_AUTH_MODE": "oidc_jwt",
        "FORGD_CONNECTOR_ISSUER": ISSUER,
        "FORGD_CONNECTOR_JWKS_URL": JWKS,
        "FORGD_CONNECTOR_AUDIENCE": json.dumps([RESOURCE]),
        "FORGD_CONNECTOR_GROUPS_CLAIM": "roles",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    cfg = config.load(_policy(tmp_path, {}))
    assert cfg.resource == RESOURCE and cfg.required_scope == "findings.read"
    assert cfg.auth.issuers[0].issuer == ISSUER
    assert cfg.auth.issuers[0].groups_claim == "roles"


def test_no_connector_override_reaches_detection_or_secrets():
    from forgd_verdict.policy import ENV_OVERRIDES, SECRET_LIST_PATHS, SECRET_PATHS

    paths = [p for n, (p, _c) in ENV_OVERRIDES.items() if n.startswith("FORGD_CONNECTOR_")]
    assert paths and all(p[0] == "connector" for p in paths)
    assert not any(p[0] == "connector" for p in SECRET_PATHS)
    assert not any(p[0][0] == "connector" for p in SECRET_LIST_PATHS)


def test_the_design_doc_names_the_mcp_pin_that_ships():
    """There is no committed uv.lock; the image installs from
    deploy/constraints, which pins mcp exactly."""
    root = Path(__file__).resolve().parent.parent
    [pin] = re.findall(r"^mcp==(\S+)", (root / "deploy" / "constraints" / "base.txt").read_text(), re.M)
    doc = " ".join((root / "docs" / "design" / "connector.md").read_text().split())
    assert "uv.lock" not in doc
    assert f"mcp=={pin}" in doc and "deploy/constraints" in doc
