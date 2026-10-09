"""Every configured URL that carries a credential, or serves the keys
credentials are verified against, is https:// or loopback http://.

Standing: the URL-valued keys in the shipped policy, any policy file one
directory down, the example policies and the built-in defaults are
enumerated, and each must be classified below. A new one fails
until it is.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

from forgd_verdict.policy import BUILTIN_SINK_TYPES, DEFAULT_POLICY, URL_KEY

ROOT = pathlib.Path(__file__).resolve().parents[1]
KEY = "sk-ant-api01-SYNTHETIC-not-a-key"
EXTERNAL = "http://collector.example:4318"
LOOPBACK = "http://127.0.0.1:4318"


def _compliance(url):
    from forgd_verdict.compliance.client import ComplianceClient

    ComplianceClient(api_key=KEY, base_url=url)


def _managed(url):
    from forgd_verdict.managed.client import ManagedAgentsClient

    ManagedAgentsClient(api_key=KEY, base_url=url)


def _auth(url):
    from forgd_verdict.dashboard.auth import AuthConfig

    AuthConfig.parse({"mode": "oidc_jwt", "issuer": "https://idp.example/",
                      "jwks_url": url, "audience": "aud"})


def _auth_issuers(url):
    from forgd_verdict.dashboard.auth import AuthConfig

    AuthConfig.parse({"mode": "oidc_jwt", "issuers": [
        {"issuer": "https://idp.example/", "jwks_url": url, "audience": "aud"}]})


def _hook(url):
    from forgd_verdict.hook.endpoint import refusal

    if refusal(url):
        raise ValueError(refusal(url))


def _sink(sink_type):
    def build(url):
        from forgd_verdict.sink.factory import build_forwarders

        build_forwarders([{"name": "s", "type": sink_type, "endpoint": url,
                           "token": "synthetic-bearer"}], [], background=False)
    return build


def _store(url):
    from forgd_verdict.store import open_store

    open_store(url.replace(":4318", "") + "/findings")


# Key path (lists as []) -> how the service checks it, at start or at policy
# load. Each refuses EXTERNAL.
CHECKED = {
    "compliance.base_url": _compliance,
    "managed_agents.base_url": _managed,
    "dashboard.auth.jwks_url": _auth,
    "dashboard.auth.issuers.[].jwks_url": _auth_issuers,
    "connector.auth.jwks_url": _auth,
    "connector.auth.issuers.[].jwks_url": _auth_issuers,
    "hook.ship_endpoint": _hook,
    "hook.scan_endpoint": _hook,
    "sinks.[].endpoint": _sink("otlp"),
    "server.store": _store,
}
# URL-valued keys that carry no credential and fetch no key material.
NOT_A_CREDENTIAL = {
    "dashboard.auth.issuer": "compared with the token's `iss`, never fetched",
    "dashboard.auth.issuers.[].issuer": "compared with the token's `iss`, never fetched",
    "connector.auth.issuer": "compared with the token's `iss`, never fetched",
    "otel.cors_origins": "an allowlist of browser origins",
}


def _url_keys() -> set[str]:
    found: set[str] = set()

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                q = (*path, str(k))
                if URL_KEY.search(str(k)) or str(k).endswith("_url"):
                    found.add(".".join(q))
                walk(v, q)
        elif isinstance(node, list):
            for item in node:
                walk(item, (*path, "[]"))

    files = [ROOT / "policy.yaml", *ROOT.glob("*/policy.yaml"),
             *ROOT.glob("examples/policy/*.yaml")]
    for path in files:
        walk(yaml.safe_load(path.read_text(encoding="utf-8")), ())
    walk(DEFAULT_POLICY, ())
    return found


def test_every_url_valued_policy_key_is_classified():
    unclassified = _url_keys() - set(CHECKED) - set(NOT_A_CREDENTIAL)
    assert not unclassified, (
        f"classify {sorted(unclassified)} in CHECKED (and refuse http:// to a "
        "non-loopback host) or in NOT_A_CREDENTIAL")


@pytest.mark.parametrize("key", sorted(CHECKED))
def test_a_credential_url_refuses_cleartext_to_a_remote_host(key):
    with pytest.raises(Exception) as exc:  # noqa: PT011 - each check has its own type
        CHECKED[key](EXTERNAL)
    assert "https" in str(exc.value)


@pytest.mark.parametrize("key", sorted(set(CHECKED) - {"server.store"}))
def test_a_credential_url_accepts_loopback_http(key):
    CHECKED[key](LOOPBACK)


@pytest.mark.parametrize("sink_type", BUILTIN_SINK_TYPES)
def test_every_built_in_sink_type_refuses_cleartext_to_a_remote_host(sink_type, monkeypatch):
    monkeypatch.setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")
    with pytest.raises(Exception) as exc:  # noqa: PT011
        _sink(sink_type)(EXTERNAL)
    assert "https" in str(exc.value)


def test_a_sink_with_no_credential_may_use_http():
    from forgd_verdict.sink.factory import build_forwarders

    (fwd,) = build_forwarders([{"name": "s", "type": "otlp", "endpoint": EXTERNAL}], [],
                              background=False)
    assert fwd.config.endpoint == EXTERNAL


def test_userinfo_in_a_sink_endpoint_is_a_credential():
    from forgd_verdict.sink.base import SinkUnavailable
    from forgd_verdict.sink.factory import build_forwarders

    with pytest.raises(SinkUnavailable, match="https"):
        build_forwarders([{"name": "s", "type": "otlp",
                           "endpoint": "http://u:p@collector.example:4318"}], [],
                         background=False)
