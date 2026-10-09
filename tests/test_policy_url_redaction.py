"""URL-valued and credential-shaped policy values on the Policy tab, in
`forgd-verdict policy`, and in every other place a policy value is shown or
logged."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest
import yaml

from forgd_verdict.models import shown_url
from forgd_verdict.policy import DEFAULT_POLICY, Policy, load_policy, redacted

REPO = Path(__file__).resolve().parent.parent
CANARY = "CANARYZ"


# -- shown_url ------------------------------------------------------------


@pytest.mark.parametrize("url", [
    f"https://user:{CANARY}1@collector.example/v1/logs",
    f"https://{CANARY}2@collector.example/v1/logs",
    f"https://:{CANARY}3@collector.example/",
    f"https://collector.example/v1/logs?api-key={CANARY}4",
    f"https://collector.example/v1/logs#{CANARY}5",
    f"https://collector.example/v1/logs?#{CANARY}6",
    f"https://u:{CANARY}7@[2001:db8::1]:8443/x?k=v",
    f"https://[2001:db8::1]/x?k={CANARY}8",
    f"https://u%3A{CANARY}9%40collector.example/",
    f"https://user%40corp:{CANARY}10@collector.example/",
    f"https://collector.example\\@{CANARY}11/",
    f"https://u:{CANARY}12\t@collector.example/",
    f"HTTPS://U:{CANARY}13@COLLECTOR.EXAMPLE/",
    f"//u:{CANARY}14@collector.example/",
    f"u:{CANARY}15@collector.example",
    f"az://acct;SharedAccessSignature={CANARY}16",
    f"https://acct.blob.core.windows.net/c;sig={CANARY}17/x",
    f"https://collector.example/hook/token={CANARY}18",
    f"https://u:{CANARY}19@collector.example:99999/",
    f"https://u＠{CANARY}20@collector.example/",
    f"  https://u:{CANARY}21@collector.example/",
    f"s3://AKIAFAKE:{CANARY}22@bucket/prefix",
    f"https://u:{CANARY}23@collector.example:not-a-port/",
    f"https://collector.example/%2F{CANARY}24%3Fx=",
    f"https://bücher.example:{CANARY}25@h/",
    f"https://h/p\n?{CANARY}26",
    f"$NOT_A_REF@{CANARY}27",
    f"https://[::1%25{CANARY}28]/",
])
def test_a_credential_in_a_url_is_not_shown(url):
    assert CANARY not in shown_url(url)


@pytest.mark.parametrize("url", [
    "https://api.anthropic.com",
    "https://collector.example:4318/v1/logs",
    "https://dce.example/dataCollectionRules/dcr-1/streams/Custom-X",
    "gs://bucket/prefix",
    "s3://bucket/prefix",
    "https://acct.blob.core.windows.net/findings/prefix",
    "./findings",
    "/var/lib/forgd/findings",
    "file:///var/lib/forgd/findings",
    "https://[2001:db8::1]:8443/v1",
    "$FORGD_SINK_ENDPOINT_AZMON",
    "http://127.0.0.1:8080/intake",
])
def test_a_url_with_no_credential_is_shown_as_written(url):
    assert shown_url(url) == url


def test_a_query_and_userinfo_are_named_as_redacted():
    assert shown_url("https://u:p@h.example/x?k=v#f") == \
        "https://<redacted>@h.example/x?<redacted>#<redacted>"


# -- redacted(): every URL-valued and credential-shaped key ---------------


def _canaries() -> dict[str, str]:
    names = ["store_cred", "ship_store_cred", "sink_url_cred", "sink_query", "ship_ep",
             "scan_ep", "jwks_q", "idp_jwks", "origin", "base_url", "fleet_map",
             "fleet_map2", "client_str", "otel_map", "req_list", "future_url",
             "future_tok", "embedded", "frag", "ipv6", "ws_map", "comp_map", "sink_map",
             "sas"]
    return {n: f"{CANARY}_{n.upper()}" for n in names}


def _kitchen_sink(c: dict[str, str]) -> dict:
    return {
        "server": {"store": f"https://u:{c['store_cred']}@acct.blob.core.windows.net/f",
                   "required_headers": [c["req_list"]]},
        "hook": {
            "ship_store": f"az://acct;SharedAccessSignature={c['ship_store_cred']}",
            "ship_endpoint": f"https://intake.example/intake?token={c['ship_ep']}",
            "scan_endpoint": f"https://x:{c['scan_ep']}@intake.example/scan",
        },
        "otel": {"store": f"gs://bucket/p#{c['frag']}",
                 "orgs": {"prod": {"token": c["otel_map"]}}},
        "intake": {
            "store": f"https://u:{c['ipv6']}@[2001:db8::1]/c",
            "fleet": {"laptops": {"tokens": [c["fleet_map"]]}, c["fleet_map2"]: {}},
            "clients": [c["client_str"]],
        },
        "compliance": {"base_url": f"https://k:{c['base_url']}@api.anthropic.com",
                       "orgs": {"prod": c["comp_map"]}},
        "managed_agents": {"workspaces": {"ws": c["ws_map"]}},
        "sinks": [{"name": "out", "type": "otlp",
                   "endpoint": f"https://user:{c['sink_url_cred']}@collector.example/v1"
                               f"/logs?api-key={c['sink_query']}"},
                  c["sink_map"]],
        "dashboard": {
            "auth": {"mode": "oidc_jwt", "issuer": "https://issuer.example/",
                     "jwks_url": f"https://issuer.example/jwks?code={c['jwks_q']}",
                     "audience": "aud",
                     "issuers": [{"issuer": "https://idp2.example/",
                                  "jwks_url": f"https://a:{c['idp_jwks']}@idp2.example/k",
                                  "audience": "aud"}]},
            "admins": {"allowed_origins": [f"https://o:{c['origin']}@dash.example"]},
            "branding": {"title": f"see https://u:{c['embedded']}@wiki.example/page"},
        },
        "future_section": {"callback_url": f"https://cb.example/?sig={c['future_url']}",
                           "api_token": c["future_tok"],
                           "blob": f"https://acct.blob.core.windows.net/c?sv=1&sig={c['sas']}"},
    }


def _dump(policy: Policy) -> str:
    return yaml.safe_dump(redacted(policy, hashes_here=False), allow_unicode=True) + \
        json.dumps(redacted(policy))


def test_no_canary_in_any_url_valued_or_credential_shaped_key():
    c = _canaries()
    text = _dump(Policy(raw=_kitchen_sink(c)))
    assert not [k for k, v in c.items() if v in text]


def test_required_headers_written_as_a_list_are_redacted():
    text = _dump(Policy(raw={"server": {"required_headers": [f"x-a: {CANARY}_RH"]}}))
    assert CANARY not in text


def test_redaction_keeps_what_an_operator_needs():
    shown = redacted(Policy(raw={
        "sinks": [{"name": "out", "type": "otlp",
                   "endpoint": "https://u:p@collector.example:4318/v1/logs?k=v"}],
        "compliance": {"base_url": "https://api.anthropic.com"},
        "server": {"store": "./findings", "max_tokens": 4096},
        "intake": {"fleet": [{"name": "laptops", "tokens": ["$FORGD_UNSET_FLEET_X"],
                              "routes": ["intake"]}]},
    }))
    assert shown["sinks"][0]["endpoint"] == \
        "https://<redacted>@collector.example:4318/v1/logs?<redacted>"
    assert shown["compliance"]["base_url"] == "https://api.anthropic.com"
    assert shown["server"]["store"] == "./findings"
    assert shown["server"]["max_tokens"] == 4096
    assert shown["intake"]["fleet"][0]["tokens"] == ["<unset: $FORGD_UNSET_FLEET_X empty>"]
    assert shown["intake"]["fleet"][0]["routes"] == ["intake"]


def test_a_detector_pattern_with_a_url_is_shown_as_written():
    pattern = r"https://hooks\.slack\.com/services/[A-Z0-9]+"
    shown = redacted(Policy(raw={"detectors": {"t0_regex": {
        "enabled": True, "patterns": [{"name": "slack", "regex": pattern}]}}}))
    assert shown["detectors"]["t0_regex"]["patterns"][0]["regex"] == pattern


@pytest.mark.parametrize("var,path", [
    ("FORGD_VERDICT_STORE", ("server", "store")),
    ("FORGD_VERDICT_SHIP_ENDPOINT", ("hook", "ship_endpoint")),
    ("FORGD_VERDICT_SCAN_ENDPOINT", ("hook", "scan_endpoint")),
    ("FORGD_VERDICT_SHIP_STORE", ("hook", "ship_store")),
])
def test_an_env_override_url_is_redacted(tmp_path, monkeypatch, var, path):
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump({"privacy": {"allow_unsalted": True},
                                 "hook": {"project_overrides": True}}))
    monkeypatch.setenv(var, f"https://u:{CANARY}_ENV@h.example/c?sig={CANARY}_ENVQ")
    policy = load_policy(str(p))
    node = policy.raw
    for part in path:
        node = node[part]
    assert CANARY in node, "the override did not reach the effective policy"
    assert CANARY not in _dump(policy)


# -- the standing walk over every shipped policy -------------------------

_URL_KEY = re.compile(r"(^|_)(endpoint|url|uri|issuer|store|origins?|issuers)$")
_CRED_KEY = re.compile(
    r"(^|_)(token|tokens|secret|secrets|password|passwd|api_key|apikey|private_key"
    r"|access_key|secret_key|signing_key|form_key|sas|sas_token|connection_string"
    r"|credential|credentials|hash_salt)$")


def _shipped() -> list[tuple[str, dict]]:
    out = [("DEFAULT_POLICY", json.loads(json.dumps(DEFAULT_POLICY)))]
    for path in [REPO / "policy.yaml", *sorted(REPO.glob("*/policy.yaml")),
                 *sorted((REPO / "examples").rglob("*.yaml"))]:
        if path.is_file():
            doc = yaml.safe_load(path.read_text())
            if isinstance(doc, dict):
                out.append((str(path.relative_to(REPO)), doc))
    return out


def _poison(node, path=(), found=None, under_detectors=False):
    """Replace every URL-shaped and credential-shaped value under `node` with
    a canary carrying credentials; return the canaries planted."""
    found = [] if found is None else found
    if isinstance(node, dict):
        for k, v in list(node.items()):
            key = str(k)
            det = under_detectors or key in ("detectors", "sink_detectors")
            if not det and _CRED_KEY.search(key) and isinstance(v, (str, list)) and v:
                tag = f"{CANARY}_{len(found)}"
                node[k] = [tag] if isinstance(v, list) else tag
                found.append((path + (key,), tag))
            elif not det and _URL_KEY.search(key) and isinstance(v, (str, list)):
                n = len(found)
                url = f"https://u:{CANARY}_{n}u@h.example/p?k={CANARY}_{n}q#{CANARY}_{n}f"
                node[k] = [url] if isinstance(v, list) else url
                found.append((path + (key,), f"{CANARY}_{n}"))
            else:
                _poison(v, path + (key,), found, det)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str) and "://" in v and not under_detectors:
                n = len(found)
                node[i] = f"https://u:{CANARY}_{n}u@h.example/?k={CANARY}_{n}q"
                found.append((path + (str(i),), f"{CANARY}_{n}"))
            else:
                _poison(v, path + (str(i),), found, under_detectors)
    return found


SHIPPED = _shipped()


@pytest.mark.parametrize("name,doc", SHIPPED, ids=[n for n, _ in SHIPPED])
def test_every_url_and_credential_in_a_shipped_policy_is_redacted(name, doc):
    planted = _poison(doc)
    assert planted, f"{name}: the walk found no URL- or credential-shaped value"
    text = _dump(Policy(raw=doc))
    leaked = [p for p, tag in planted if tag in text]
    assert not leaked, f"{name}: {leaked}"


def test_the_walk_covers_the_shipped_url_keys():
    """A guard on the walk itself: these are the URL-valued keys the shipped
    policy.yaml carries."""
    planted = {".".join(p) for p, _ in _poison(dict(SHIPPED[1][1]))}
    for key in ("server.store", "compliance.base_url", "dashboard.auth.jwks_url",
                "dashboard.auth.issuer", "sinks.0.endpoint"):
        assert key in planted, key


@pytest.mark.parametrize("name,doc", SHIPPED, ids=[n for n, _ in SHIPPED])
async def test_every_url_and_credential_stays_off_the_policy_tab(
        tmp_path, monkeypatch, name, doc):
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from conftest import ASGIClient

    from forgd_verdict.dashboard import app as dapp
    from forgd_verdict.store import LocalFileStore

    planted = _poison(doc)
    doc.setdefault("privacy", {})["allow_unsalted"] = True
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(doc))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(p))
    dapp.POLICY_CACHE.clear()
    dash = dapp.Dashboard(LocalFileStore(tmp_path / "findings", instance="t"))
    status, html = await ASGIClient(dash).get("/policy")
    assert status == 200
    assert "could not be loaded" not in html or CANARY not in html
    assert not [path for path, tag in planted if tag in html], name


def test_the_policy_command_prints_no_canary(tmp_path, capsys):
    from forgd_verdict.cli import main

    c = _canaries()
    doc = _kitchen_sink(c)
    doc.pop("future_section")
    doc["server"].pop("required_headers")
    doc["privacy"] = {"allow_unsalted": True}
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(doc))
    main(["--policy", str(p), "policy"])
    out = capsys.readouterr()
    assert not [k for k, v in c.items() if v in out.out + out.err]


# -- other places a policy value is shown or logged ----------------------


def test_the_dashboard_auth_description_shows_no_url_credential():
    from forgd_verdict.dashboard.auth import AuthConfig

    cfg = AuthConfig.parse({"mode": "oidc_jwt",
                            "issuer": f"https://u:{CANARY}_I@issuer.example/?q={CANARY}_Q",
                            "jwks_url": "https://issuer.example/jwks", "audience": "aud"})
    assert CANARY not in json.dumps(cfg.describe())


def test_an_allowed_origin_refusal_does_not_echo_a_credential():
    from forgd_verdict.dashboard.admin import AdminConfig
    from forgd_verdict.dashboard.auth import AuthConfig

    auth = AuthConfig.parse({"mode": "oidc_jwt", "issuer": "https://i.example/",
                             "jwks_url": "https://i.example/k", "audience": "aud"})
    with pytest.raises(ValueError) as exc:
        AdminConfig.parse({"groups": [{"group": "a"}], "form_key": "k" * 40,
                           "allowed_origins": [f"https://u:{CANARY}_O@dash.example"]},
                          auth=auth)
    assert "allowed_origins" in str(exc.value)
    assert CANARY not in str(exc.value)


@pytest.mark.parametrize("spec", [
    f"s3://AKIAFAKE:{CANARY}_S3@bucket/prefix",
    f"gs://u:{CANARY}_GS@bucket/prefix",
    f"https://u:{CANARY}_AZ@acct.blob.core.windows.net/c",
])
def test_a_store_spec_with_userinfo_is_refused_without_echoing_it(spec, caplog):
    from forgd_verdict.store import open_store

    with caplog.at_level(logging.DEBUG), pytest.raises(ValueError) as exc:
        open_store(spec, instance="t")
    assert CANARY not in str(exc.value)
    assert CANARY not in caplog.text


@pytest.mark.parametrize("spec", [f"s3:///?{CANARY}_S3", f"gs:///#{CANARY}_GS"])
def test_a_malformed_bucket_spec_error_does_not_echo_a_credential(spec):
    from forgd_verdict.store import open_store

    with pytest.raises(Exception) as exc:  # noqa: B017 - any refusal, as long as it is quiet
        open_store(spec, instance="t")
    assert CANARY not in str(exc.value)
