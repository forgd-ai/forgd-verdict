"""The dashboard names no literal org id: not on the Policy tab, and not in
the log line for a refused `?org=`."""

from __future__ import annotations

import json
import logging

import pytest
import yaml
from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.entitlements import MODE_OIDC_JWT, MODE_TRUSTED_HEADER, Principal
from forgd_verdict.policy import ORG_ID_PLACEHOLDER, Policy, redacted
from forgd_verdict.store.base import pseudonym
from forgd_verdict.store.local import LocalFileStore

LITERALS = {
    "orgs": "sentinel-orgs-id-3e1f",
    "legacy": "sentinel-legacy-org-id-77a0",
    "compliance": "sentinel-compliance-id-c4d2",
    "otel": "sentinel-otel-id-90bb",
    "map": "sentinel-map-org-18fe",
    "other_env": "$SOME_OTHER_VAR",
}
RESOLVED = {
    "FORGD_ORG_ID_PROD": "sentinel-resolved-prod-5a5a",
    "FORGD_ORG_ID_EU": "sentinel-resolved-eu-6b6b",
    "SOME_OTHER_VAR": "sentinel-resolved-other-7c7c",
}
AUTH = {"mode": MODE_OIDC_JWT, "jwks_url": "https://idp/keys", "issuer": "https://idp",
        "audience": "aud"}


def raw_policy() -> dict:
    return {
        "privacy": {"hash_salt": "s"},
        "orgs": [{"id": LITERALS["orgs"], "label": "Literal"},
                 {"id": "$FORGD_ORG_ID_PROD", "label": "Prod"},
                 {"id": "", "label": "Empty"}],
        "compliance": {
            "org_id": LITERALS["legacy"],
            "orgs": [{"id": LITERALS["compliance"]}, {"id": "$FORGD_ORG_ID_EU"}],
        },
        "otel": {"orgs": [{"id": LITERALS["otel"], "token": "t"},
                          {"id": LITERALS["other_env"], "token": "t"}]},
        "dashboard": {"auth": dict(AUTH), "entitlements": {"map": [
            {"group": "g", "orgs": [LITERALS["map"], "$FORGD_ORG_ID_PROD"]},
        ]}},
    }


@pytest.fixture
def org_env(monkeypatch):
    for name, value in RESOLVED.items():
        monkeypatch.setenv(name, value)


def test_redacted_replaces_every_literal_org_id_and_keeps_env_references(org_env):
    shown = redacted(Policy(raw=raw_policy()), hashes_here=False)
    assert [o["id"] for o in shown["orgs"]] == [ORG_ID_PLACEHOLDER, "$FORGD_ORG_ID_PROD", ""]
    assert shown["compliance"]["org_id"] == ORG_ID_PLACEHOLDER
    assert [o["id"] for o in shown["compliance"]["orgs"]] == [
        ORG_ID_PLACEHOLDER, "$FORGD_ORG_ID_EU"]
    assert [o["id"] for o in shown["otel"]["orgs"]] == [ORG_ID_PLACEHOLDER] * 2
    assert shown["dashboard"]["entitlements"]["map"][0]["orgs"] == [
        ORG_ID_PLACEHOLDER, "$FORGD_ORG_ID_PROD"]


def test_redacted_leaves_the_policy_it_was_given_unchanged():
    policy = Policy(raw=raw_policy())
    redacted(policy)
    assert policy.raw == raw_policy()


async def test_the_policy_tab_shows_no_literal_org_id(tmp_path, monkeypatch, org_env):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml.safe_dump(raw_policy()))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy_file))

    dash = Dashboard(LocalFileStore(tmp_path / "store", instance="t"))
    status, body = await ASGIClient(dash).get("/policy")
    assert status == 200
    assert "could not be loaded" not in body
    for value in list(LITERALS.values()) + list(RESOLVED.values()):
        assert value not in body, value
    assert "$FORGD_ORG_ID_PROD" in body and "$FORGD_ORG_ID_EU" in body
    assert "&lt;org id&gt;" in body


# --- the refused `?org=` log line ------------------------------------------


def _restricted_dashboard(tmp_path) -> Dashboard:
    policy = Policy(raw={"privacy": {"hash_salt": "s"}, "dashboard": {
        "auth": dict(AUTH), "entitlements": {"map": [{"group": "g", "orgs": ["org-a"]}]}}})

    class FixedAuth(AuthConfig):
        def authenticate(self, headers):
            return Principal("dana", ("g",))

    return Dashboard(LocalFileStore(tmp_path / "store", instance="t"),
                     auth=FixedAuth(mode=MODE_TRUSTED_HEADER),
                     entitlements=policy.entitlements())


@pytest.mark.parametrize("requested,well_formed", [
    (pseudonym("org-b", "s", "org"), True),
    ("sentinel-requested-org-id-2d9c", False),
    ("org_0123456789abc", False),
])
async def test_a_refused_org_is_logged_without_its_value(
        tmp_path, caplog, requested, well_formed):
    dash = _restricted_dashboard(tmp_path)
    with caplog.at_level(logging.INFO, logger="forgd_verdict.dashboard"):
        status, body = await ASGIClient(dash).get(f"/?org={requested}")
    assert status == 403 and body == {"error": "forbidden"}
    refused = [r for r in caplog.records if r.getMessage() == "dashboard org refused"]
    assert len(refused) == 1
    assert refused[0].fields == {"who": "dana", "org_well_formed": well_formed}
    for record in caplog.records:
        text = record.getMessage() + json.dumps(getattr(record, "fields", {}), default=str)
        assert requested not in text
