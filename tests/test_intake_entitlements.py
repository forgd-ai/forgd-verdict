"""Intake client partitions under dashboard entitlements.

Before the fleet model the intake filed a client's records under the
client's name. Those partitions stay in a store, so a `clients:` grant
still reads them; the picker no longer offers them, and a map need not
grant any.
"""

from __future__ import annotations

import pytest
import yaml
from conftest import ASGIClient

from forgd_verdict.dashboard import app as dashboard_app
from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.entitlements import MODE_TRUSTED_HEADER, Entitlements, Principal
from forgd_verdict.policy import Policy
from forgd_verdict.store.base import SOURCE_CODE_HOOK, VerdictRecord, pseudonym
from forgd_verdict.store.local import LocalFileStore

SALT = "s"
A = pseudonym("org-a", SALT, "org")
AUTH = {"mode": "oidc_jwt", "jwks_url": "https://x.example/keys",
        "issuer": "https://x.example", "audience": "aud"}
CLIENTS = [{"name": "developer", "token": "$FORGD_INTAKE_TOKEN_DEVELOPER"},
           {"name": "ci-bot", "token": "$FORGD_INTAKE_TOKEN_CI_BOT"}]
MAP = [{"group": "g-dev", "orgs": ["org-a"], "clients": ["developer"]},
       {"group": "g-org", "orgs": ["org-a"]}]


def _raw(entries=MAP, clients=CLIENTS) -> dict:
    return {"privacy": {"hash_salt": SALT},
            "orgs": [{"id": "org-a", "label": "Alpha"}],
            "intake": {"clients": clients},
            "dashboard": {"auth": AUTH, "entitlements": {"map": entries}}}


def _dashboard(tmp_path, principal, policy: Policy, entitlements=None):
    store = LocalFileStore(tmp_path, instance="t")
    store.write_verdicts([
        VerdictRecord(source=SOURCE_CODE_HOOK, session_id="dev-session-1",
                      tenant_hash="developer", surface="surface-dev"),
        VerdictRecord(source=SOURCE_CODE_HOOK, session_id="bot-session-1",
                      tenant_hash="ci-bot", surface="surface-bot"),
        VerdictRecord(source="otel_collect", session_id="org-session-1",
                      tenant_hash=A, surface="surface-org"),
    ])

    class FixedAuth(AuthConfig):
        def authenticate(self, headers):
            return principal

    return Dashboard(store, auth=FixedAuth(mode=MODE_TRUSTED_HEADER),
                     entitlements=policy.entitlements() if entitlements is None
                     else entitlements,
                     org_labels=policy.partition_labels())


def test_a_client_grant_resolves_to_the_partition_intake_writes():
    ent = Policy(raw=_raw()).entitlements()
    assert ent.allowed(Principal("dana", ("g-dev",))) == frozenset({A, "developer"})
    assert ent.allowed(Principal("olu", ("g-org",))) == frozenset({A})


async def test_a_granted_viewer_reads_the_clients_partition(tmp_path):
    dash = _dashboard(tmp_path, Principal("dana", ("g-dev",)), Policy(raw=_raw()))
    status, html = await ASGIClient(dash).get("/events?window=all&code_hook_allows=show")
    assert status == 200
    assert "dev-session-1" in html and "org-session-1" in html
    assert "bot-session-1" not in html
    status, html = await ASGIClient(dash).get(
        "/events?window=all&org=developer&code_hook_allows=show")
    assert status == 200
    assert "dev-session-1" in html and "org-session-1" not in html
    # The picker lists orgs only.
    assert 'href="/events?org=developer"' not in html


async def test_an_ungranted_viewer_cannot_read_it(tmp_path):
    dash = _dashboard(tmp_path, Principal("olu", ("g-org",)), Policy(raw=_raw()))
    status, html = await ASGIClient(dash).get("/events?window=all&code_hook_allows=show")
    assert status == 200
    assert "org-session-1" in html
    assert "dev-session-1" not in html and "bot-session-1" not in html
    status, body = await ASGIClient(dash).get(
        "/events?window=all&org=developer&code_hook_allows=show")
    assert status == 403


async def test_with_no_map_the_picker_lists_no_client(tmp_path):
    policy = Policy(raw=_raw(entries=[]))
    dash = _dashboard(tmp_path, Principal("anyone"), policy, entitlements=Entitlements())
    status, html = await ASGIClient(dash).get("/events?window=all&code_hook_allows=show")
    assert status == 200
    for name in ("developer", "ci-bot"):
        assert f'href="/events?org={name}"' not in html
    assert "dev-session-1" in html and "bot-session-1" in html


def test_a_map_that_grants_no_client_loads_while_clients_exist():
    ent = Policy(raw=_raw(entries=[{"group": "g-org", "orgs": ["org-a"]}])).entitlements()
    assert ent.allowed(Principal("olu", ("g-org",))) == frozenset({A})


def test_the_dashboard_starts_on_that_map(tmp_path, monkeypatch):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(_raw(entries=[{"group": "g-org", "orgs": ["org-a"]}])))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(path))
    dashboard_app.create_app(str(tmp_path / "store"))


@pytest.mark.parametrize("bad", ["Developer", "dev_box", "org_0123456789", "", "unattributed"])
def test_a_client_name_outside_the_intake_form_is_refused(bad):
    entries = [{"group": "g", "clients": [bad or "x" * 41]}]
    with pytest.raises(ValueError, match="`clients`"):
        Policy(raw=_raw(entries=entries)).entitlements()


def test_unattributed_is_never_a_client_partition():
    """It names the shared partition for records with no org."""
    policy = Policy(raw=_raw(clients=CLIENTS + [{"name": "unattributed", "token": "t"}]))
    assert "unattributed" not in policy.intake_client_names()
    assert policy.partition_pseudonym(("client", "unattributed")) is None


def test_a_grant_to_a_client_that_is_not_configured_is_refused():
    entries = [{"group": "g-dev", "orgs": ["org-a"], "clients": ["developer", "retired-box"]}]
    with pytest.raises(ValueError, match="retired-box"):
        Policy(raw=_raw(entries=entries)).entitlements()
    with pytest.raises(ValueError, match="not in intake.clients"):
        Policy(raw=_raw(entries=[{"group": "g", "clients": ["typo-box"]}])).entitlements()
