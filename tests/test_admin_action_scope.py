"""Every dashboard admin action is authorised against the orgs it affects.

A request exclusion or a device deny affects the orgs of the records that
carry that request id or device; every other action affects every org. An
admin entitled to some orgs may apply the first kind only to values whose
records are all in their orgs, and the second kind not at all. The Policy
tab lists, and offers forms for, only what they may change.
"""

from __future__ import annotations

import re
import time

import pytest
from conftest import DETECTORS, OVERRIDES_KEY
from test_dashboard_admin import (
    AUDIENCE,
    HEADER,
    ISSUER,
    _admins,
    _call,
    _form,
    _headers,
    _token,
)

from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.entitlements import MODE_OIDC_JWT, Entitlements, Principal
from forgd_verdict.overrides import (
    ACTION_CLEAR,
    ACTION_CLEAR_ALL,
    ACTION_DENY_CLEAR,
    ACTION_DENY_DEVICE,
    ACTION_EXCLUDE,
    ACTION_EXCLUDE_CLEAR,
    ACTION_INIT,
    ACTION_RECOVER,
    ACTION_RESET,
    ACTION_RESET_CLEAR,
    ACTION_SET,
    ACTION_UNDENY_DEVICE,
    ACTION_UNEXCLUDE,
    DASHBOARD_ACTIONS,
    DEPLOYMENT_ACTIONS,
    KEY_MODE,
    SCOPED_ACTIONS,
    Change,
    RuntimeOverrides,
    apply_change,
    parse_state,
)
from forgd_verdict.store import FindingRow, LocalFileStore, VerdictRecord

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")

A, B = "org_aaaaaaaaaa", "org_bbbbbbbbbb"
REQ_A, REQ_B, REQ_AB = "req-org-a-0001", "req-org-b-0001", "req-both-0001"
DEV_A, DEV_B = "d00000000000a", "d00000000000b"
ENTITLEMENTS = Entitlements(by_group={"org-a-viewers": frozenset({A}),
                                      "org-b-viewers": frozenset({B})})

# The form each action takes from a scoped admin who is entitled to org A:
# (key, value) for one that may be applied, and for one that may not.
FORMS = {
    ACTION_EXCLUDE: ("excluded_requests", "req-org-a-0002", REQ_B),
    ACTION_UNEXCLUDE: ("excluded_requests", REQ_A, REQ_B),
    ACTION_DENY_DEVICE: ("denied_devices", DEV_A, DEV_B),
    ACTION_UNDENY_DEVICE: ("denied_devices", DEV_A, DEV_B),
    ACTION_SET: (KEY_MODE, None, "enforce"),
    ACTION_CLEAR: (KEY_MODE, None, ""),
    ACTION_CLEAR_ALL: ("", None, ""),
    ACTION_RESET: ("stats_reset", None, ""),
    ACTION_RESET_CLEAR: ("stats_reset", None, ""),
    ACTION_EXCLUDE_CLEAR: ("excluded_requests", None, ""),
    ACTION_DENY_CLEAR: ("denied_devices", None, ""),
    ACTION_RECOVER: ("", None, ""),
    ACTION_INIT: ("", None, ""),
}


@pytest.fixture(scope="module")
def pem():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())


@pytest.fixture
def auth(pem, monkeypatch):
    cfg = AuthConfig.parse({"mode": MODE_OIDC_JWT, "header": HEADER,
                            "jwks_url": "https://example.invalid/keys",
                            "issuer": ISSUER, "audience": AUDIENCE})

    class _Signing:
        key = pem[0].public_key()

    class _Client:
        def get_signing_key_from_jwt(self, _token):
            return _Signing()

    monkeypatch.setattr(cfg, "_keys", lambda *_: _Client())
    return cfg


@pytest.fixture
def store(tmp_path):
    return LocalFileStore(tmp_path / "s", instance="t")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _seed(store) -> None:
    def rec(org, request_id, device=None):
        return VerdictRecord(source="code_hook", observed_at=_now(), tenant_hash=org,
                             request_id=request_id, device=device, client="laptops",
                             action="deny", findings_count=1,
                             findings=[FindingRow("t0_regex", "block", "prompt", "a" * 64)])
    store.write_verdicts([rec(A, REQ_A, DEV_A), rec(B, REQ_B, DEV_B), rec(A, REQ_AB),
                          rec(B, REQ_AB), rec(A, "req-org-a-0002", DEV_A)])
    actor = {"name": "ops"}
    apply_change(store, actor, Change(ACTION_INIT), detectors=DETECTORS,
                 signing_key=OVERRIDES_KEY)
    for value in (REQ_A, REQ_B, REQ_AB):
        apply_change(store, actor, Change(ACTION_EXCLUDE, value=value),
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    for value in (DEV_A, DEV_B):
        apply_change(store, actor, Change(ACTION_DENY_DEVICE, value=value),
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY,
                     writer_version="0.46.0")


def _app(store, auth):
    overrides = RuntimeOverrides(store, "dashboard", baseline={KEY_MODE: "observe"})
    overrides.refresh()
    return Dashboard(store, auth=auth, admins=_admins(auth), overrides=overrides,
                     baseline_mode="observe", entitlements=ENTITLEMENTS)


def _alice(groups=("forgd-operators", "org-a-viewers")):
    return Principal(name="dana", groups=groups, issuer=ISSUER, subject="user-1")


def _revision(store) -> int:
    return parse_state(store.read_control().body).revision


def test_every_dashboard_action_is_classified():
    assert set(SCOPED_ACTIONS) | DEPLOYMENT_ACTIONS == DASHBOARD_ACTIONS
    assert not set(SCOPED_ACTIONS) & DEPLOYMENT_ACTIONS
    assert set(FORMS) == DASHBOARD_ACTIONS


@pytest.mark.parametrize("action", sorted(DASHBOARD_ACTIONS))
async def test_a_scoped_admin_cannot_apply_an_action_outside_their_orgs(store, auth, pem,
                                                                        action):
    _seed(store)
    app = _app(store, auth)
    key, _, outside = FORMS[action]
    before = store.read_control().body
    status, _, _ = await _call(
        app, "POST", "/admin/actions",
        _headers(pem, **{HEADER: _token(pem, groups=["forgd-operators", "org-a-viewers"])}),
        _form(app, action, key, outside, _revision(store), principal=_alice()))
    assert status == 403
    assert store.read_control().body == before


@pytest.mark.parametrize("action", sorted(SCOPED_ACTIONS))
async def test_a_scoped_admin_can_apply_an_action_inside_their_orgs(store, auth, pem, action):
    _seed(store)
    if action in (ACTION_DENY_DEVICE,):
        apply_change(store, {"name": "ops"}, Change(ACTION_UNDENY_DEVICE, value=DEV_A),
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    app = _app(store, auth)
    key, inside, _ = FORMS[action]
    status, headers, _ = await _call(
        app, "POST", "/admin/actions",
        _headers(pem, **{HEADER: _token(pem, groups=["forgd-operators", "org-a-viewers"])}),
        _form(app, action, key, inside, _revision(store), principal=_alice()))
    assert status == 303 and headers[b"location"] == b"/policy?result=applied"


async def test_a_request_id_in_two_orgs_needs_both(store, auth, pem):
    _seed(store)
    app = _app(store, auth)
    form = _form(app, ACTION_UNEXCLUDE, "excluded_requests", REQ_AB, _revision(store),
                 principal=_alice())
    status, _, _ = await _call(
        app, "POST", "/admin/actions",
        _headers(pem, **{HEADER: _token(pem, groups=["forgd-operators", "org-a-viewers"])}),
        form)
    assert status == 403
    both = ("forgd-operators", "org-a-viewers", "org-b-viewers")
    status, _, _ = await _call(
        app, "POST", "/admin/actions",
        _headers(pem, **{HEADER: _token(pem, groups=list(both))}),
        _form(app, ACTION_UNEXCLUDE, "excluded_requests", REQ_AB, _revision(store),
              principal=_alice(both)))
    assert status == 303


async def test_an_admin_of_every_org_may_apply_a_deployment_action(store, auth, pem):
    _seed(store)
    app = _app(store, auth)
    both = ("forgd-operators", "org-a-viewers", "org-b-viewers")
    status, headers, _ = await _call(
        app, "POST", "/admin/actions",
        _headers(pem, **{HEADER: _token(pem, groups=list(both))}),
        _form(app, ACTION_EXCLUDE_CLEAR, "excluded_requests", "", _revision(store),
              principal=_alice(both)))
    assert status == 303 and headers[b"location"] == b"/policy?result=applied"
    assert parse_state(store.read_control().body).excluded_requests == set()


async def test_the_policy_tab_shows_a_scoped_admin_only_their_orgs(store, auth, pem):
    _seed(store)
    app = _app(store, auth)
    _, _, body = await _call(app, "GET", "/policy", {
        HEADER: _token(pem, groups=["forgd-operators", "org-a-viewers"])})
    html = body.decode()
    values = set(re.findall(r'name="value" value="([^"]*)"', html))
    actions = set(re.findall(r'name="action" value="([^"]*)"', html))
    assert values == {REQ_A, DEV_A}
    assert actions == {ACTION_UNEXCLUDE, ACTION_UNDENY_DEVICE}
    for hidden in (REQ_B, REQ_AB, DEV_B):
        assert hidden not in html
    assert "more outside the organizations you may read" in html


async def test_the_event_log_offers_a_scoped_admin_only_their_values(store, auth, pem):
    _seed(store)
    shared_device = "d00000000000c"
    store.write_verdicts([
        VerdictRecord(source="code_hook", observed_at=_now(), tenant_hash=org,
                      request_id="req-both-0002", device=shared_device, client="laptops",
                      action="deny", findings_count=1,
                      findings=[FindingRow("t0_regex", "block", "prompt", "a" * 64)])
        for org in (A, B)])
    app = _app(store, auth)
    _, _, body = await _call(app, "GET", "/events", {
        HEADER: _token(pem, groups=["forgd-operators", "org-a-viewers"])},
        query=b"window=7d")
    html = body.decode()
    assert "req-both-0002" in html and shared_device in html
    values = set(re.findall(r'name="value" value="([^"]*)"', html))
    assert "req-both-0002" not in values and shared_device not in values
    assert "req-org-a-0002" in values
