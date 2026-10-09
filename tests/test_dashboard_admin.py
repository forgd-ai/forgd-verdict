"""Changing runtime overrides from the dashboard.

Every refusal a POST can meet: no admins configured, an unverified identity, a
viewer outside the admin groups, a foreign or missing Origin, a missing,
forged, stale or replayed form token. Then what a change writes, and what the
pages show.
"""

from __future__ import annotations

import json
import logging
import re
import time
from urllib.parse import urlencode

import pytest
from conftest import DETECTORS, FAKE_GITHUB_TOKEN, OVERRIDES_KEY

from forgd_verdict.dashboard.admin import TOKEN_TTL_S, AdminConfig, TokenRefused
from forgd_verdict.dashboard.app import Dashboard, create_app
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.entitlements import MODE_NONE, MODE_OIDC_JWT, Principal
from forgd_verdict.overrides import (
    ACTION_DENY_DEVICE,
    ACTION_EXCLUDE,
    ACTION_INIT,
    ACTION_MIGRATE,
    ACTION_SET,
    CONTROL_IDENTITY_OFF,
    ENV_ENABLED,
    KEY_MODE,
    Change,
    RuntimeOverrides,
    apply_change,
    audit_name,
    parse_state,
)
from forgd_verdict.policy import Policy, redacted
from forgd_verdict.store import LocalFileStore, VerdictRecord
from forgd_verdict.store.base import FindingRow, StoreReadError

jwt = pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

ISSUER = "https://login.example/v2.0"
AUDIENCE = "api://forgd-dashboard"
ORIGIN = "https://dash.example.com"
KEY = "k" * 40
HEADER = "authorization"

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")


@pytest.fixture(scope="module")
def pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())


def _token(pem, **claims):
    body = {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "preferred_username": "dana",
            "groups": ["forgd-operators"], "exp": int(time.time()) + 600,
            "iat": int(time.time()) - 10}
    body.update(claims)
    return "Bearer " + jwt.encode({k: v for k, v in body.items() if v is not None},
                                  pem[1], algorithm="RS256")


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


def _admins(auth, **raw):
    return AdminConfig.parse({"groups": [{"group": "forgd-operators"}],
                              "allowed_origins": [ORIGIN], "form_key": KEY, **raw}, auth)


@pytest.fixture
def store(tmp_path):
    return LocalFileStore(tmp_path / "s", instance="t")


def _init(store):
    apply_change(store, {"name": "ops"}, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


def _app(store, auth, admins=True, baseline="observe"):
    overrides = RuntimeOverrides(store, "dashboard", baseline={KEY_MODE: baseline})
    overrides.refresh()
    return Dashboard(store, auth=auth, admins=_admins(auth) if admins else None,
                     overrides=overrides, baseline_mode=baseline)


async def _call(app, method, path, headers=None, body=b"", query=b""):
    sent = []
    chunks = [body]

    async def receive():
        return {"type": "http.request", "body": chunks.pop(0) if chunks else b"",
                "more_body": False}

    async def send(msg):
        sent.append(msg)

    raw = [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    await app({"type": "http", "method": method, "path": path, "query_string": query,
               "headers": raw}, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    out = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), out


def _principal(**kw):
    return Principal(name="dana", groups=("forgd-operators",), issuer=ISSUER,
                     subject="user-1", **kw)


def _form(app, action, key, value, revision=0, principal=None, issued=None):
    token = app.admins.mint(principal or _principal(), action, key, value, revision,
                            issued if issued is not None else int(time.time()))
    return urlencode({"action": action, "key": key, "value": value, "token": token}).encode()


def _headers(pem, **extra):
    base = {HEADER: _token(pem), "origin": ORIGIN,
            "content-type": "application/x-www-form-urlencoded"}
    base.update(extra)
    return {k: v for k, v in base.items() if v is not None}


def _mode(store):
    found = store.read_control()
    return parse_state(found.body).value(KEY_MODE) if found.status == "ok" else None


# -- off by default --------------------------------------------------------


async def test_without_admins_every_post_is_405(store, auth, pem):
    app = _app(store, auth, admins=False)
    for path in ("/admin/actions", "/", "/policy"):
        status, headers, _ = await _call(app, "POST", path, _headers(pem))
        assert status == 405
        assert headers[b"allow"] == b"GET, HEAD"
    assert store.read_control().status == "absent"


async def test_with_admins_other_methods_and_paths_stay_405(store, auth, pem):
    app = _app(store, auth)
    for method, path in (("POST", "/"), ("POST", "/policy"), ("PUT", "/admin/actions"),
                         ("DELETE", "/admin/actions"), ("PATCH", "/admin/actions")):
        status, _, _ = await _call(app, method, path, _headers(pem))
        assert status == 405, (method, path)


async def test_without_admins_the_policy_tab_has_no_controls(store, auth, pem):
    app = _app(store, auth, admins=False)
    status, headers, body = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert status == 200
    assert b'method="post"' not in body and b"Changed without a release" not in body
    assert b"Runtime overrides are not initialized" in body
    csp = headers[b"content-security-policy"]
    assert b"form-action 'self'" in csp and b"base-uri 'none'" in csp


def test_admins_absent_or_empty_is_off(auth):
    assert AdminConfig.parse(None, auth) is None
    assert AdminConfig.parse({}, auth) is None
    assert AdminConfig.parse({"groups": []}, auth) is None


# -- configuration refusals ------------------------------------------------


def test_admins_require_oidc_jwt():
    for mode in (MODE_NONE, "trusted_header"):
        cfg = AuthConfig(mode=mode)
        with pytest.raises(ValueError, match="oidc_jwt"):
            AdminConfig.parse({"groups": [{"group": "g"}], "allowed_origins": [ORIGIN],
                               "form_key": KEY}, cfg)


def test_admins_refuse_iap(auth):
    auth.platform = "iap"
    with pytest.raises(ValueError, match="iap"):
        _admins(auth)


def test_two_issuers_need_scoped_groups(pem, monkeypatch):
    cfg = AuthConfig.parse({"mode": MODE_OIDC_JWT, "header": HEADER, "issuers": [
        {"issuer": ISSUER, "jwks_url": "https://a.invalid/k", "audience": AUDIENCE},
        {"issuer": "https://other/", "jwks_url": "https://b.invalid/k", "audience": "x"}]})
    with pytest.raises(ValueError, match="issuer"):
        _admins(cfg)
    scoped = AdminConfig.parse({"groups": [{"group": "forgd-operators", "issuer": ISSUER}],
                                "allowed_origins": [ORIGIN], "form_key": KEY}, cfg)
    assert scoped.match(_principal()) == "forgd-operators"
    other = Principal(name="x", groups=("forgd-operators",), issuer="https://other/",
                      subject="s")
    assert scoped.match(other) is None


@pytest.mark.parametrize("raw,match", [
    ({"allowed_origins": []}, "allowed_origins"),
    ({"allowed_origins": ["https://dash.example.com/path"]}, "allowed_origins"),
    ({"form_key": ""}, "form_key"),
    ({"form_key": "short"}, "form_key"),
    ({"form_key": "$FORGD_DASHBOARD_FORM_KEY_UNSET_IN_TESTS"}, "form_key"),
])
def test_admins_refuse_to_start_without_origins_or_a_key(auth, raw, match):
    with pytest.raises(ValueError, match=match):
        _admins(auth, **raw)


def test_the_form_key_comes_from_the_environment(auth, monkeypatch):
    monkeypatch.setenv("FORGD_DASHBOARD_FORM_KEY", KEY)
    assert _admins(auth, form_key="$FORGD_DASHBOARD_FORM_KEY").form_key == KEY.encode()


def test_create_app_refuses_admins_without_a_form_key(tmp_path, monkeypatch):
    policy = tmp_path / "policy.yaml"
    policy.write_text(json.dumps({"dashboard": {
        "auth": {"mode": MODE_OIDC_JWT, "jwks_url": "https://x.invalid/k",
                 "issuer": ISSUER, "audience": AUDIENCE},
        "admins": {"groups": [{"group": "g"}], "allowed_origins": [ORIGIN],
                   "form_key": "$FORGD_DASHBOARD_FORM_KEY"}}}))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))
    monkeypatch.delenv("FORGD_DASHBOARD_FORM_KEY", raising=False)
    with pytest.raises(ValueError, match="form_key"):
        create_app(str(tmp_path / "s"))



def _admin_policy(tmp_path, monkeypatch):
    policy = tmp_path / "policy.yaml"
    policy.write_text(json.dumps({"dashboard": {
        "auth": {"mode": MODE_OIDC_JWT, "jwks_url": "https://x.invalid/k",
                 "issuer": ISSUER, "audience": AUDIENCE},
        "admins": {"groups": [{"group": "g"}], "allowed_origins": [ORIGIN],
                   "form_key": KEY}}}))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))


def _identity_off_warnings(caplog) -> list:
    return [r for r in caplog.records
            if r.levelno == logging.WARNING and r.getMessage() == CONTROL_IDENTITY_OFF]


def test_create_app_without_the_control_identity_starts_with_one_warning(tmp_path, monkeypatch,
                                                                         caplog):
    """Mutation: call enabled_in in place of honoured_in in create_app."""
    _admin_policy(tmp_path, monkeypatch)
    monkeypatch.delenv(ENV_ENABLED, raising=False)
    app = create_app(str(tmp_path / "s"))
    assert app.admins is not None
    assert app.overrides is None
    assert app.controls_off
    assert len(_identity_off_warnings(caplog)) == 1
    assert "dashboard admin controls enabled" not in caplog.text


def test_create_app_with_the_control_identity_honours_admins(tmp_path, monkeypatch, caplog):
    _admin_policy(tmp_path, monkeypatch)
    app = create_app(str(tmp_path / "s"))
    assert app.overrides is not None
    assert not app.controls_off
    assert _identity_off_warnings(caplog) == []


async def test_without_the_control_identity_an_admin_action_is_refused(store, auth, pem,
                                                                       caplog, monkeypatch):
    """Admins parsed, FORGD_OVERRIDES_ENABLED unset: an admin with a valid form
    token is refused, and no page offers a control.

    Mutation: drop the controls_off test from _admin_post, or from
    _admin_group, or compute controls_off without deployment_enabled."""
    monkeypatch.delenv(ENV_ENABLED, raising=False)
    app = _app(store, auth)
    status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                               _form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert status == 403
    assert _mode(store) is None
    assert [r["reason"] for r in _refusals(caplog)] == ["control_identity_off"]
    assert _refusals(caplog)[0]["detail"] == CONTROL_IDENTITY_OFF
    for path in ("/policy", "/events"):
        _, _, body = await _call(app, "GET", path, {HEADER: _token(pem)})
        assert b'method="post"' not in body

def test_the_form_key_is_redacted_on_the_policy_tab():
    out = redacted(Policy(raw={"dashboard": {"admins": {"form_key": KEY}}}),
                   hashes_here=False)
    assert out["dashboard"]["admins"]["form_key"] == "<redacted>"


# -- request refusals ------------------------------------------------------


async def test_a_foreign_or_missing_origin_is_refused(store, auth, pem):
    app = _app(store, auth)
    body = _form(app, ACTION_SET, KEY_MODE, "enforce")
    for origin in ("https://evil.example", None, "null", ORIGIN + ".evil.example"):
        status, _, _ = await _call(app, "POST", "/admin/actions",
                                   _headers(pem, origin=origin), body)
        assert status == 403, origin
    assert _mode(store) is None


async def test_a_cross_site_fetch_is_refused(store, auth, pem):
    app = _app(store, auth)
    status, _, _ = await _call(app, "POST", "/admin/actions",
                               _headers(pem, **{"sec-fetch-site": "cross-site"}),
                               _form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert status == 403
    assert _mode(store) is None


async def test_an_unverified_identity_is_refused(store, auth, pem):
    app = _app(store, auth)
    body = _form(app, ACTION_SET, KEY_MODE, "enforce")
    for header in (None, "Bearer forged", _token(pem, iss="https://other/")):
        status, _, _ = await _call(app, "POST", "/admin/actions",
                                   _headers(pem, **{HEADER: header}), body)
        assert status == 401, header
    assert _mode(store) is None


async def test_a_non_admin_is_refused(store, auth, pem):
    app = _app(store, auth)
    status, _, _ = await _call(app, "POST", "/admin/actions",
                               _headers(pem, **{HEADER: _token(pem, groups=["viewers"])}),
                               _form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert status == 403
    assert _mode(store) is None


@pytest.mark.parametrize("signal", [{"hasgroups": True},
                                    {"_claim_names": {"groups": "src1"}}])
async def test_incomplete_groups_are_refused_even_with_the_admin_group(store, auth, pem, signal):
    """The token lists the admin group and carries an overage signal.
    Mutation: drop the incomplete check in `_admin_post`."""
    app = _app(store, auth)
    token = _token(pem, groups=["forgd-operators"], **signal)
    principal = app.auth.authenticate({HEADER: token})
    assert app.admins.match(principal) == "forgd-operators" and principal.groups_incomplete
    status, _, _ = await _call(app, "POST", "/admin/actions",
                               _headers(pem, **{HEADER: token}),
                               _form(app, ACTION_SET, KEY_MODE, "enforce",
                                     principal=principal))
    assert status == 403
    assert _mode(store) is None
    _, _, page = await _call(app, "GET", "/policy", {HEADER: token})
    assert b'action="/admin/actions"' not in page


async def test_a_token_without_a_subject_is_refused(store, auth, pem):
    app = _app(store, auth)
    status, _, _ = await _call(app, "POST", "/admin/actions",
                               _headers(pem, **{HEADER: _token(pem, sub=None)}),
                               _form(app, ACTION_SET, KEY_MODE, "enforce",
                                     principal=_principal().__class__(
                                         name="dana", groups=("forgd-operators",),
                                         issuer=ISSUER, subject="")))
    assert status == 403


async def test_a_missing_form_token_is_refused(store, auth, pem):
    app = _app(store, auth)
    body = urlencode({"action": ACTION_SET, "key": KEY_MODE, "value": "enforce"}).encode()
    status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem), body)
    assert status == 400
    assert _mode(store) is None


@pytest.mark.parametrize("tamper", ["forged", "expired", "other_user", "other_value",
                                    "other_action", "other_key"])
async def test_a_bad_form_token_is_refused(store, auth, pem, tamper):
    app = _app(store, auth)
    now = int(time.time())
    kwargs = {"principal": None, "issued": now}
    if tamper == "expired":
        kwargs["issued"] = now - TOKEN_TTL_S - 1
    if tamper == "other_user":
        kwargs["principal"] = Principal(name="eve", groups=("forgd-operators",),
                                        issuer=ISSUER, subject="user-2")
    body = dict(action=ACTION_SET, key=KEY_MODE, value="enforce")
    token = app.admins.mint(kwargs["principal"] or _principal(), body["action"],
                            body["key"], body["value"], 0, kwargs["issued"])
    if tamper == "forged":
        token = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    if tamper == "other_value":
        body["value"] = "observe"
    if tamper == "other_action":
        body["action"] = "override.clear"
    if tamper == "other_key":
        body["key"] = "stats_reset"
    status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                               urlencode({**body, "token": token}).encode())
    assert status == 403, tamper
    assert _mode(store) is None


async def test_a_wrong_content_type_or_a_large_body_is_refused(store, auth, pem):
    app = _app(store, auth)
    body = _form(app, ACTION_SET, KEY_MODE, "enforce")
    status, _, _ = await _call(app, "POST", "/admin/actions",
                               _headers(pem, **{"content-type": "application/json"}), body)
    assert status == 415
    status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                               body + b"&pad=" + b"x" * 5000)
    assert status == 413
    assert _mode(store) is None


# -- a change --------------------------------------------------------------


def _requests(store):
    return [json.loads(store.get_audit(n)) for n in store.list_audit()
            if n.endswith("-request.json")]


async def test_an_uninitialized_store_offers_only_init(store, auth, pem):
    app = _app(store, auth)
    _, _, page = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert b"Runtime overrides are not initialized" in page
    assert b'name="action" value="state.init"' in page
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert (status, headers[b"location"]) == (303, b"/policy?result=refused")
    assert store.list_audit() == []
    assert store.read_control().status == "absent"

    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_INIT, "", ""))
    assert (status, headers[b"location"]) == (303, b"/policy?result=applied")
    assert parse_state(store.read_control().body).revision == 1
    assert [(r["action"], r["principal"]["subject"]) for r in _requests(store)] == [
        (ACTION_INIT, "user-1")]
    assert app.overrides.current().ready
    _, _, page = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert b"Runtime overrides are not initialized" not in page
    assert b'name="action" value="state.init"' not in page
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_SET, KEY_MODE, "enforce", 1))
    assert headers[b"location"] == b"/policy?result=applied"
    assert _mode(store) == "enforce"


async def test_an_admin_change_writes_a_verification_naming_its_head(tmp_path, auth, pem,
                                                                    monkeypatch):
    """Mutation: pass no after_write from the dashboard's admin action."""
    from conftest import OVERRIDES_PUBLIC

    from forgd_verdict import lockout
    from forgd_verdict.overrides import anchor_of

    store = LocalFileStore(tmp_path / "s", instance="t")
    _init(store)
    overrides = RuntimeOverrides(store, "dashboard", baseline={KEY_MODE: "observe"},
                                 verify_keys=(OVERRIDES_PUBLIC,))
    overrides.refresh()
    app = Dashboard(store, auth=auth, admins=_admins(auth), overrides=overrides,
                    baseline_mode="observe", signing_key=OVERRIDES_KEY)
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_SET, KEY_MODE, "enforce", 1))
    assert headers[b"location"] == b"/policy?result=applied"
    head = anchor_of(parse_state(store.read_control().body))
    assert head["revision"] == 2
    assert lockout.anchored_head(store, (OVERRIDES_PUBLIC,)) == head


async def test_an_admin_change_is_applied_and_audited(store, auth, pem):
    _init(store)
    app = _app(store, auth)
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_SET, KEY_MODE, "enforce", 1))
    assert status == 303
    assert headers[b"location"] == b"/policy?result=applied"
    assert _mode(store) == "enforce"
    requests = [r for r in _requests(store) if r["action"] == ACTION_SET]
    assert len(requests) == 1
    assert requests[0]["principal"] == {"issuer": ISSUER, "subject": "user-1",
                                        "name": "dana", "via_group": "forgd-operators",
                                        "verified": True}
    for name in store.list_audit():
        text = store.get_audit(name).decode()
        # A JWT is `eyJ<header>.eyJ<payload>.<signature>`. A bare "eyJ"
        # also turns up by chance in the record's random base64url signature.
        assert not re.search(r"eyJ[\w-]*\.eyJ[\w-]*\.", text)
        assert "token" not in text and KEY not in text
    from conftest import OVERRIDES_KEY_TEXT, OVERRIDES_PUBLIC

    from forgd_verdict import overrides_signing

    assert overrides_signing.verify(requests[0], [OVERRIDES_PUBLIC])
    for name in store.list_audit():
        assert OVERRIDES_KEY_TEXT not in store.get_audit(name).decode()


async def test_an_admin_change_without_a_signing_key_is_refused(store, auth, pem,
                                                                 monkeypatch):
    _init(store)
    app = _app(store, auth)
    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    before = sorted(store.list_audit())
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_SET, KEY_MODE, "enforce", 1))
    assert (status, headers[b"location"]) == (303, b"/policy?result=refused")
    assert sorted(store.list_audit()) == before and _mode(store) is None


@pytest.mark.parametrize("action,key,value", [
    ("exclusion.add", "excluded_requests", FAKE_GITHUB_TOKEN),
    ("exclusion.add", "excluded_requests", f"PreToolUse:Bash:{FAKE_GITHUB_TOKEN}"),
    ("override.set", "server.mode", FAKE_GITHUB_TOKEN),
])
async def test_a_form_value_a_detector_matches_is_refused(store, auth, pem, caplog,
                                                          action, key, value):
    """Mutation: drop the screen at the top of apply_change."""
    app = _app(store, auth)
    with caplog.at_level("DEBUG"):
        status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                         _form(app, action, key, value))
    assert status == 303
    assert headers[b"location"] == b"/policy?result=refused"
    assert store.list_audit() == []
    assert store.read_control().status != "ok"
    assert FAKE_GITHUB_TOKEN not in caplog.text + json.dumps(
        [getattr(r, "fields", {}) for r in caplog.records], default=str)
    refused = [r for r in caplog.records if r.getMessage() == "dashboard admin action refused"]
    assert "matched a detector: " in refused[-1].fields["detail"]


async def test_a_token_is_single_use(store, auth, pem):
    _init(store)
    app = _app(store, auth)
    body = _form(app, ACTION_SET, KEY_MODE, "enforce", 1)
    assert (await _call(app, "POST", "/admin/actions", _headers(pem), body))[0] == 303
    apply_change(store, {"name": "x"}, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem), body)
    assert headers[b"location"] == b"/policy?result=conflict"
    assert _mode(store) == "observe"


def test_a_token_verifies_only_its_own_fields(auth):
    admins = _admins(auth)
    now = int(time.time())
    token = admins.mint(_principal(), ACTION_SET, KEY_MODE, "enforce", 4, now)
    assert admins.verify(token, _principal(), ACTION_SET, KEY_MODE, "enforce", now) == 4
    with pytest.raises(TokenRefused):
        admins.verify(token, _principal(), ACTION_SET, KEY_MODE, "observe", now)
    rotated = AdminConfig(admins.groups, admins.allowed_origins, b"n" * 40)
    with pytest.raises(TokenRefused):
        rotated.verify(token, _principal(), ACTION_SET, KEY_MODE, "enforce", now)


# -- pages -----------------------------------------------------------------


async def test_admins_see_controls_and_viewers_do_not(store, auth, pem):
    app = _app(store, auth)
    _, headers, admin = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert b'action="/admin/actions"' in admin
    assert b"form-action 'self'" in headers[b"content-security-policy"]
    _, _, viewer = await _call(app, "GET", "/policy",
                               {HEADER: _token(pem, groups=["viewers"])})
    assert b"Runtime overrides" in viewer and b'method="post"' not in viewer


async def test_recent_changes_flag_an_overwritten_record(store, auth, pem):
    _init(store)
    apply_change(store, {"name": "x"}, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    middle = apply_change(store, {"name": "x"}, Change(ACTION_EXCLUDE, value="req_1"),
                          detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, {"name": "x"}, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    flag = b"does not match the audit chain"
    app = _app(store, auth)
    _, _, body = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert b"Recent changes" in body and flag not in body
    path = store.root / "audit" / "runtime-overrides" / audit_name(middle.audit_id, "request")
    path.write_bytes(path.read_bytes().replace(b"req_1", b"req_2"))
    app.overrides.refresh()
    _, _, body = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert body.count(flag) == 1
    assert b"overwritten or forged" in body
    _, _, cold = await _call(_app(store, auth), "GET", "/policy", {HEADER: _token(pem)})
    assert b"Runtime overrides are invalid" in cold


async def test_the_durability_warning(store, auth, pem):
    _init(store)
    apply_change(store, {"name": "x"}, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    text = b"enforce only because of a runtime override"
    app = _app(store, auth, baseline="observe")
    for path in ("/policy", "/"):
        _, _, body = await _call(app, "GET", path, {HEADER: _token(pem)})
        assert text in body, path
    _, _, body = await _call(_app(store, auth, baseline="enforce"), "GET", "/policy",
                             {HEADER: _token(pem)})
    assert text not in body
    apply_change(store, {"name": "x"}, Change("override.clear", KEY_MODE), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _, _, body = await _call(_app(store, auth), "GET", "/policy", {HEADER: _token(pem)})
    assert text not in body


async def test_an_unreadable_object_is_bannered(store, auth, pem, monkeypatch):
    _init(store)
    apply_change(store, {"name": "x"}, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    app = _app(store, auth)

    def fail():
        raise StoreReadError("denied")

    monkeypatch.setattr(app.overrides.store, "read_control", fail)
    app.overrides.refresh()
    _, _, body = await _call(app, "GET", "/", {HEADER: _token(pem)})
    assert b"Runtime overrides could not be read; keeping the values last read" in body


async def test_the_event_log_offers_exclusion_to_admins(store, auth, pem):
    store.write_verdicts([VerdictRecord(
        source="inference_hook", observed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        request_id="req_visible", action="allow", findings_count=1,
        findings=[FindingRow("t0_regex", "block", "m0:0-4", "a" * 64)])])
    _init(store)
    app = _app(store, auth)
    _, _, admin = await _call(app, "GET", "/events", {HEADER: _token(pem)})
    assert b'name="value" value="req_visible"' in admin
    _, _, viewer = await _call(app, "GET", "/events",
                               {HEADER: _token(pem, groups=["viewers"])})
    assert b"req_visible" in viewer and b'method="post"' not in viewer
    status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                               _form(app, ACTION_EXCLUDE, "excluded_requests", "req_visible", 1))
    assert status == 303
    assert parse_state(store.read_control().body).excluded_requests == {"req_visible"}


async def test_the_event_log_offers_to_deny_an_intake_device_to_admins(store, auth, pem):
    store.write_verdicts([VerdictRecord(
        source="code_hook", observed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        request_id="req_fleet", action="deny", findings_count=1, client="corp-laptops",
        device="d000000000042", findings=[FindingRow("t0_regex", "block", "m0:0-4", "a" * 64)])])
    _init(store)
    app = _app(store, auth)
    _, _, admin = await _call(app, "GET", "/events", {HEADER: _token(pem)})
    assert b'name="action" value="device.deny"' in admin
    assert b'name="value" value="d000000000042"' in admin
    _, _, viewer = await _call(app, "GET", "/events",
                               {HEADER: _token(pem, groups=["viewers"])})
    assert b"d000000000042" in viewer and b"device.deny" not in viewer
    status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                               _form(app, ACTION_DENY_DEVICE, "denied_devices", "d000000000042", 1))
    assert status == 303
    state = parse_state(store.read_control().body)
    assert state.denied_devices == {"d000000000042"}
    app.overrides.refresh()
    _, _, after = await _call(_app(store, auth), "GET", "/events", {HEADER: _token(pem)})
    assert b'name="value" value="d000000000042"' not in after
    assert b"denied" in after


async def test_with_the_feature_off_every_page_is_byte_identical(store, auth, pem, monkeypatch):
    """No admins, so no overrides reader, as create_app builds it with the
    feature off: the pages are exactly those of a dashboard built without
    runtime overrides at all."""
    import sys

    for name, mod in list(sys.modules.items()):
        if name.startswith("forgd_verdict") and callable(getattr(mod, "utcnow", None)):
            monkeypatch.setattr(mod, "utcnow", lambda: "2026-09-28T00:00:00Z")
    plain = Dashboard(store, auth=auth)
    featured = Dashboard(store, auth=auth, admins=None, overrides=None, baseline_mode="observe")
    for path in ("/", "/policy", "/events", "/api/summary"):
        a = await _call(plain, "GET", path, {HEADER: _token(pem)})
        b = await _call(featured, "GET", path, {HEADER: _token(pem)})
        assert a[0] == 200, path
        assert a == b, path


async def test_a_refusal_never_logs_a_raw_action_or_origin(store, auth, pem, caplog):
    """Mutation: log the unknown action, or an origin that is not one."""
    app = _app(store, auth)
    body = urlencode({"action": FAKE_GITHUB_TOKEN, "key": "", "value": "", "token": "x"}).encode()
    with caplog.at_level("DEBUG"):
        status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem), body)
        assert status == 400
        status, _, _ = await _call(app, "POST", "/admin/actions",
                                   _headers(pem, origin=f"https://x/{FAKE_GITHUB_TOKEN}"),
                                   _form(app, ACTION_SET, KEY_MODE, "enforce"))
        assert status == 403
        status, _, _ = await _call(app, "POST", "/admin/actions",
                                   _headers(pem, origin="https://evil.example"),
                                   _form(app, ACTION_SET, KEY_MODE, "enforce"))
        assert status == 403
    logged = caplog.text + json.dumps([getattr(r, "fields", {}) for r in caplog.records],
                                      default=str)
    assert FAKE_GITHUB_TOKEN not in logged
    origins = [r.fields.get("origin") for r in caplog.records
               if getattr(r, "fields", {}).get("reason") == "origin"]
    assert origins == ["malformed", "https://evil.example"]



def _logged(caplog) -> str:
    return caplog.text + json.dumps([getattr(r, "fields", {}) for r in caplog.records], default=str)


def _refusals(caplog) -> list[dict]:
    return [r.fields for r in caplog.records if r.getMessage() == "dashboard admin action refused"]


def _salted(tmp_path, monkeypatch, salt):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"privacy": {"hash_salt": salt}}))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))


async def test_a_refusal_logs_a_matched_name_as_a_pseudonym_and_the_detector(store, auth, pem,
                                                                             caplog, tmp_path,
                                                                             monkeypatch):
    """A token whose preferred_username a detector matches, refused as a
    non-admin and for a bad form token, with a salt configured. Mutation:
    log `who` unscreened."""
    _salted(tmp_path, monkeypatch, "a-made-up-test-salt")
    app = _app(store, auth)
    token = _token(pem, preferred_username=FAKE_GITHUB_TOKEN, groups=["viewers"])
    admin_token = _token(pem, preferred_username=FAKE_GITHUB_TOKEN)
    with caplog.at_level("DEBUG"):
        status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem, **{HEADER: token}),
                                   _form(app, ACTION_SET, KEY_MODE, "enforce"))
        assert status == 403
        body = urlencode({"action": ACTION_SET, "key": KEY_MODE, "value": "enforce",
                          "token": "forged"}).encode()
        status, _, _ = await _call(app, "POST", "/admin/actions",
                                   _headers(pem, **{HEADER: admin_token}), body)
        assert status == 403
    assert FAKE_GITHUB_TOKEN not in _logged(caplog)
    refusals = _refusals(caplog)
    assert [f["reason"] for f in refusals] == ["not_admin", "token"]
    whos = {f["who"] for f in refusals}
    assert len(whos) == 1 and next(iter(whos)).startswith("who"), whos
    for f in refusals:
        assert "regex:github-token" in f["who_matched"], f


async def test_without_a_salt_a_matched_name_is_withheld(store, auth, pem, caplog, tmp_path,
                                                         monkeypatch):
    """With privacy.hash_salt empty, a pseudonym would be a truncated bare
    sha256. Mutation: log the pseudonym without a salt."""
    _salted(tmp_path, monkeypatch, "")
    app = _app(store, auth)
    token = _token(pem, preferred_username=FAKE_GITHUB_TOKEN, groups=["viewers"])
    with caplog.at_level("DEBUG"):
        status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem, **{HEADER: token}),
                                   _form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert status == 403
    assert FAKE_GITHUB_TOKEN not in _logged(caplog)
    [refusal] = _refusals(caplog)
    assert refusal["who"] == "<withheld>" and "regex:github-token" in refusal["who_matched"]


async def test_a_refusal_logs_a_clean_name_as_it_is(store, auth, pem, caplog):
    app = _app(store, auth)
    with caplog.at_level("DEBUG"):
        await _call(app, "POST", "/admin/actions",
                    _headers(pem, **{HEADER: _token(pem, groups=["viewers"])}),
                    _form(app, ACTION_SET, KEY_MODE, "enforce"))
    [refusal] = _refusals(caplog)
    assert refusal["who"] == "dana" and "who_matched" not in refusal


async def test_a_refusal_withholds_the_name_when_it_cannot_be_scanned(store, auth, pem, caplog,
                                                                     monkeypatch):
    """Mutation: log `who` when the detectors cannot be built."""
    def broken():
        raise RuntimeError("no policy")

    monkeypatch.setattr("forgd_verdict.policy.load_policy", broken)
    app = _app(store, auth)
    token = _token(pem, preferred_username=FAKE_GITHUB_TOKEN, groups=["viewers"])
    with caplog.at_level("DEBUG"):
        status, _, _ = await _call(app, "POST", "/admin/actions", _headers(pem, **{HEADER: token}),
                                   _form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert status == 403
    assert FAKE_GITHUB_TOKEN not in _logged(caplog)
    [refusal] = _refusals(caplog)
    assert refusal["who"] == "<withheld>" and refusal["who_unscanned"] is True


ORG_ID = "00000000-0000-4000-8000-00000000c0de"


@pytest.mark.parametrize("section", [
    {"orgs": [{"id": "$FORGD_ORG_ID_PROD"}]},
    {"compliance": {"orgs": [{"id": "$FORGD_ORG_ID_PROD"}]}},
    {"otel": {"orgs": [{"id": "$FORGD_ORG_ID_PROD"}]}},
], ids=["orgs", "compliance", "otel.orgs"])
async def test_an_org_id_is_refused_as_an_exclusion(store, auth, pem, caplog, monkeypatch,
                                                    tmp_path, section):
    """Mutation: pass the dashboard's apply_change no org ids."""
    monkeypatch.setenv("FORGD_ORG_ID_PROD", ORG_ID)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(section))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))
    app = _app(store, auth)
    with caplog.at_level("DEBUG"):
        status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                         _form(app, ACTION_EXCLUDE, "excluded_requests", ORG_ID))
    assert (status, headers[b"location"]) == (303, b"/policy?result=refused")
    assert store.list_audit() == []
    [refusal] = _refusals(caplog)
    assert "configured organization id" in refusal["detail"]
    assert ORG_ID not in _logged(caplog)


async def test_the_legacy_markers_banner_shows_until_they_are_retired(store, auth, pem):
    """Mutation: drop the banner, or keep it after migrate-markers. Before
    any object is adopted the markers are not applied, and the banner says
    so."""
    app = _app(store, auth)
    _, _, page = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert b"are not applied" in page and b"markers/excluded_requests" in page
    assert b"overrides migrate-markers" not in page
    _init(store)
    apply_change(store, {"name": "ops"}, Change(ACTION_SET, KEY_MODE, "enforce"),
                 detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    app.overrides.refresh()
    app._cache.clear()
    _, _, page = await _call(app, "GET", "/", {HEADER: _token(pem)})
    assert b"overrides migrate-markers" in page
    apply_change(store, {"name": "ops"}, Change(ACTION_MIGRATE), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    app.overrides.refresh()
    app._cache.clear()
    for path in ("/", "/policy", "/events"):
        _, _, page = await _call(app, "GET", path, {HEADER: _token(pem)})
        assert b"overrides migrate-markers" not in page, path


def test_create_app_signs_verifications_and_checks_them_with_the_policy_keys(tmp_path,
                                                                            monkeypatch):
    """Mutation: start the verifier without the signing key, or read the
    fleet without the verify keys."""
    from conftest import OVERRIDES_PUBLIC

    from forgd_verdict import lockout, overrides_signing

    _admin_policy(tmp_path, monkeypatch)
    app = create_app(str(tmp_path / "s"))
    assert [overrides_signing.key_id(k) for k in app.lockout.verify_keys] == [
        overrides_signing.key_id(OVERRIDES_PUBLIC)]
    app.verifier.once()
    [path] = (tmp_path / "s").rglob(f"{lockout.VERIFY_PREFIX}*.json")
    record = json.loads(path.read_text())
    assert overrides_signing.verify(record, [OVERRIDES_PUBLIC]) == overrides_signing.key_id(
        OVERRIDES_PUBLIC)


def test_create_app_names_its_own_verified_head_in_each_verification(tmp_path, monkeypatch):
    """Mutation: start the verifier without `trusted`."""
    from forgd_verdict import lockout
    from forgd_verdict.overrides import anchor_of

    _admin_policy(tmp_path, monkeypatch)
    app = create_app(str(tmp_path / "s"))
    store = app.overrides.store
    _init(store)
    apply_change(store, {"name": "ops"}, Change(ACTION_SET, KEY_MODE, "enforce"),
                 detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    app.overrides.refresh()
    held = app.overrides.current().state
    assert held is not None and held.revision == 2
    app.verifier.once()
    [path] = (tmp_path / "s").rglob(f"{lockout.VERIFY_PREFIX}*.json")
    assert json.loads(path.read_text())["head"] == anchor_of(held)
