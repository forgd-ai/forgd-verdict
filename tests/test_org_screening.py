"""Configured org ids in runtime overrides values.

Every org id in a principal is replaced with its salted pseudonym before an
audit record is built, and every principal, key, value and request id the
dashboard, its logs and the CLI show goes through the same screen
(`overrides.OrgScreen`), compared without case.
"""

from __future__ import annotations

import json
import logging

import pytest
from conftest import DETECTORS, OVERRIDES_KEY
from test_dashboard_admin import (  # noqa: F401 - fixtures
    HEADER,
    ISSUER,
    KEY,
    ORIGIN,
    _app,
    _call,
    _form,
    _headers,
    _init,
    _logged,
    _refusals,
    _token,
    auth,
    pem,
)
from test_legacy_exclusion_display import _frames, _list
from test_overrides_services import ORG_ID

from forgd_verdict import overrides as ov
from forgd_verdict.entitlements import Principal
from forgd_verdict.models import pseudonym
from forgd_verdict.overrides import (
    ACTION_INIT,
    ACTION_SET,
    KEY_MODE,
    WITHHELD_ORG,
    WITHHELD_UNSCANNED,
    Change,
    OrgScreen,
    apply_change,
)
from forgd_verdict.store import LocalFileStore

SALT = "test-salt-7f3a9c2e5b1d4a8f"  # gitleaks:allow
PSEUDONYM = pseudonym(ORG_ID.lower(), SALT, "org")
ORGS = {"orgs": [{"id": "$FORGD_ORG_ID_PROD", "label": "prod"}], "privacy": {"hash_salt": SALT}}
ADMINS = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}}}
PRINCIPAL_FIELDS = ("name", "subject", "issuer", "via_group")

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")


@pytest.fixture(autouse=True)
def org_env(monkeypatch):
    monkeypatch.setenv("FORGD_ORG_ID_PROD", ORG_ID)


@pytest.fixture
def store(tmp_path):
    return LocalFileStore(tmp_path / "s", instance="t")


def _policy_file(tmp_path, monkeypatch, raw):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(raw))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(path))
    return path


def _raw_in(text: str) -> bool:
    return ORG_ID.lower() in text.lower()


def _stored(store) -> str:
    """Every byte the store holds, as text."""
    return "".join(p.read_text(errors="replace") for p in store.root.rglob("*") if p.is_file())


def _actor(**fields):
    return {"issuer": ISSUER, "subject": "user-1", "name": "dana", "via_group": "ops",
            "verified": True, **fields}


# -- the screen ------------------------------------------------------------


@pytest.mark.parametrize("value", [ORG_ID, ORG_ID.upper(), ORG_ID.title()])
def test_an_org_id_becomes_one_pseudonym_whatever_its_case(value):
    """Mutation: compare with case."""
    assert OrgScreen({ORG_ID.upper()}, SALT)(value) == PSEUDONYM
    assert OrgScreen({ORG_ID}, SALT)(f"'{value}' is not allowed") == f"'{PSEUDONYM}' is not allowed"


def test_the_screen_walks_mappings_and_lists_keys_included():
    screened = OrgScreen({ORG_ID}, SALT)({ORG_ID: [ORG_ID.upper(), {"x": ORG_ID}], "n": 1})
    assert screened == {PSEUDONYM: [PSEUDONYM, {"x": PSEUDONYM}], "n": 1}


def test_without_a_salt_an_org_id_is_withheld():
    assert OrgScreen({ORG_ID}, "")(ORG_ID) == WITHHELD_ORG


def test_without_the_policy_every_value_is_withheld():
    """Mutation: pass values through when the org ids are unknown."""
    assert ov.ORG_SCREEN_UNAVAILABLE({"name": ORG_ID, "k": ["dana"]}) == {
        "name": WITHHELD_UNSCANNED, "k": [WITHHELD_UNSCANNED]}


# -- the audit record ------------------------------------------------------


@pytest.mark.parametrize("field", PRINCIPAL_FIELDS)
def test_each_principal_field_is_stored_as_its_pseudonym(store, field):
    """Mutation: pass any one of the four fields to the record unscreened."""
    apply_change(store, _actor(), Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    for value, mode in ((ORG_ID.upper(), "enforce"), (ORG_ID, "observe")):
        applied = apply_change(store, _actor(**{field: value}), Change(ACTION_SET, KEY_MODE, mode),
                               detectors=DETECTORS, signing_key=OVERRIDES_KEY, org_ids={ORG_ID}, salt=SALT)
        assert applied.record["principal"][field] == PSEUDONYM
        assert applied.state.overrides[KEY_MODE].set_by[field] == PSEUDONYM
    assert not _raw_in(_stored(store))


def test_a_detector_still_refuses_a_principal(store):
    from conftest import FAKE_GITHUB_TOKEN

    apply_change(store, _actor(), Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    with pytest.raises(ov.Matched):
        apply_change(store, _actor(name=FAKE_GITHUB_TOKEN), Change(ACTION_SET, KEY_MODE, "enforce"),
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY, org_ids={ORG_ID}, salt=SALT)


def test_the_cli_principal_is_screened(tmp_path, monkeypatch, capsys):
    """Mutation: pass the CLI's apply_change no salt, or no org ids."""
    from forgd_verdict.cli import main

    monkeypatch.setattr("getpass.getuser", lambda: ORG_ID.upper())
    policy = _policy_file(tmp_path, monkeypatch, {**ORGS, **ADMINS})
    root = tmp_path / "s"
    for argv in (("init",), ("set", KEY_MODE, "enforce")):
        assert main(["--policy", str(policy), "overrides", "--store", str(root), *argv]) == 0
    out = capsys.readouterr()
    assert not _raw_in(_stored(LocalFileStore(root)) + out.out + out.err)
    [record] = [json.loads(p.read_text()) for p in (root / "audit").rglob("*-request.json")
                if json.loads(p.read_text())["action"] == ACTION_SET]
    assert record["principal"]["name"] == PSEUDONYM


# -- the dashboard ---------------------------------------------------------


def _org_admin_app(store, cfg):
    """A dashboard whose admin group is the org id."""
    from forgd_verdict.dashboard.admin import AdminConfig
    from forgd_verdict.dashboard.app import Dashboard

    admins = AdminConfig.parse({"groups": [{"group": ORG_ID.upper()}],
                                "allowed_origins": [ORIGIN], "form_key": KEY}, cfg)
    overrides = ov.RuntimeOverrides(store, "dashboard", baseline={KEY_MODE: "observe"})
    overrides.refresh()
    return Dashboard(store, auth=cfg, admins=admins, overrides=overrides,
                     baseline_mode="observe")


async def test_a_dashboard_change_by_an_org_id_principal_never_shows_it(
        store, auth, pem, tmp_path, monkeypatch, caplog):  # noqa: F811
    """name, subject and matched group are the org id. Mutation: log `who`
    unscreened on an applied change; render a banner, panel or history
    principal unscreened."""
    _policy_file(tmp_path, monkeypatch, ORGS)
    _init(store)
    app = _org_admin_app(store, auth)
    principal = Principal(name=ORG_ID.upper(), groups=(ORG_ID.upper(),), issuer=ISSUER,
                          subject=ORG_ID)
    token = _token(pem, preferred_username=ORG_ID.upper(), sub=ORG_ID, groups=[ORG_ID.upper()])
    with caplog.at_level(logging.DEBUG):
        status, headers, _ = await _call(
            app, "POST", "/admin/actions", _headers(pem, **{HEADER: token}),
            _form(app, ACTION_SET, KEY_MODE, "enforce", 1, principal=principal))
        assert headers[b"location"] == b"/policy?result=applied", status
        pages = [(await _call(app, "GET", path, {HEADER: token}))[2].decode()
                 for path in ("/policy", "/")]
    record = next(json.loads(store.get_audit(n)) for n in store.list_audit()
                  if n.endswith("-request.json")
                  and json.loads(store.get_audit(n))["action"] == ACTION_SET)
    assert {k: record["principal"][k] for k in ("name", "subject", "via_group")} == {
        "name": PSEUDONYM, "subject": PSEUDONYM, "via_group": PSEUDONYM}
    assert not _raw_in(_stored(store))
    assert not _raw_in(_logged(caplog))
    applied = [r.fields for r in caplog.records
               if r.getMessage() == "dashboard admin action applied"]
    assert applied and applied[0]["who"] == PSEUDONYM
    for page in pages:
        assert not _raw_in(page) and PSEUDONYM in page


async def test_a_refusal_logs_an_org_id_principal_as_its_pseudonym(
        store, auth, pem, tmp_path, monkeypatch, caplog):  # noqa: F811
    """Mutation: log `who`, or another refusal field, unscreened."""
    _policy_file(tmp_path, monkeypatch, ORGS)
    app = _app(store, auth)
    token = _token(pem, preferred_username=ORG_ID.upper(), groups=["viewers"])
    origin = f"https://{ORG_ID}.example"
    with caplog.at_level(logging.DEBUG):
        await _call(app, "POST", "/admin/actions", _headers(pem, **{HEADER: token}),
                    _form(app, ACTION_SET, KEY_MODE, "enforce"))
        await _call(app, "POST", "/admin/actions", _headers(pem, origin=origin),
                    _form(app, ACTION_SET, KEY_MODE, "enforce"))
    refusals = _refusals(caplog)
    assert refusals[0]["who"] == PSEUDONYM
    assert refusals[1]["origin"] == f"https://{PSEUDONYM}.example"
    assert not _raw_in(_logged(caplog))


def _unscreened(store):
    """A change stored before the org was configured: the principal is raw."""
    apply_change(store, _actor(), Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, _actor(name=ORG_ID.upper()), Change(ACTION_SET, KEY_MODE, "enforce"),
                 detectors=DETECTORS, signing_key=OVERRIDES_KEY)


async def test_recent_changes_and_banners_show_a_stored_org_id_as_its_pseudonym(
        store, auth, pem, tmp_path, monkeypatch):  # noqa: F811
    """Mutation: render the history, the panel's `set by` or a banner's
    principal unscreened."""
    _unscreened(store)
    _policy_file(tmp_path, monkeypatch, ORGS)
    app = _app(store, auth)
    for path in ("/policy", "/", "/events"):
        page = (await _call(app, "GET", path, {HEADER: _token(pem)}))[2].decode()
        assert not _raw_in(page), path
        assert PSEUDONYM in page, path
    policy_page = (await _call(app, "GET", "/policy", {HEADER: _token(pem)}))[2].decode()
    assert policy_page.count(PSEUDONYM) >= 3, "banner, set by, and the history"


async def test_without_the_policy_the_dashboard_withholds_every_principal(
        store, auth, pem, monkeypatch, caplog):  # noqa: F811
    """Mutation: show the values when the policy cannot be loaded."""
    import forgd_verdict.policy as policy_module

    _unscreened(store)
    app = _app(store, auth)

    def broken(*_a, **_k):
        raise RuntimeError("no policy")

    monkeypatch.setattr(policy_module, "load_policy", broken)
    with caplog.at_level(logging.DEBUG):
        page = (await _call(app, "GET", "/policy", {HEADER: _token(pem)}))[2].decode()
    assert not _raw_in(page) and not _raw_in(_logged(caplog))
    assert WITHHELD_UNSCANNED in page


def test_the_panel_withholds_principals_without_a_screen(store):
    """Mutation: fall back to the raw value when no screen is given."""
    from forgd_verdict.dashboard.controls import Panel, banners, panel

    _unscreened(store)
    snap = ov.RuntimeOverrides(store, "t", baseline={KEY_MODE: "observe"}).refresh()
    html = panel(Panel(snapshot=snap, baseline_mode="observe", baseline_source="policy.yaml",
                       legacy_reset=None, legacy_excluded=set(),
                       history=ov.history(store, snap.state), form=None))
    html += banners(snap, "observe")
    assert not _raw_in(html) and WITHHELD_UNSCANNED in html


# -- the CLI ---------------------------------------------------------------


def test_overrides_show_prints_a_stored_org_id_as_its_pseudonym(store, tmp_path, monkeypatch,
                                                                capsys):
    """Mutation: print the state, or the recent changes, unscreened."""
    from forgd_verdict.cli import main

    _unscreened(store)
    policy = _policy_file(tmp_path, monkeypatch, {**ORGS, **ADMINS})
    assert main(["--policy", str(policy), "overrides", "--store", str(store.root), "show"]) == 0
    out = capsys.readouterr()
    shown = json.loads(out.out)
    assert shown["recent_changes"][0]["by"] == PSEUDONYM
    assert shown["state"]["overrides"][KEY_MODE]["set_by"]["name"] == PSEUDONYM
    assert not _raw_in(out.out + out.err)


def test_a_cli_refusal_does_not_print_an_org_id(store, tmp_path, monkeypatch, capsys):
    """A mode refusal does not repeat the value. Mutation: echo it unscreened."""
    from forgd_verdict.cli import main

    apply_change(store, _actor(), Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    policy = _policy_file(tmp_path, monkeypatch, {**ORGS, **ADMINS})
    assert main(["--policy", str(policy), "overrides", "--store", str(store.root),
                 "set", KEY_MODE, ORG_ID.upper()]) == 2
    out = capsys.readouterr()
    assert "refused" in out.err and not _raw_in(out.out + out.err)


@pytest.mark.parametrize("on", [False, True], ids=["overrides-off", "overrides-on"])
def test_the_cli_listing_screens_excluded_and_other_request_ids(tmp_path, capsys, caplog, on):
    """Mutation: print a non-excluded request id unscreened."""
    root = tmp_path / "s"
    other = f"PreToolUse:{ORG_ID.upper()}"
    _frames(root, ORG_ID.upper(), other, "req_plain")
    LocalFileStore(root).set_excluded([ORG_ID.upper()])
    if on:
        apply_change(LocalFileStore(root), {"name": "ops"}, Change(ACTION_INIT),
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    with caplog.at_level(logging.DEBUG):
        out = _list(tmp_path, capsys, {**ORGS, **(ADMINS if on else {})}, root)
    lines = out.out.splitlines()
    assert lines[0] == "3 frame(s) with findings; 1 excluded"
    assert any("EXCLUDED" in line and line.endswith(WITHHELD_ORG) for line in lines)
    assert any(line.endswith(f"PreToolUse:{PSEUDONYM}") for line in lines)
    assert any(line.endswith("req_plain") for line in lines)
    assert not _raw_in(out.out + out.err + caplog.text)


# -- the event log ---------------------------------------------------------


def _events(store):
    import time

    from forgd_verdict.store import VerdictRecord
    from forgd_verdict.store.base import FindingRow

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    finding = [FindingRow("t0_regex", "block", "m0:0-4", "a" * 64)]
    store.write_verdicts([
        VerdictRecord(source="inference_hook", observed_at=now, request_id=rid, action="allow",
                      findings_count=1, findings=finding)
        for rid in (ORG_ID.upper(), f"PreToolUse:Bash:{ORG_ID}", "req_plain")
    ] + [VerdictRecord(source="compliance_scan", observed_at=now, session_id=ORG_ID,
                       action="allow", findings_count=1, findings=finding)])


async def test_the_event_log_shows_an_org_id_request_id_as_its_pseudonym_with_no_form(
        store, auth, pem, tmp_path, monkeypatch, caplog):  # noqa: F811
    """Mutation: render the raw id; offer an Exclude form for a screened id;
    pass the event log no screen."""
    _policy_file(tmp_path, monkeypatch, ORGS)
    _events(store)
    _init(store)
    app = _app(store, auth)
    with caplog.at_level(logging.DEBUG):
        _, _, page = await _call(app, "GET", "/events", {HEADER: _token(pem)})
    text = page.decode()
    assert not _raw_in(text) and not _raw_in(_logged(caplog))
    # The request id and the session id whole; the long one shortened to
    # its end, which the pseudonym now is.
    assert text.count(PSEUDONYM) == 2 and PSEUDONYM[-12:] + "<" in text.replace("</code>", "<")
    assert text.count('name="value"') == 1
    assert 'name="value" value="req_plain"' in text


async def test_without_the_policy_the_event_log_withholds_every_id_and_offers_no_form(
        store, auth, pem, monkeypatch, caplog):  # noqa: F811
    import forgd_verdict.policy as policy_module

    _events(store)
    _init(store)
    app = _app(store, auth)

    def broken(*_a, **_k):
        raise RuntimeError("no policy")

    monkeypatch.setattr(policy_module, "load_policy", broken)
    with caplog.at_level(logging.DEBUG):
        _, _, page = await _call(app, "GET", "/events", {HEADER: _token(pem)})
    text = page.decode()
    assert not _raw_in(text) and "req_plain" not in text
    assert 'method="post"' not in text and WITHHELD_UNSCANNED in text


def test_a_cli_store_read_error_prints_an_org_id_as_its_pseudonym(store, tmp_path, monkeypatch,
                                                                   capsys):
    """A backend's read error can name the organization, through a bucket or
    container name. Mutation: print the error unscreened."""
    from forgd_verdict import overrides
    from forgd_verdict.cli import main
    from forgd_verdict.store.base import StoreReadError

    def unreadable(*args, **kwargs):
        raise StoreReadError(f"AccessDenied on findings-{ORG_ID.upper()}")

    monkeypatch.setattr(overrides, "apply_change", unreadable)
    policy = _policy_file(tmp_path, monkeypatch, {**ORGS, **ADMINS})
    assert main(["--policy", str(policy), "overrides", "--store", str(store.root),
                 "set", KEY_MODE, "enforce"]) == 1
    out = capsys.readouterr()
    assert "the store could not be read" in out.err
    assert PSEUDONYM in out.err and not _raw_in(out.out + out.err)
