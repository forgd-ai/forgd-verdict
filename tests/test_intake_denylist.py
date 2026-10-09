"""A fleet device refused through the runtime overrides, without a reload."""

from __future__ import annotations

import json

import pytest
from conftest import DETECTORS, FAKE_AWS_KEY, OVERRIDES_KEY, OVERRIDES_PUBLIC_TEXT, ASGIClient
from test_intake_fleet import FLEET_TOKEN, _headers, _ndjson, _policy, _rec

from forgd_verdict import __version__
from forgd_verdict.intake.app import Intake
from forgd_verdict.overrides import (
    ACTION_CLEAR,
    ACTION_DENY_CLEAR,
    ACTION_DENY_DEVICE,
    ACTION_INIT,
    ACTION_SET,
    ACTION_UNDENY_DEVICE,
    ERROR_READER_TOO_OLD,
    FIELD_DENIED_DEVICES,
    KEY_MODE,
    Change,
    InvalidState,
    Refused,
    RuntimeOverrides,
    apply_change,
    parse_state,
)
from forgd_verdict.store import LocalFileStore

ADMIN = {"issuer": "https://idp/", "subject": "s", "name": "a", "verified": True}
ADMINS = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
          "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")


@pytest.fixture(autouse=True)
def org_env(monkeypatch):
    from test_intake_fleet import ORG_DEV, ORG_PROD

    monkeypatch.setenv("FORGD_ORG_ID_PROD", ORG_PROD)
    monkeypatch.setenv("FORGD_ORG_ID_DEV", ORG_DEV)
    monkeypatch.setenv("FORGD_INTAKE_FLEET_TOKEN", FLEET_TOKEN)


def _change(store, action, value=None, key=None, **kw):
    return apply_change(store, ADMIN, Change(action, key, value), detectors=DETECTORS,
                        signing_key=OVERRIDES_KEY, **kw)


@pytest.fixture
def store(tmp_path):
    s = LocalFileStore(tmp_path / "store", instance="t")
    _change(s, ACTION_INIT)
    return s


@pytest.fixture
def app(store, monkeypatch):
    from forgd_verdict.policy import _deep_merge

    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    a = Intake(type(_policy())(raw=_deep_merge(_policy().raw, ADMINS)), store=store)
    yield a
    a.close()


async def _ship(app, device, route="/intake"):
    body = _ndjson(_rec()) if route == "/intake" else json.dumps(
        {"hook_event_name": "UserPromptSubmit", "prompt": "hello",
         "session_id": "s"}).encode()
    return await ASGIClient(app).post(route, body, _headers(FLEET_TOKEN, device))


async def test_a_denied_device_is_refused_after_the_reader_refreshes(app, store):
    assert (await _ship(app, "d000000000042"))[0] == 200
    _change(store, ACTION_DENY_DEVICE, "d000000000042")
    app.overrides.refresh()
    for route in ("/intake", "/scan"):
        status, body = await _ship(app, "d000000000042", route)
        assert status == 403, route
        assert body == {"error": "device_denied"}
    assert (await _ship(app, "d000000000043"))[0] == 200
    assert app.stats()["counts"]["device_denied"] == 2
    app.flush()
    assert len(list(store.read_verdicts())) == 2

    _change(store, ACTION_UNDENY_DEVICE, "d000000000042")
    app.overrides.refresh()
    assert (await _ship(app, "d000000000042"))[0] == 200


def test_denying_a_device_raises_the_min_reader_version(store):
    applied = _change(store, ACTION_DENY_DEVICE, "d000000000001", writer_version="0.46.0")
    assert applied.state.denied_devices == {"d000000000001"}
    assert applied.state.min_reader_version == "0.46.0"
    assert applied.record["min_reader_version"] == "0.46.0"
    applied = _change(store, ACTION_DENY_CLEAR)
    assert not applied.state.denied_devices
    assert applied.state.min_reader_version is None


def test_the_min_reader_version_stays_while_a_mode_or_a_device_needs_it(store):
    _change(store, ACTION_SET, "enforce", key=KEY_MODE, writer_version="0.46.0")
    _change(store, ACTION_DENY_DEVICE, "d000000000001", writer_version="0.46.0")
    assert _change(store, ACTION_CLEAR, key=KEY_MODE).state.min_reader_version == "0.46.0"
    assert _change(store, ACTION_DENY_CLEAR).state.min_reader_version is None


def test_an_older_reader_does_not_adopt_a_denylist(store):
    _change(store, ACTION_DENY_DEVICE, "d000000000001", writer_version="0.46.0")
    old = RuntimeOverrides(store, "intake", reader_version="0.45.0").refresh()
    assert old.error == ERROR_READER_TOO_OLD
    new = RuntimeOverrides(store, "intake", reader_version="0.46.0").refresh()
    assert new.state.denied_devices == {"d000000000001"}


@pytest.mark.parametrize("bad", ["", "has space", "-leading", "x" * 65, "a/b"])
def test_a_malformed_device_id_is_refused(store, bad):
    with pytest.raises(Refused):
        _change(store, ACTION_DENY_DEVICE, bad)


def test_a_secret_shaped_device_id_is_refused(store):
    with pytest.raises(Refused):
        _change(store, ACTION_DENY_DEVICE, FAKE_AWS_KEY)


def test_the_denylist_is_capped(store, monkeypatch):
    from forgd_verdict import overrides

    monkeypatch.setattr(overrides, "MAX_DENIED_DEVICES", 2)
    _change(store, ACTION_DENY_DEVICE, "d000000000001")
    _change(store, ACTION_DENY_DEVICE, "d000000000002")
    with pytest.raises(Refused, match="at most 2"):
        _change(store, ACTION_DENY_DEVICE, "d000000000003")


def test_an_object_without_a_denylist_keeps_its_shape(store):
    body = json.loads(store.read_control().body)
    assert FIELD_DENIED_DEVICES not in body


@pytest.mark.parametrize("field", [
    {FIELD_DENIED_DEVICES: ["d000000000001"]},
    {FIELD_DENIED_DEVICES: [], "min_reader_version": "0.46.0"},
    {FIELD_DENIED_DEVICES: ["not ok"], "min_reader_version": "0.46.0"},
])
def test_a_malformed_denylist_object_is_invalid(field):
    with pytest.raises(InvalidState):
        parse_state(json.dumps({"version": 1, "revision": 1, **field}).encode())


def test_the_cli_denies_and_accepts_a_device(tmp_path, capsys):
    from forgd_verdict.cli import main

    policy = tmp_path / "admins.json"
    policy.write_text(json.dumps(ADMINS))
    root = str(tmp_path / "cli-store")

    def run(*argv):
        return main(["--policy", str(policy), "overrides", "--store", root, *argv])

    assert run("init") == 0
    assert run("deny-device", "d000000000007") == 0
    state = parse_state(LocalFileStore(root, instance="r").read_control().body)
    assert state.denied_devices == {"d000000000007"}
    assert state.min_reader_version == __version__
    assert run("undeny-device", "d000000000007") == 0
    assert run("deny-device", "d000000000008") == 0
    assert run("clear-devices") == 0
    state = parse_state(LocalFileStore(root, instance="r").read_control().body)
    assert not state.denied_devices


def test_the_policy_tab_lists_denied_devices_with_an_undeny_form(store):
    from forgd_verdict.dashboard.controls import Panel, panel

    _change(store, ACTION_DENY_DEVICE, "d000000000009")
    snap = RuntimeOverrides(store, "t", baseline={KEY_MODE: "observe"}).refresh()
    forms = []

    def form(action, key, value, label, confirm):
        forms.append((action, key, value))
        return ""

    html = panel(Panel(snapshot=snap, baseline_mode="observe", baseline_source="policy.yaml",
                       legacy_reset=None, legacy_excluded=set(), history=None, form=form,
                       org_screen=lambda v: v))
    assert "d000000000009" in html
    assert (ACTION_UNDENY_DEVICE, FIELD_DENIED_DEVICES, "d000000000009") in forms
    assert (ACTION_DENY_CLEAR, FIELD_DENIED_DEVICES, "") in forms


def test_a_fleet_with_runtime_overrides_on_does_not_warn(store, monkeypatch, caplog):
    import logging

    from forgd_verdict.policy import _deep_merge

    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    caplog.set_level(logging.WARNING, logger="forgd_verdict")
    a = Intake(type(_policy())(raw=_deep_merge(_policy().raw, ADMINS)), store=store)
    try:
        assert a.overrides.enabled
        assert not [r for r in caplog.records
                    if "one device cannot be denied" in r.getMessage()]
    finally:
        a.close()
