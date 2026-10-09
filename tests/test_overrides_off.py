"""Runtime overrides are off unless `dashboard.admins` lists groups.

Off, no service touches the control object or the audit prefix, and
`exclude` and `reset-stats` write the legacy `markers/*` objects as they did
before runtime overrides existed. Each store here already holds an object
that would change behaviour if it were read: an initialized object holding an
`enforce` override, an exclusion and a reset.
"""

from __future__ import annotations

import json
import logging

import pytest
from conftest import (
    DETECTORS,
    FAKE_AWS_KEY,
    OVERRIDES_KEY,
    OVERRIDES_PUBLIC_TEXT,
    WHSEC,
    ASGIClient,
    frame,
    make_policy,
    sign,
    text_msg,
)

from forgd_verdict.models import CONTROL_STATE
from forgd_verdict.overrides import (
    ACTION_EXCLUDE,
    ACTION_INIT,
    ACTION_RESET,
    ACTION_SET,
    CONTROL_IDENTITY_OFF,
    ENV_ENABLED,
    KEY_MODE,
    Change,
    apply_change,
    enabled_in,
)
from forgd_verdict.policy import Policy, _deep_merge
from forgd_verdict.store import LocalFileStore

ADMIN = {"issuer": "https://idp/", "subject": "s", "name": "a", "verified": True}
ON = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
     "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}
OFF = {
    "absent": {},
    "no groups": {"dashboard": {"admins": {"groups": []}}},
    "groups null": {"dashboard": {"admins": {"allowed_origins": ["https://d"],
                                             "groups": None}}},
}
_CONTROL_METHODS = ("read_control", "write_control", "put_audit", "get_audit", "list_audit",
                    "audit_days")

pytestmark = pytest.mark.usefixtures("control_identity")


@pytest.fixture
def seeded(tmp_path):
    root = tmp_path / "store"
    store = LocalFileStore(root, instance="seed")
    apply_change(store, ADMIN, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_object"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_RESET, value="2026-09-01T00:00:00Z"),
                 detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    return root


@pytest.fixture
def touched(monkeypatch):
    """Every call, on any LocalFileStore, that reads or writes the control
    object or the audit prefix."""
    calls: list[str] = []

    def spy(name):
        real = getattr(LocalFileStore, name)

        def wrapper(self, *a, **kw):
            calls.append(name)
            return real(self, *a, **kw)
        return wrapper

    for name in _CONTROL_METHODS:
        monkeypatch.setattr(LocalFileStore, name, spy(name))
    real_get_state = LocalFileStore.get_state

    def get_state(self, name, *a, **kw):
        if name == CONTROL_STATE:
            calls.append("get_state")
        return real_get_state(self, name, *a, **kw)

    monkeypatch.setattr(LocalFileStore, "get_state", get_state)
    return calls


def test_enabled_in_is_the_admin_config_test():
    from forgd_verdict.dashboard.admin import AdminConfig
    from forgd_verdict.dashboard.auth import AuthConfig

    for raw in OFF.values():
        assert not enabled_in(raw)
        assert AdminConfig.parse((raw.get("dashboard") or {}).get("admins"),
                                 AuthConfig(mode="none")) is None
    assert enabled_in(ON)


# -- services --------------------------------------------------------------


async def _verdict(root, extra):
    from forgd_verdict.server.app import VerdictServer

    server = VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": None,
                "store": str(root), "store_flush_s": 3600}, **extra))
    try:
        raw = json.dumps(frame([text_msg(f"key {FAKE_AWS_KEY}")], request_id="req_v")).encode()
        _, verdict = await ASGIClient(server).post("/hook", raw, sign(raw, webhook_id="req_v"))
        return verdict["action"], server._metrics_body()["runtime_overrides"]["status"]
    finally:
        server.close()


async def _intake(root, extra):
    from test_scan_frames import _policy, auth, user
    from test_scan_frames import frame as scan_frame

    from forgd_verdict.intake.app import Intake

    app = Intake(Policy(raw=_deep_merge(_policy().raw, extra)),
                 store=LocalFileStore(root, instance="t"))
    try:
        _, body = await ASGIClient(app).post(
            "/scan", scan_frame([user(f"deploy with {FAKE_AWS_KEY}")]), auth())
        return body["action"], app.stats()["runtime_overrides"]["status"]
    finally:
        app.close()


async def _collector(root, extra):
    from forgd_verdict.otel.app import Collector

    app = Collector(make_policy(**extra), store=LocalFileStore(root, instance="t"))
    try:
        return None, app.stats()["runtime_overrides"]["status"]
    finally:
        app.close()


async def _ingest(root, extra, tmp_path, capsys):
    from forgd_verdict.cli import main

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"compliance": {"api_key": ""}, **extra}))
    assert main(["--policy", str(policy), "ingest", "--store", str(root)]) == 0
    return None, json.loads(capsys.readouterr().out)["runtime_overrides"]["status"]


async def _connector(root, extra):
    from forgd_verdict.connector.tools import reader_from_policy

    store = LocalFileStore(root, instance="t")
    store.set_excluded(["req_legacy"])

    class Cfg:
        auth = None
        entitlements = None

    reader = reader_from_policy(make_policy(**extra), Cfg(), store)
    desc = reader.store.describe()
    return (sorted(reader.store.get_excluded()), desc.get("reset_at")), None


SERVICES = {"verdict": _verdict, "intake": _intake, "collector": _collector,
            "ingest": _ingest, "connector": _connector}


async def _run(name, root, extra, tmp_path, capsys):
    if name == "ingest":
        return await _ingest(root, extra, tmp_path, capsys)
    return await SERVICES[name](root, extra)


@pytest.mark.parametrize("off", OFF, ids=str)
@pytest.mark.parametrize("name", SERVICES)
async def test_off_no_service_touches_the_object(name, off, seeded, touched, tmp_path, capsys):
    """Mutation: drop the enabled_in test from reader_for, or from the connector."""
    applied, status = await _run(name, seeded, OFF[off], tmp_path, capsys)
    assert touched == []
    if name in ("verdict", "intake"):
        assert applied == "allow"
    if name == "connector":
        assert applied == (["req_legacy"], None)
    else:
        assert status == "disabled"


@pytest.mark.parametrize("name", SERVICES)
async def test_on_every_service_reads_the_object(name, seeded, touched, tmp_path, capsys,
                                                 overrides_log):
    """The spy sees reads when the feature is on, so its silence above means something."""
    applied, status = await _run(name, seeded, ON, tmp_path, capsys)
    assert "read_control" in touched
    assert _identity_off_warnings(overrides_log) == []
    if name in ("verdict", "intake"):
        assert applied == "deny"
    if name == "connector":
        assert applied == (["req_legacy", "req_object"], "2026-09-01T00:00:00Z")
    else:
        assert status == "ok"



@pytest.fixture
def overrides_log():
    """Every record the overrides logger emits. A handler on the logger itself,
    since `applog` stops `forgd_verdict` propagating to caplog."""
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append
    logger = logging.getLogger("forgd_verdict.overrides")
    logger.addHandler(handler)
    yield records
    logger.removeHandler(handler)


def _identity_off_warnings(records) -> list[logging.LogRecord]:
    return [r for r in records
            if r.levelno == logging.WARNING and r.getMessage() == CONTROL_IDENTITY_OFF]


@pytest.mark.parametrize("value", [None, "", "1", "True", "yes"], ids=repr)
@pytest.mark.parametrize("name", SERVICES)
async def test_without_the_control_identity_no_service_touches_the_object(
        name, value, seeded, touched, tmp_path, capsys, overrides_log, monkeypatch):
    """Groups listed, FORGD_OVERRIDES_ENABLED not exactly `true`: as if off, with
    one warning.

    Mutation: drop the deployment_enabled test from honoured_in, or the
    honoured_in call from reader_for or the connector."""
    if value is None:
        monkeypatch.delenv(ENV_ENABLED, raising=False)
    else:
        monkeypatch.setenv(ENV_ENABLED, value)
    applied, status = await _run(name, seeded, ON, tmp_path, capsys)
    assert touched == []
    if name in ("verdict", "intake"):
        assert applied == "allow"
    if name == "connector":
        assert applied == (["req_legacy"], None)
    else:
        assert status == "disabled"
    warnings = _identity_off_warnings(overrides_log)
    assert len(warnings) == 1
    assert "dashboard.admins.enabled" in CONTROL_IDENTITY_OFF
    assert "dashboard_admins_enabled" in CONTROL_IDENTITY_OFF

@pytest.mark.parametrize("off", OFF, ids=str)
async def test_off_the_dashboard_never_touches_the_object(off, seeded, touched, tmp_path,
                                                          monkeypatch):
    """Mutation: drop the enabled_in test from the dashboard's create_app."""
    from test_dashboard_admin import _call

    from forgd_verdict.dashboard.app import create_app

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(OFF[off]))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(seeded))
    app = create_app()
    assert app.overrides is None
    for path in ("/", "/policy", "/events"):
        status, _, body = await _call(app, "GET", path)
        assert status == 200
        assert b"Runtime overrides" not in body
    assert "legacy_reset_at" not in app.store.describe()
    assert touched == []


# -- the CLI ---------------------------------------------------------------


def _cli(tmp_path, extra, *argv):
    from forgd_verdict.cli import main

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(extra))
    return main(["--policy", str(policy), *argv])


def _tree(root):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


@pytest.mark.parametrize("off", OFF, ids=str)
def test_off_exclude_writes_the_legacy_marker_exactly(off, tmp_path, touched, capsys):
    """Mutation: drop the _overrides_on test from _cmd_exclude."""
    root, s = tmp_path / "s", str(tmp_path / "s")
    extra = OFF[off]
    assert _cli(tmp_path, extra, "exclude", "--store", s, "--request-id", "req_b",
                "--request-id", "req_a") == 0
    assert capsys.readouterr().out == "2 added, 2 excluded in total\n"
    assert _cli(tmp_path, extra, "exclude", "--store", s, "--request-id", "req_a",
                "--request-id", "req_c") == 0
    assert capsys.readouterr().out == "1 added, 3 excluded in total\n"
    marker = root / "markers" / "excluded_requests"
    assert LocalFileStore(root).get_excluded() == {"req_a", "req_b", "req_c"}
    assert _cli(tmp_path, extra, "exclude", "--store", s, "--list") == 0
    assert capsys.readouterr().out.startswith("0 frame(s) with findings; 3 excluded\n")
    assert _cli(tmp_path, extra, "exclude", "--store", s, "--clear") == 0
    assert capsys.readouterr().out == "all exclusions removed\n"
    assert LocalFileStore(root).get_excluded() == set()
    assert marker.exists()
    assert _cli(tmp_path, extra, "exclude", "--store", s) == 2
    assert capsys.readouterr().err == "nothing to do: pass --request-id, --list or --clear\n"
    assert _tree(root) == ["markers/excluded_requests"]
    assert touched == []


@pytest.mark.parametrize("off", OFF, ids=str)
def test_off_reset_stats_writes_the_legacy_marker_exactly(off, tmp_path, touched, capsys,
                                                          monkeypatch):
    """Mutation: drop the _overrides_on test from _cmd_reset_stats."""
    root, s = tmp_path / "s", str(tmp_path / "s")
    extra = OFF[off]
    assert _cli(tmp_path, extra, "reset-stats", "--store", s,
                "--at", "2026-09-01T00:00:00Z") == 0
    assert json.loads(capsys.readouterr().out) == {
        "reset_at": "2026-09-01T00:00:00Z",
        "note": "records are kept; the dashboard now starts from this point"}
    assert LocalFileStore(root).get_reset_marker() == "2026-09-01T00:00:00Z"
    # Before runtime overrides, --at was stored as given.
    assert _cli(tmp_path, extra, "reset-stats", "--store", s, "--at", "yesterday") == 0
    assert LocalFileStore(root).get_reset_marker() == "yesterday"
    capsys.readouterr()
    assert _cli(tmp_path, extra, "reset-stats", "--store", s, "--clear") == 0
    assert json.loads(capsys.readouterr().out) == {"reset_at": None, "note": "marker cleared"}
    assert not LocalFileStore(root).get_reset_marker()
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    assert _cli(tmp_path, extra, "reset-stats") == 2
    assert capsys.readouterr().err == "no store configured: pass --store or set server.store\n"
    assert _tree(root) == ["markers/stats_reset"]
    assert touched == []


@pytest.mark.parametrize("what", [("init",), ("set", "server.mode", "enforce"),
                                  ("clear", "server.mode"), ("clear-all",), ("recover",),
                                  ("migrate-markers",)],
                         ids=lambda w: w[0])
def test_off_overrides_writes_are_refused(what, tmp_path, touched, capsys):
    """Mutation: drop the _overrides_on test from _cmd_overrides."""
    root = tmp_path / "s"
    assert _cli(tmp_path, {}, "overrides", "--store", str(root), *what) == 2
    assert "runtime overrides are off because dashboard.admins lists no groups" in \
        capsys.readouterr().err
    assert not root.exists()
    assert touched == []


def test_on_exclude_and_reset_stats_write_the_object(tmp_path, capsys, signing_env):
    root, s = tmp_path / "s", str(tmp_path / "s")
    assert _cli(tmp_path, ON, "overrides", "--store", s, "init") == 0
    assert _cli(tmp_path, ON, "exclude", "--store", s, "--request-id", "req_a") == 0
    assert _cli(tmp_path, ON, "reset-stats", "--store", s, "--at", "2026-09-01T00:00:00Z") == 0
    tree = _tree(root)
    assert f"state/{CONTROL_STATE}" in tree
    assert not any(p.startswith("markers/") for p in tree)
