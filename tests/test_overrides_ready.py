"""A process with no last-known-good is not ready until it knows what is in force.

With runtime overrides on, a cold reader is ready on a valid object only. It
is not ready while the object is absent, whether the audit prefix lists
records, lists none (the store was never initialized) or cannot be listed, or
while the object is unreadable or invalid. Every long-running service answers
`/readyz` with a 503 then, and `ingest` exits before either path runs.
`/healthz` (and `/health` where it exists) answers 200 throughout. A reader
holding a last-known-good stays ready through the same failures, and with
runtime overrides off nothing is read and every service is ready.
"""

from __future__ import annotations

import json
import logging

import pytest
from conftest import DETECTORS, OVERRIDES_KEY, OVERRIDES_PUBLIC_TEXT, WHSEC, ASGIClient, make_policy

from forgd_verdict.cli import main
from forgd_verdict.connector.app import create_app as create_connector
from forgd_verdict.connector.tools import reader_from_policy
from forgd_verdict.dashboard.app import create_app as create_dashboard
from forgd_verdict.intake.app import Intake
from forgd_verdict.otel.app import Collector
from forgd_verdict.overrides import (
    ACTION_EXCLUDE,
    ACTION_INIT,
    ACTION_RECOVER,
    ACTION_SET,
    ERROR_UNINITIALIZED,
    KEY_MODE,
    Change,
    RuntimeOverrides,
    apply_change,
)
from forgd_verdict.policy import Policy, _deep_merge
from forgd_verdict.server.app import VerdictServer
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import StoreReadError

ADMIN = {"issuer": "https://idp/", "subject": "s", "name": "a", "verified": True}
ON = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
     "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}
_OBJECT = ("state", "runtime-overrides.json")

pytestmark = pytest.mark.usefixtures("control_identity")


def _init(store):
    apply_change(store, ADMIN, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


def _seed(root):
    store = LocalFileStore(root, instance="seed")
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_object"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    return store


def _fail(self, *a):
    raise StoreReadError("denied")


def _orphan(root, monkeypatch):
    root.joinpath(*_OBJECT).unlink()


def _deny_audit_list(root, monkeypatch):
    if root.joinpath(*_OBJECT).exists():
        root.joinpath(*_OBJECT).unlink()
    monkeypatch.setattr(LocalFileStore, "list_audit", _fail)
    monkeypatch.setattr(LocalFileStore, "audit_days", _fail)


def _deny_read(root, monkeypatch):
    monkeypatch.setattr(LocalFileStore, "read_control", _fail)


def _corrupt(root, monkeypatch):
    root.joinpath(*_OBJECT).write_bytes(b"{broken")


# Each breaks a store that holds a valid object.
BREAK = {"absent with audit records": _orphan, "audit list fails": _deny_audit_list,
         "unreadable": _deny_read, "invalid": _corrupt}


def _cold(case):
    """The case on a store a process has not read before. The audit-list
    case has no object and no records."""
    def setup(root, monkeypatch):
        if case != "audit list fails":
            _seed(root)
        BREAK[case](root, monkeypatch)
    return setup


COLD = {case: _cold(case) for case in BREAK}


def _invalid(root, monkeypatch):
    _seed(root)
    _corrupt(root, monkeypatch)
STATUS = {"absent with audit records": "absent", "audit list fails": "absent",
          "unreadable": "unreadable", "invalid": "invalid"}


# -- the reader ------------------------------------------------------------


@pytest.mark.parametrize("case", COLD)
def test_a_cold_reader_is_not_ready_and_says_so(case, tmp_path, monkeypatch, caplog):
    """Mutation: return a ready baseline from _first_run or _failed."""
    root = tmp_path / "s"
    COLD[case](root, monkeypatch)
    caplog.set_level(logging.INFO, logger="forgd_verdict")
    snap = RuntimeOverrides(LocalFileStore(root), "test").refresh()
    assert (snap.ready, snap.in_error, snap.status, snap.source) == (
        False, True, STATUS[case], "baseline")
    assert snap.fields()["ready"] is False and snap.fields()["in_error"] == 1
    assert any(r.levelno == logging.ERROR for r in caplog.records)


def test_an_uninitialized_store_is_not_ready_until_init(tmp_path, caplog):
    """Mutation: return a ready baseline from _first_run on an empty audit prefix."""
    store = LocalFileStore(tmp_path / "s")
    reader = RuntimeOverrides(store, "test")
    caplog.set_level(logging.INFO, logger="forgd_verdict")
    snap = reader.refresh()
    assert (snap.ready, snap.in_error, snap.status, snap.source, snap.error) == (
        False, True, "absent", "baseline", ERROR_UNINITIALIZED)
    assert any(r.levelno == logging.ERROR for r in caplog.records)
    _init(store)
    snap = reader.refresh()
    assert (snap.ready, snap.in_error, snap.status, snap.source) == (
        True, False, "ok", "object")


def test_a_cold_reader_on_an_absent_object_lists_the_audit_prefix(tmp_path, monkeypatch):
    """Mutation: skip the audit listing in _first_run."""
    listed = []
    real = LocalFileStore.audit_days
    monkeypatch.setattr(LocalFileStore, "audit_days",
                        lambda self: listed.append(1) or real(self))
    RuntimeOverrides(LocalFileStore(tmp_path / "s"), "test").refresh()
    assert listed


@pytest.mark.parametrize("case", COLD)
def test_a_reader_with_a_last_known_good_stays_ready(case, tmp_path, monkeypatch):
    """Mutation: make _failed with a last-known-good not ready."""
    root = tmp_path / "s"
    _seed(root)
    reader = RuntimeOverrides(LocalFileStore(root), "test")
    assert reader.refresh().ready
    BREAK[case](root, monkeypatch)
    snap = reader.refresh()
    assert (snap.ready, snap.in_error, snap.source) == (True, True, "last_known_good")
    assert reader.mode("observe") == "enforce"


def test_a_cold_reader_becomes_ready_once_the_object_reads(tmp_path):
    root = tmp_path / "s"
    _invalid(root, None)
    store = LocalFileStore(root)
    reader = RuntimeOverrides(store, "test")
    assert not reader.refresh().ready
    root.joinpath(*_OBJECT).unlink()

    apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert reader.refresh().ready


# -- services --------------------------------------------------------------


def _verdict(root, extra):
    return VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": None,
                "store": str(root), "store_flush_s": 3600}, **extra))


def _intake(root, extra):
    from test_scan_frames import _policy

    return Intake(Policy(raw=_deep_merge(_policy().raw, extra)),
                  store=LocalFileStore(root, instance="t"))


def _collector(root, extra):
    return Collector(make_policy(**extra), store=LocalFileStore(root, instance="t"))


SERVICES = {"verdict": _verdict, "intake": _intake, "collector": _collector}


async def _get(app, path):
    status, body = await ASGIClient(app).get(path)
    return status, body


LIVENESS = ("/healthz", "/health")


async def _live(app):
    """Every liveness route answers 200 with `status: ok`."""
    for path in LIVENESS:
        status, body = await _get(app, path)
        assert (status, body["status"]) == (200, "ok"), (path, body)
        assert "build" in body and "uptime_s" in body and "runtime_overrides" not in body


@pytest.mark.parametrize("case", COLD)
@pytest.mark.parametrize("name", SERVICES)
async def test_a_cold_service_is_not_ready(name, case, tmp_path, monkeypatch):
    """Mutation: answer 200 from each service's /readyz, or readiness from /healthz."""
    root = tmp_path / "s"
    COLD[case](root, monkeypatch)
    app = SERVICES[name](root, ON)
    try:
        status, body = await _get(app, "/readyz")
        assert status == 503, body
        assert body == {"status": "not_ready",
                        "reason": "runtime overrides could not be confirmed",
                        "runtime_overrides": STATUS[case]}
        await _live(app)
        assert (await _get(app, "/livez"))[0] == 200
        stats = app._metrics_body() if name == "verdict" else app.stats()
        assert stats["runtime_overrides"]["in_error"] == 1
    finally:
        app.close()


@pytest.mark.parametrize("name", SERVICES)
async def test_a_service_on_a_valid_object_is_ready(name, tmp_path):
    root = tmp_path / "s"
    _seed(root)
    app = SERVICES[name](root, ON)
    try:
        assert await _get(app, "/readyz") == (200, {"status": "ok"})
        await _live(app)
    finally:
        app.close()


@pytest.mark.parametrize("name", SERVICES)
async def test_a_service_on_an_uninitialized_store_is_not_ready_until_init(name, tmp_path):
    """Mutation: drop the ERROR_UNINITIALIZED case from readiness."""
    root = tmp_path / "s"
    app = SERVICES[name](root, ON)
    try:
        status, body = await _get(app, "/readyz")
        assert status == 503, body
        assert body == {"status": "not_ready", "reason": "runtime overrides are not initialized",
                        "runtime_overrides": "absent"}
        await _live(app)
        stats = app._metrics_body() if name == "verdict" else app.stats()
        assert stats["runtime_overrides"]["in_error"] == 1
        _init(LocalFileStore(root, instance="init"))
        app.overrides.refresh()
        assert await _get(app, "/readyz") == (200, {"status": "ok"})
        await _live(app)
    finally:
        app.close()


@pytest.mark.parametrize("case", COLD)
@pytest.mark.parametrize("name", SERVICES)
async def test_a_service_with_a_last_known_good_stays_ready(name, case, tmp_path, monkeypatch):
    root = tmp_path / "s"
    _seed(root)
    app = SERVICES[name](root, ON)
    try:
        BREAK[case](root, monkeypatch)
        app.overrides.refresh()
        assert app.overrides.current().in_error
        assert (await _get(app, "/readyz"))[0] == 200
        await _live(app)
    finally:
        app.close()


@pytest.mark.parametrize("case", [*COLD, "uninitialized"])
@pytest.mark.parametrize("name", SERVICES)
async def test_off_a_service_is_ready_without_reading(name, case, tmp_path, monkeypatch):
    """Mutation: drop the enabled_in test from reader_for."""
    root = tmp_path / "s"
    if case != "uninitialized":
        COLD[case](root, monkeypatch)

    def refuse(self, *a):
        raise AssertionError("read with runtime overrides off")
    monkeypatch.setattr(LocalFileStore, "read_control", refuse)
    monkeypatch.setattr(LocalFileStore, "list_audit", refuse)
    monkeypatch.setattr(LocalFileStore, "audit_days", refuse)
    app = SERVICES[name](root, {})
    try:
        assert await _get(app, "/readyz") == (200, {"status": "ok"})
        await _live(app)
    finally:
        app.close()


# -- the dashboard ---------------------------------------------------------


def _dashboard(root, extra, tmp_path, monkeypatch):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(extra))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(root))
    return create_dashboard()


def _dashboard_on(monkeypatch):
    """create_app refuses admins without oidc_jwt; the readiness route is
    ahead of sign-in, so a parsed AdminConfig is not needed to reach it."""
    monkeypatch.setattr("forgd_verdict.dashboard.app.AdminConfig.parse",
                        staticmethod(lambda raw, auth: None))


@pytest.mark.parametrize("case", COLD)
async def test_a_cold_dashboard_is_not_ready_and_shows_the_banner(case, tmp_path, monkeypatch):
    """Mutation: answer 200 from the dashboard's /readyz, or readiness from /healthz."""
    from test_dashboard_admin import _call

    root = tmp_path / "s"
    COLD[case](root, monkeypatch)
    _dashboard_on(monkeypatch)
    app = _dashboard(root, ON, tmp_path, monkeypatch)
    status, _, body = await _call(app, "GET", "/readyz")
    assert status == 503
    assert json.loads(body)["runtime_overrides"] == STATUS[case]
    status, _, body = await _call(app, "GET", "/healthz")
    assert (status, json.loads(body)["status"]) == (200, "ok")
    _, _, page = await _call(app, "GET", "/")
    assert b"Runtime overrides" in page and b"running on policy.yaml" in page


async def test_a_dashboard_banner_names_orphaned_audit_records(tmp_path, monkeypatch):
    from test_dashboard_admin import _call

    root = tmp_path / "s"
    COLD["absent with audit records"](root, monkeypatch)
    _dashboard_on(monkeypatch)
    app = _dashboard(root, ON, tmp_path, monkeypatch)
    _, _, page = await _call(app, "GET", "/")
    assert b"Runtime overrides have disappeared from the store" in page


async def test_a_dashboard_on_an_uninitialized_store_is_not_ready_until_init(
        tmp_path, monkeypatch):
    """Mutation: exempt the dashboard from the uninitialized check."""
    from test_dashboard_admin import _call

    root = tmp_path / "s"
    _dashboard_on(monkeypatch)
    app = _dashboard(root, ON, tmp_path, monkeypatch)
    status, _, body = await _call(app, "GET", "/readyz")
    assert status == 503
    assert json.loads(body)["reason"] == "runtime overrides are not initialized"
    assert (await _call(app, "GET", "/healthz"))[0] == 200
    _, _, page = await _call(app, "GET", "/")
    assert b"Runtime overrides are not initialized" in page
    assert b"forgd-verdict overrides init" in page
    _init(LocalFileStore(root, instance="init"))
    app = _dashboard(root, ON, tmp_path, monkeypatch)
    assert (await _call(app, "GET", "/readyz"))[0] == 200


async def test_a_dashboard_is_ready_on_a_valid_object_and_when_off(tmp_path, monkeypatch):
    from test_dashboard_admin import _call

    _dashboard_on(monkeypatch)
    _seed(tmp_path / "s")
    app = _dashboard(tmp_path / "s", ON, tmp_path, monkeypatch)
    assert (await _call(app, "GET", "/readyz"))[0] == 200
    _invalid(tmp_path / "broken", None)
    app = _dashboard(tmp_path / "broken", {}, tmp_path, monkeypatch)
    assert (await _call(app, "GET", "/readyz"))[0] == 200
    assert (await _call(app, "GET", "/healthz"))[0] == 200


# -- the connector ---------------------------------------------------------


def _connector(root, extra, tmp_path):
    pytest.importorskip("mcp", reason="needs forgd-verdict[connector]")
    from test_connector_server import _cfg

    cfg = _cfg(tmp_path)
    return create_connector(cfg, reader_from_policy(make_policy(**extra), cfg,
                                              LocalFileStore(root, instance="t")))


async def _connector_get(root, extra, tmp_path, path):
    """(status, body) from a new connector: each serves one request."""
    from test_connector_server import _call

    status, _, body = await _call(_connector(root, extra, tmp_path), "GET", path)
    return status, json.loads(body)


@pytest.mark.parametrize("case", COLD)
async def test_a_cold_connector_is_not_ready(case, tmp_path, monkeypatch):
    """Mutation: answer 200 from the connector's /readyz, readiness from /healthz,
    or drop Reader.overrides."""
    root = tmp_path / "s"
    COLD[case](root, monkeypatch)
    status, body = await _connector_get(root, ON, tmp_path, "/readyz")
    assert status == 503
    assert body["runtime_overrides"] == STATUS[case]
    status, body = await _connector_get(root, ON, tmp_path, "/healthz")
    assert (status, body["status"]) == (200, "ok")


async def test_a_connector_on_an_uninitialized_store_is_not_ready_until_init(tmp_path):
    root = tmp_path / "s"
    status, body = await _connector_get(root, ON, tmp_path, "/readyz")
    assert status == 503
    assert body["reason"] == "runtime overrides are not initialized"
    assert (await _connector_get(root, ON, tmp_path, "/healthz"))[0] == 200
    _init(LocalFileStore(root, instance="init"))
    assert (await _connector_get(root, ON, tmp_path, "/readyz"))[0] == 200


async def test_a_connector_is_ready_on_a_valid_object_and_when_off(tmp_path):
    _seed(tmp_path / "s")
    assert (await _connector_get(tmp_path / "s", ON, tmp_path, "/readyz"))[0] == 200
    _invalid(tmp_path / "broken", None)
    for path in ("/readyz", "/healthz"):
        assert (await _connector_get(tmp_path / "broken", {}, tmp_path, path))[0] == 200


# -- ingest ----------------------------------------------------------------


@pytest.fixture
def ingest_paths(monkeypatch):
    ran: list[str] = []
    monkeypatch.setattr("forgd_verdict.compliance.ingest.run_ingest",
                        lambda *a, **k: ran.append("compliance") or {})
    monkeypatch.setattr("forgd_verdict.managed.scanner.run_managed_ingest",
                        lambda *a, **k: ran.append("managed") or {})
    return ran


def _ingest(root, extra, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "compliance": {"api_key": "sk-ant-admin01-" + "x" * 20},
        "managed_agents": {"workspaces": [{"name": "w", "api_key": "k"}]}, **extra}))
    return main(["--policy", str(policy), "ingest", "--store", str(root)])


@pytest.mark.parametrize("case", COLD)
def test_a_cold_ingest_exits_before_either_path(case, tmp_path, monkeypatch, capsys,
                                                ingest_paths):
    """Mutation: drop the readiness check from _cmd_ingest."""
    root = tmp_path / "s"
    COLD[case](root, monkeypatch)
    assert _ingest(root, ON, tmp_path) == 1
    assert ingest_paths == []
    out = capsys.readouterr()
    assert "refusing to ingest: the runtime overrides could not be confirmed" in out.err
    assert json.loads(out.out)["runtime_overrides"]["ready"] is False


def test_an_uninitialized_ingest_exits_before_either_path_until_init(tmp_path, capsys,
                                                                    ingest_paths):
    root = tmp_path / "s"
    assert _ingest(root, ON, tmp_path) == 1
    assert ingest_paths == []
    out = capsys.readouterr()
    assert "refusing to ingest" in out.err
    fields = json.loads(out.out)["runtime_overrides"]
    assert fields["ready"] is False
    _init(LocalFileStore(root, instance="init"))
    assert _ingest(root, ON, tmp_path) == 0
    assert ingest_paths == ["compliance", "managed"]


def test_ingest_runs_on_a_valid_object_and_when_off(tmp_path, monkeypatch, capsys,
                                                    ingest_paths):
    _seed(tmp_path / "s")
    assert _ingest(tmp_path / "s", ON, tmp_path) == 0
    assert ingest_paths == ["compliance", "managed"]
    ingest_paths.clear()
    _invalid(tmp_path / "broken", None)
    assert _ingest(tmp_path / "broken", {}, tmp_path) == 0
    assert ingest_paths == ["compliance", "managed"]


# -- an image from before /readyz -----------------------------------------


@pytest.mark.parametrize("name", [*SERVICES, "dashboard", "connector"])
async def test_a_route_an_image_does_not_serve_fails_every_readiness_probe(
        name, tmp_path, monkeypatch):
    """An image from before /readyz routes it as any path it does not serve.
    Kubernetes, Container Apps and Cloud Run count only 200-399 as passing,
    and the ECS target group only 200 (tests/test_app_probes.py), so with
    overrides on such an image is never put into service."""
    root = tmp_path / "s"
    _seed(root)
    if name == "connector":
        status, _ = await _connector_get(root, ON, tmp_path, "/no-such-route")
    elif name == "dashboard":
        from test_dashboard_admin import _call

        _dashboard_on(monkeypatch)
        status, _, _ = await _call(_dashboard(root, ON, tmp_path, monkeypatch), "GET",
                                   "/no-such-route")
    else:
        app = SERVICES[name](root, ON)
        try:
            status, _ = await _get(app, "/no-such-route")
        finally:
            app.close()
    assert not 200 <= status < 400, status
