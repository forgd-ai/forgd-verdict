"""`overrides init`: the one change that writes a store nothing has written.

Until it runs every service with runtime overrides on is not ready. It writes
one audited `state.init` record and an empty object, once; it refuses a store
whose object is invalid, or absent with audit records, and leaves those to
`overrides recover`.
"""

from __future__ import annotations

import json

import pytest
from conftest import DETECTORS, OVERRIDES_KEY, OVERRIDES_PUBLIC_TEXT
from test_dashboard_admin import (  # noqa: F401 - fixtures
    HEADER,
    _app,
    _call,
    _form,
    _headers,
    _token,
    auth,
    pem,
)

from forgd_verdict import overrides as ov
from forgd_verdict.models import CONTROL_STATE
from forgd_verdict.overrides import (
    ACTION_CLEAR,
    ACTION_CLEAR_ALL,
    ACTION_DENY_CLEAR,
    ACTION_DENY_DEVICE,
    ACTION_EXCLUDE,
    ACTION_EXCLUDE_CLEAR,
    ACTION_INIT,
    ACTION_MIGRATE,
    ACTION_RECOVER,
    ACTION_RESET,
    ACTION_RESET_CLEAR,
    ACTION_SET,
    ACTION_UNDENY_DEVICE,
    ACTION_UNEXCLUDE,
    ACTIONS,
    ERROR_ORPHANED,
    ERROR_UNINITIALIZED,
    KEY_MODE,
    Change,
    InvalidState,
    NoChange,
    Refused,
    RuntimeOverrides,
    apply_change,
    parse_state,
    readiness,
)
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import STATE_PREFIX

ADMIN = {"issuer": "https://idp/", "subject": "s", "name": "a", "verified": True}
ADMINS = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
          "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")

_OTHERS = {
    ACTION_SET: Change(ACTION_SET, KEY_MODE, "enforce"),
    ACTION_CLEAR: Change(ACTION_CLEAR, KEY_MODE),
    ACTION_CLEAR_ALL: Change(ACTION_CLEAR_ALL),
    ACTION_RESET: Change(ACTION_RESET, value="2026-09-01T00:00:00Z"),
    ACTION_RESET_CLEAR: Change(ACTION_RESET_CLEAR),
    ACTION_EXCLUDE: Change(ACTION_EXCLUDE, value="req_1"),
    ACTION_UNEXCLUDE: Change(ACTION_UNEXCLUDE, value="req_1"),
    ACTION_EXCLUDE_CLEAR: Change(ACTION_EXCLUDE_CLEAR),
    ACTION_MIGRATE: Change(ACTION_MIGRATE),
    ACTION_RECOVER: Change(ACTION_RECOVER),
    ACTION_DENY_DEVICE: Change(ACTION_DENY_DEVICE, value="d000000000001"),
    ACTION_UNDENY_DEVICE: Change(ACTION_UNDENY_DEVICE, value="d000000000001"),
    ACTION_DENY_CLEAR: Change(ACTION_DENY_CLEAR),
}


@pytest.fixture
def store(tmp_path):
    return LocalFileStore(tmp_path / "s", instance="t")


def _init(store):
    return apply_change(store, ADMIN, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


def _contents(store):
    """Every file under the store, as bytes."""
    root = store.root
    return {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()} \
        if root.exists() else {}


def _requests(store):
    return [json.loads(store.get_audit(n)) for n in store.list_audit()
            if n.endswith("-request.json")]


def _reader(store):
    return RuntimeOverrides(store, "test", baseline={KEY_MODE: "observe"})


# -- the change ------------------------------------------------------------


def test_every_action_is_listed():
    assert set(_OTHERS) | {ACTION_INIT} == ACTIONS


@pytest.mark.parametrize("action", sorted(_OTHERS))
def test_no_other_change_writes_an_uninitialized_store(store, action):
    """Mutation: drop the genesis requirement from apply_change."""
    kwargs = {"migrate": (None, frozenset())} if action == ACTION_MIGRATE else {}
    with pytest.raises(Refused, match=ERROR_UNINITIALIZED):
        apply_change(store, ADMIN, _OTHERS[action], detectors=DETECTORS, signing_key=OVERRIDES_KEY, **kwargs)
    assert _contents(store) == {}


def test_init_writes_one_record_and_an_empty_object(store):
    """Mutation: make init write nothing, or write a non-empty object."""
    applied = _init(store)
    state = parse_state(store.read_control().body)
    assert state == applied.state
    assert (state.revision, state.audit_id) == (1, applied.audit_id)
    assert (dict(state.overrides), state.stats_reset, state.excluded_requests,
            state.legacy_markers_retired, state.retired_by) == ({}, None, frozenset(),
                                                                False, None)
    [record] = _requests(store)
    assert record == applied.record
    assert (record["action"], record["key"], record["old_value"], record["new_value"],
            record["base_revision"], record["base_audit_id"], record["base_hash"]) == (
        ACTION_INIT, None, None, {}, 0, None, None)
    assert record["principal"] == ADMIN


def test_init_again_writes_nothing(store):
    _init(store)
    before = _contents(store)
    with pytest.raises(NoChange, match="already initialized"):
        _init(store)
    assert _contents(store) == before


def test_init_after_changes_writes_nothing(store):
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    before = _contents(store)
    with pytest.raises(NoChange):
        _init(store)
    assert _contents(store) == before
    assert parse_state(store.read_control().body).value(KEY_MODE) == "enforce"


def test_init_refuses_an_orphaned_store(store):
    """Mutation: let init write an absent object whatever the audit prefix holds."""
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    (store.root / STATE_PREFIX / CONTROL_STATE).unlink()
    before = _contents(store)
    with pytest.raises(Refused, match="overrides recover"):
        _init(store)
    assert _contents(store) == before
    assert _reader(store).refresh().error == ERROR_ORPHANED
    apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert _reader(store).refresh().ready


@pytest.mark.parametrize("body", [b"{broken", b"[]", b'{"version": 1, "revision": 1}'])
def test_init_refuses_an_invalid_object(store, body):
    _init(store)
    (store.root / STATE_PREFIX / CONTROL_STATE).write_bytes(body)
    before = _contents(store)
    with pytest.raises(InvalidState):
        _init(store)
    assert _contents(store) == before


def test_an_invalid_object_with_no_records_is_not_initialized_by_init(store):
    (store.root / STATE_PREFIX).mkdir(parents=True)
    (store.root / STATE_PREFIX / CONTROL_STATE).write_bytes(b"{broken")
    with pytest.raises(InvalidState):
        _init(store)
    assert store.list_audit() == []


def test_init_needs_the_control_identity(store, monkeypatch):
    def denied(name, body):
        raise ov.StoreForbidden("the runtime overrides audit prefix")

    monkeypatch.setattr(store, "put_audit", denied)
    with pytest.raises(ov.StoreForbidden):
        _init(store)
    assert store.read_control().status == "absent"


# -- readiness -------------------------------------------------------------


def test_a_cold_reader_is_not_ready_until_init(store):
    """Mutation: treat an absent object with an empty audit prefix as ready."""
    reader = _reader(store)
    snap = reader.refresh()
    assert (snap.ready, snap.error, snap.source) == (False, ERROR_UNINITIALIZED, "baseline")
    code, body = readiness(reader)
    assert code == 503 and body["reason"] == "runtime overrides are not initialized"
    _init(store)
    reader = _reader(store)
    assert reader.refresh().ready
    assert readiness(reader) == (200, {"status": "ok"})


def _orphaned(store):
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    (store.root / STATE_PREFIX / CONTROL_STATE).unlink()


@pytest.mark.parametrize("action", sorted(set(_OTHERS) - {ACTION_RECOVER}))
def test_no_change_but_recover_writes_an_orphaned_store(store, action):
    """Mutation: let set, reset, exclude or clear-all write an absent object
    whose audit records exist."""
    _orphaned(store)
    before = _contents(store)
    kwargs = {"migrate": (None, frozenset())} if action == ACTION_MIGRATE else {}
    with pytest.raises(Refused) as refused:
        apply_change(store, ADMIN, _OTHERS[action], detectors=DETECTORS, signing_key=OVERRIDES_KEY, **kwargs)
    assert str(refused.value) == ov.REFUSED_ORPHANED
    assert "run `forgd-verdict overrides recover`" in str(refused.value)
    assert _contents(store) == before


def test_an_init_whose_object_write_failed_directs_its_retry_to_recover(store, monkeypatch):
    """The request record is written before the object, so an init whose
    object write fails leaves an orphaned store."""
    real = store.write_control

    def fail(body, etag):
        raise OSError("the object write failed")

    monkeypatch.setattr(store, "write_control", fail)
    with pytest.raises(OSError):
        _init(store)
    monkeypatch.setattr(store, "write_control", real)
    assert [r["action"] for r in _requests(store)] == [ACTION_INIT]
    assert store.read_control().body is None
    before = _contents(store)
    with pytest.raises(Refused, match="run `forgd-verdict overrides recover`"):
        _init(store)
    assert _contents(store) == before
    apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert _reader(store).refresh().status == "ok"


# -- the CLI ---------------------------------------------------------------


def _run(tmp_path, *argv):
    from forgd_verdict.cli import main

    policy = tmp_path / "admins.json"
    policy.write_text(json.dumps(ADMINS))
    return main(["--policy", str(policy), *argv])


def test_the_cli_initializes_once(tmp_path, capsys):
    root = tmp_path / "s"
    assert _run(tmp_path, "overrides", "--store", str(root), "init") == 0
    out = json.loads(capsys.readouterr().out)
    store = LocalFileStore(root)
    assert out["revision"] == 1
    assert [(r["action"], r["id"], r["principal"]["issuer"]) for r in _requests(store)] == [
        (ACTION_INIT, out["audit_id"], "cli")]
    before = _contents(store)
    assert _run(tmp_path, "overrides", "--store", str(root), "init") == 0
    assert "nothing to do: the store is already initialized" in capsys.readouterr().err
    assert _contents(store) == before


def test_the_cli_refuses_a_change_before_init(tmp_path, capsys):
    root = tmp_path / "s"
    assert _run(tmp_path, "overrides", "--store", str(root), "set", KEY_MODE, "enforce") == 2
    assert f"refused: {ERROR_UNINITIALIZED}" in capsys.readouterr().err
    assert _contents(LocalFileStore(root)) == {}
    assert _run(tmp_path, "overrides", "--store", str(root), "init") == 0
    assert _run(tmp_path, "overrides", "--store", str(root), "set", KEY_MODE, "enforce") == 0


def test_the_cli_refuses_to_init_an_orphaned_store(tmp_path, capsys):
    root = tmp_path / "s"
    _init(LocalFileStore(root))
    (root / STATE_PREFIX / CONTROL_STATE).unlink()
    assert _run(tmp_path, "overrides", "--store", str(root), "init") == 2
    assert "overrides recover" in capsys.readouterr().err
    assert not (root / STATE_PREFIX / CONTROL_STATE).exists()


@pytest.mark.parametrize("argv", [
    ("overrides", "--store", "{s}", "set", KEY_MODE, "enforce"),
    ("reset-stats", "--store", "{s}", "--at", "2026-09-01T00:00:00Z"),
    ("exclude", "--store", "{s}", "--request-id", "req_1"),
    ("overrides", "--store", "{s}", "clear-all"),
    ("overrides", "--store", "{s}", "init"),
], ids=["set", "reset-stats", "exclude", "clear-all", "init"])
def test_the_cli_refuses_every_write_but_recover_on_an_orphaned_store(tmp_path, capsys, argv):
    root = tmp_path / "s"
    store = LocalFileStore(root)
    _orphaned(store)
    before = _contents(store)
    assert _run(tmp_path, *(a.format(s=root) for a in argv)) == 2
    assert f"refused: {ov.REFUSED_ORPHANED}" in capsys.readouterr().err
    assert _contents(store) == before
    assert _run(tmp_path, "overrides", "--store", str(root), "recover") == 0
    assert parse_state(store.read_control().body).value(KEY_MODE) == "enforce"


def test_the_cli_retry_of_a_failed_init_says_to_recover(tmp_path, capsys, monkeypatch):
    root = tmp_path / "s"
    # Its own context: undoing the fixture's monkeypatch would also unset the keys.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(LocalFileStore, "write_control",
                   lambda self, body, etag: (_ for _ in ()).throw(OSError("failed")))
        with pytest.raises(OSError):
            _run(tmp_path, "overrides", "--store", str(root), "init")
    capsys.readouterr()
    assert _run(tmp_path, "overrides", "--store", str(root), "init") == 2
    assert "run `forgd-verdict overrides recover`" in capsys.readouterr().err
    assert not (root / STATE_PREFIX / CONTROL_STATE).exists()


def test_the_cli_refuses_to_init_an_invalid_object(tmp_path, capsys):
    root = tmp_path / "s"
    _init(LocalFileStore(root))
    (root / STATE_PREFIX / CONTROL_STATE).write_bytes(b"{broken")
    assert _run(tmp_path, "overrides", "--store", str(root), "init") == 1
    assert "overrides recover" in capsys.readouterr().err
    assert (root / STATE_PREFIX / CONTROL_STATE).read_bytes() == b"{broken"


@pytest.mark.parametrize("kind", ["s3", "gcs", "blob"])
def test_the_cli_init_needs_the_control_identity(tmp_path, capsys, monkeypatch, kind):
    import test_store_conformance as fakes

    install, url = {"s3": (fakes._install_fake_boto3, fakes.S3_URL),
                    "gcs": (fakes._install_fake_gcs, fakes.GCS_URL),
                    "blob": (fakes._install_fake_azure, fakes.BLOB_URL)}[kind]
    backend = install(monkeypatch)
    backend.deny_write("audit/runtime-overrides/")
    backend.deny_write("state/runtime-overrides.json")
    assert _run(tmp_path, "overrides", "--store", url, "init") == 2
    err = capsys.readouterr().err
    assert "control identity" in err and "Traceback" not in err


def test_ingest_names_the_missing_init(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    root = tmp_path / "s"
    assert _run(tmp_path, "ingest", "--store", str(root)) == 1
    assert f"refusing to ingest: {ERROR_UNINITIALIZED}" in capsys.readouterr().err


# -- the dashboard ---------------------------------------------------------


async def test_the_dashboard_is_not_ready_but_offers_init(store, auth, pem):  # noqa: F811
    """Mutation: answer 200 from the dashboard's /readyz on an uninitialized store."""
    app = _app(store, auth)
    status, _, body = await _call(app, "GET", "/readyz")
    assert status == 503
    assert json.loads(body)["reason"] == "runtime overrides are not initialized"
    assert (await _call(app, "GET", "/healthz"))[0] == 200
    _, _, page = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert b"Runtime overrides are not initialized" in page
    assert f'value="{ACTION_INIT}"'.encode() in page
    _, _, viewer = await _call(app, "GET", "/policy", {HEADER: _token(pem, groups=["viewers"])})
    assert b"not initialized" in viewer and b"<form" not in viewer


async def test_the_dashboard_initializes_and_becomes_ready(store, auth, pem):  # noqa: F811
    app = _app(store, auth)
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_INIT, "", ""))
    assert (status, headers[b"location"]) == (303, b"/policy?result=applied")
    [record] = _requests(store)
    assert record["action"] == ACTION_INIT
    assert record["principal"]["name"] == "dana" and record["principal"]["verified"] is True
    assert (await _call(app, "GET", "/readyz"))[0] == 200
    _, _, page = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert f'value="{ACTION_INIT}"'.encode() not in page
    before = _contents(store)
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_INIT, "", "", revision=1))
    assert headers[b"location"] == b"/policy?result=nochange"
    assert _contents(store) == before


async def test_the_dashboard_refuses_a_change_before_init(store, auth, pem):  # noqa: F811
    app = _app(store, auth)
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert headers[b"location"] == b"/policy?result=refused"
    assert _contents(store) == {}


async def test_the_dashboard_offers_no_init_on_an_orphaned_store(store, auth, pem):  # noqa: F811
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    (store.root / STATE_PREFIX / CONTROL_STATE).unlink()
    app = _app(store, auth)
    assert (await _call(app, "GET", "/readyz"))[0] == 503
    assert (await _call(app, "GET", "/healthz"))[0] == 200
    _, _, page = await _call(app, "GET", "/policy", {HEADER: _token(pem)})
    assert f'value="{ACTION_INIT}"'.encode() not in page
    before = _contents(store)
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_INIT, "", ""))
    assert headers[b"location"] == b"/policy?result=refused"
    assert _contents(store) == before


async def test_the_dashboard_init_needs_the_control_identity(store, auth, pem, monkeypatch):  # noqa: F811
    app = _app(store, auth)

    def denied(name, body):
        raise ov.StoreForbidden("the runtime overrides audit prefix")

    monkeypatch.setattr(store, "put_audit", denied)
    status, headers, _ = await _call(app, "POST", "/admin/actions", _headers(pem),
                                     _form(app, ACTION_INIT, "", ""))
    assert headers[b"location"] == b"/policy?result=error"
    assert store.read_control().status == "absent"
