"""Every service reads the runtime overrides; the ones with a field apply it.

The verdict server and the intake apply `server.mode`. The dashboard and the
connector apply the marker fields. The collector and the ingest jobs have no
field to apply and report the object's status. The CLI writes through the
same audited path the dashboard does.
"""

from __future__ import annotations

import json

import pytest
from conftest import (
    DETECTORS,
    FAKE_AWS_KEY,
    FAKE_GITHUB_TOKEN,
    OVERRIDES_KEY,
    OVERRIDES_PUBLIC_TEXT,
    WHSEC,
    ASGIClient,
    frame,
    make_policy,
    sign,
    text_msg,
)

from forgd_verdict import overrides as ov
from forgd_verdict.overrides import (
    ACTION_EXCLUDE,
    ACTION_INIT,
    ACTION_SET,
    ERROR_UNINITIALIZED,
    KEY_MODE,
    REFRESH_S,
    Change,
    apply_change,
    parse_state,
)
from forgd_verdict.store import LocalFileStore

ADMIN = {"issuer": "https://idp/", "subject": "s", "name": "a", "verified": True}
# Runtime overrides are on only when dashboard.admins lists groups.
ADMINS = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
          "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")


class Clock:
    t = 5000.0

    def __call__(self):
        return self.t


def _init(store):
    apply_change(store, ADMIN, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


async def _post(server, request_id):
    raw = json.dumps(frame([text_msg(f"key {FAKE_AWS_KEY}")], request_id=request_id)).encode()
    return await ASGIClient(server).post("/hook", raw, sign(raw, webhook_id=request_id))


@pytest.fixture
def served(tmp_path, monkeypatch):
    """A verdict server, which holds no signing key."""
    from forgd_verdict.server.app import VerdictServer

    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")

    root = tmp_path / "store"
    store = LocalFileStore(root, instance="admin")
    _init(store)
    server = VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": None,
                "store": str(root), "store_flush_s": 3600}, **ADMINS))
    yield server, store
    server.close()


async def test_the_verdict_server_is_not_ready_until_the_store_is_initialized(tmp_path,
                                                                            monkeypatch):
    from forgd_verdict.server.app import VerdictServer

    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")

    root = tmp_path / "store"
    server = VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": None,
                "store": str(root), "store_flush_s": 3600}, **ADMINS))
    try:
        snap = server.overrides.current()
        assert (snap.error, snap.ready) == (ERROR_UNINITIALIZED, False)
        status, body = await ASGIClient(server).get("/readyz")
        assert status == 503 and body["reason"] == "runtime overrides are not initialized"
        assert (await ASGIClient(server).get("/healthz"))[0] == 200
        _init(LocalFileStore(root, instance="admin"))
        assert server.overrides.refresh().ready
        assert (await ASGIClient(server).get("/readyz"))[0] == 200
    finally:
        server.close()


async def test_the_verdict_server_enforces_within_the_refresh_window(served):
    server, store = served
    clock = Clock()
    server.overrides.clock = clock
    server.overrides.refresh()
    assert (await _post(server, "req_a"))[1]["action"] == "allow"

    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    clock.t += REFRESH_S - 1
    assert (await _post(server, "req_b"))[1]["action"] == "allow"
    clock.t += 1
    status, verdict = await _post(server, "req_c")
    assert status == 200 and verdict["action"] == "deny"
    assert server.mode == "enforce"


async def test_the_verdict_server_reports_the_object_in_metrics(served):
    server, store = served
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    server.overrides.refresh()
    body = server._metrics_body()
    assert body["runtime_overrides"]["status"] == "ok"
    assert body["runtime_overrides"]["keys"] == ["server.mode"]
    assert body["runtime_overrides"]["in_error"] == 0
    assert body["mode"] == "enforce"
    (store.root / "state" / "runtime-overrides.json").write_bytes(b"{broken")
    server.overrides.refresh()
    assert server._metrics_body()["runtime_overrides"]["in_error"] == 1


async def test_the_intake_applies_a_mode_override(tmp_path, monkeypatch):
    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    from test_scan_frames import _policy, auth, user
    from test_scan_frames import frame as scan_frame

    from forgd_verdict.intake.app import Intake
    from forgd_verdict.policy import Policy, _deep_merge

    store = LocalFileStore(tmp_path, instance="t")
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    app = Intake(Policy(raw=_deep_merge(_policy().raw, ADMINS)), store=store)
    try:
        assert app.policy.mode == "observe"
        status, body = await ASGIClient(app).post(
            "/scan", scan_frame([user(f"deploy with {FAKE_AWS_KEY}")]), auth())
    finally:
        app.close()
    assert status == 200 and body["action"] == "deny"
    assert app.stats()["runtime_overrides"]["status"] == "ok"


def test_the_collector_reads_the_object(tmp_path, monkeypatch):
    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    from forgd_verdict.otel.app import Collector

    store = LocalFileStore(tmp_path / "findings", instance="t")
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    app = Collector(make_policy(**ADMINS), store=store)
    try:
        assert app.stats()["runtime_overrides"]["status"] == "ok"
    finally:
        app.close()


def test_the_ingest_run_summary_reports_the_object(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    from forgd_verdict.cli import main

    root = tmp_path / "findings"
    store = LocalFileStore(root, instance="t")
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"compliance": {"api_key": ""}, **ADMINS}))
    assert main(["--policy", str(policy), "ingest", "--store", str(root)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["runtime_overrides"]["status"] == "ok"


def test_the_connector_combines_the_markers(tmp_path, monkeypatch):
    monkeypatch.delenv("FORGD_OVERRIDES_SIGNING_KEY")
    from forgd_verdict.connector.tools import reader_from_policy

    store = LocalFileStore(tmp_path, instance="t")
    store.set_excluded(["req_legacy"])
    _init(store)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_new"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)

    class Cfg:
        auth = None
        entitlements = None

    reader = reader_from_policy(make_policy(**ADMINS), Cfg(), store)
    assert reader.store.get_excluded() == {"req_legacy", "req_new"}


# -- the CLI ---------------------------------------------------------------


def _run(tmp_path, *argv):
    from forgd_verdict.cli import main

    policy = tmp_path / "admins.json"
    policy.write_text(json.dumps(ADMINS))
    return main(["--policy", str(policy), *argv])


def _state(root):
    return parse_state(LocalFileStore(root, instance="r").read_control().body)


def _init_cli(tmp_path, root):
    assert _run(tmp_path, "overrides", "--store", str(root), "init") == 0


def _requests(store):
    return [json.loads(store.get_audit(n)) for n in store.list_audit()
            if n.endswith("-request.json")]


def test_the_cli_refuses_every_change_until_init(tmp_path, capsys):
    root, s = tmp_path / "s", str(tmp_path / "s")
    for argv in (("exclude", "--store", s, "--request-id", "req_1"),
                 ("reset-stats", "--store", s, "--at", "2026-09-01T00:00:00Z"),
                 ("overrides", "--store", s, "set", "server.mode", "enforce"),
                 ("overrides", "--store", s, "migrate-markers")):
        assert _run(tmp_path, *argv) == 2, argv
        assert f"refused: {ERROR_UNINITIALIZED}" in capsys.readouterr().err, argv
    assert not root.exists() or not LocalFileStore(root).list_audit()

    _init_cli(tmp_path, root)
    state = _state(root)
    assert state.revision == 1 and not state.overrides and not state.excluded_requests
    assert [(r["action"], r["principal"]["issuer"]) for r in _requests(LocalFileStore(root))] == [
        (ACTION_INIT, "cli")]
    audits = LocalFileStore(root).list_audit()
    capsys.readouterr()
    assert _run(tmp_path, "overrides", "--store", s, "init") == 0
    assert "nothing to do" in capsys.readouterr().err
    assert LocalFileStore(root).list_audit() == audits
    assert _run(tmp_path, "exclude", "--store", s, "--request-id", "req_1") == 0


def test_exclude_writes_the_field_and_not_the_legacy_object(tmp_path, capsys):
    root = tmp_path / "s"
    _init_cli(tmp_path, root)
    assert _run(tmp_path, "exclude", "--store", str(root), "--request-id", "req_1") == 0
    assert _state(root).excluded_requests == {"req_1"}
    assert not (root / "markers" / "excluded_requests").exists()
    [record] = [r for r in _requests(LocalFileStore(root)) if r["action"] == ACTION_EXCLUDE]
    assert record["principal"]["issuer"] == "cli"
    assert record["principal"]["verified"] is False


def test_reset_stats_writes_the_field(tmp_path):
    root = tmp_path / "s"
    _init_cli(tmp_path, root)
    assert _run(tmp_path, "reset-stats", "--store", str(root),
                "--at", "2026-09-01T00:00:00Z") == 0
    assert _state(root).stats_reset == "2026-09-01T00:00:00Z"
    assert LocalFileStore(root).get_reset_marker() is None
    assert _run(tmp_path, "reset-stats", "--store", str(root), "--at", "yesterday") == 2


def _markers(root):
    return {n: (root / "markers" / n).read_bytes() for n in ("stats_reset", "excluded_requests")
            if (root / "markers" / n).exists()}


def _legacy(root):
    legacy = LocalFileStore(root)
    legacy.set_excluded(["req_legacy"])
    legacy.set_reset_marker("2026-09-01T00:00:00Z")
    return legacy


def test_clears_never_touch_the_legacy_markers_and_warn_before_retirement(tmp_path, capsys):
    """Mutation: blank the legacy object in either --clear path."""
    root, s = tmp_path / "s", str(tmp_path / "s")
    _legacy(root)
    before = _markers(root)
    assert len(before) == 2
    _init_cli(tmp_path, root)
    assert _run(tmp_path, "exclude", "--store", s, "--request-id", "req_1") == 0
    assert _run(tmp_path, "reset-stats", "--store", s, "--at", "2026-09-10T00:00:00Z") == 0
    capsys.readouterr()
    assert _run(tmp_path, "exclude", "--store", s, "--clear") == 0
    assert "markers/excluded_requests object still apply" in capsys.readouterr().err
    assert _run(tmp_path, "reset-stats", "--store", s, "--clear") == 0
    assert "markers/stats_reset object still applies" in capsys.readouterr().err
    state = _state(root)
    assert (state.excluded_requests, state.stats_reset) == (frozenset(), None)
    assert _markers(root) == before

    assert _run(tmp_path, "overrides", "--store", s, "migrate-markers") == 0
    capsys.readouterr()
    assert _run(tmp_path, "exclude", "--store", s, "--clear") == 0
    assert _run(tmp_path, "reset-stats", "--store", s, "--clear") == 0
    assert "warning" not in capsys.readouterr().err, "retired markers do not apply"
    assert _markers(root) == before


def test_migrate_markers_folds_retires_and_is_idempotent(tmp_path, capsys):
    """Mutation: let a second migration through once retired."""
    root, s = tmp_path / "s", str(tmp_path / "s")
    legacy = _legacy(root)
    before = _markers(root)
    _init_cli(tmp_path, root)
    assert _run(tmp_path, "overrides", "--store", s, "migrate-markers") == 0
    state = _state(root)
    assert state.excluded_requests == {"req_legacy"}
    assert state.stats_reset == "2026-09-01T00:00:00Z"
    assert state.legacy_markers_retired is True
    assert _markers(root) == before, "the legacy objects are read, never written"
    requests = [r for r in _requests(legacy) if r["action"] != ACTION_INIT]
    assert [(r["action"], r["principal"]["issuer"], r["new_value"]) for r in requests] == [
        ("legacy.migrate", "cli", {"stats_reset": "2026-09-01T00:00:00Z",
                                   "excluded_requests": ["req_legacy"],
                                   "legacy_markers_retired": True})]

    legacy.set_excluded(["req_later"])
    legacy.set_reset_marker("2099-01-01T00:00:00Z")
    audits = legacy.list_audit()
    capsys.readouterr()
    assert _run(tmp_path, "overrides", "--store", s, "migrate-markers") == 0
    assert "already retired" in capsys.readouterr().err
    assert legacy.list_audit() == audits
    assert _state(root) == state


def test_migrate_markers_retires_empty_legacy_markers_too(tmp_path):
    root = tmp_path / "s"
    _init_cli(tmp_path, root)
    assert _run(tmp_path, "overrides", "--store", str(root), "migrate-markers") == 0
    assert _state(root).legacy_markers_retired is True
    assert _markers(root) == {}


def test_overrides_set_clear_and_recover(tmp_path):
    root = tmp_path / "s"
    s = str(root)
    _init_cli(tmp_path, root)
    assert _run(tmp_path, "overrides", "--store", s, "set", "server.mode", "enforce") == 0
    assert _state(root).value(KEY_MODE) == "enforce"
    assert _run(tmp_path, "overrides", "--store", s, "set", "detectors.x", "false") == 2
    assert _run(tmp_path, "overrides", "--store", s, "clear-all") == 0
    assert _state(root).value(KEY_MODE) is None
    (root / "state" / "runtime-overrides.json").write_text("{nope")
    assert _run(tmp_path, "overrides", "--store", s, "set", "server.mode", "observe") == 1
    assert _run(tmp_path, "overrides", "--store", s, "recover", "--mode", "enforce") == 0
    assert _state(root).value(KEY_MODE) == "enforce"
    assert _run(tmp_path, "overrides", "--store", s, "recover") == 2


def _files(root) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(root.rglob("*"))
                    if p.is_file() and "markers" not in p.parts)


@pytest.mark.parametrize("argv", [
    ("exclude", "--request-id", FAKE_GITHUB_TOKEN),
    ("exclude", "--request-id", "req_1", "--request-id", f"PreToolUse:Bash:{FAKE_AWS_KEY}"),
    ("reset-stats", "--at", FAKE_GITHUB_TOKEN),
    ("overrides", "set", "server.mode", FAKE_GITHUB_TOKEN),
    ("overrides", "set", FAKE_GITHUB_TOKEN, "enforce"),
    ("overrides", "clear", FAKE_GITHUB_TOKEN),
], ids=lambda a: " ".join(a[:2]))
def test_the_cli_refuses_a_value_a_detector_matches(tmp_path, capsys, argv):
    """Mutation: drop the screen at the top of apply_change."""
    root = tmp_path / "s"
    _init_cli(tmp_path, root)
    command, *rest = argv
    assert _run(tmp_path, command, "--store", str(root), *rest) == 2
    err = capsys.readouterr().err
    assert "matched a detector: " in err and "regex:" in err
    assert FAKE_GITHUB_TOKEN not in err and FAKE_AWS_KEY not in err
    stored = _files(root)
    assert FAKE_GITHUB_TOKEN.encode() not in stored
    assert FAKE_AWS_KEY.encode() not in stored
    assert b"PreToolUse" not in stored


def test_migrate_markers_leaves_a_legacy_value_a_detector_matches(tmp_path):
    root, s = tmp_path / "s", str(tmp_path / "s")
    LocalFileStore(root).set_excluded(["req_legacy", FAKE_GITHUB_TOKEN])
    _init_cli(tmp_path, root)
    assert _run(tmp_path, "overrides", "--store", s, "migrate-markers") == 0
    state = _state(root)
    assert state.excluded_requests == {"req_legacy"}
    assert state.legacy_markers_retired is True
    assert FAKE_GITHUB_TOKEN.encode() not in _files(root)


def test_the_cli_refuses_to_change_without_its_detectors(tmp_path, capsys):
    root = tmp_path / "s"
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"detectors": {"gitleaks": {
        "enabled": True, "severity": "block", "binary": str(tmp_path / "no-gitleaks")}},
        **ADMINS}))
    from forgd_verdict.cli import main

    assert main(["--policy", str(policy), "exclude", "--store", str(root),
                 "--request-id", "req_1"]) == 2
    assert "gitleaks is required here but unavailable" in capsys.readouterr().err
    assert not root.exists() or not LocalFileStore(root).list_audit()


def test_the_cli_refuses_a_login_name_a_detector_matches(tmp_path, capsys, monkeypatch):
    root = tmp_path / "s"
    monkeypatch.setattr("getpass.getuser", lambda: FAKE_GITHUB_TOKEN)
    assert _run(tmp_path, "overrides", "--store", str(root), "init") == 2
    err = capsys.readouterr().err
    assert "matched a detector: " in err and FAKE_GITHUB_TOKEN not in err
    assert not root.exists() or FAKE_GITHUB_TOKEN.encode() not in _files(root)
    monkeypatch.setattr("getpass.getuser", lambda: "ops")
    _init_cli(tmp_path, root)
    monkeypatch.setattr("getpass.getuser", lambda: FAKE_GITHUB_TOKEN)
    assert _run(tmp_path, "exclude", "--store", str(root), "--request-id", "req_1") == 2
    err = capsys.readouterr().err
    assert "matched a detector: " in err and FAKE_GITHUB_TOKEN not in err
    assert FAKE_GITHUB_TOKEN.encode() not in _files(root)


def test_recover_rejects_keep_markers(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        _run(tmp_path, "overrides", "--store", str(tmp_path / "s"), "recover", "--keep-markers")
    assert exc.value.code == 2
    assert "unrecognized arguments: --keep-markers" in capsys.readouterr().err
    assert not (tmp_path / "s").exists()


def test_cli_recover_after_migration_keeps_the_markers_retired(tmp_path):
    root, s = tmp_path / "s", str(tmp_path / "s")
    _legacy(root)
    _init_cli(tmp_path, root)
    assert _run(tmp_path, "overrides", "--store", s, "migrate-markers") == 0
    migrated = _state(root)
    path = root / "state" / "runtime-overrides.json"
    path.write_text(path.read_text().replace('"version": 1', '"version": 99'))
    assert _run(tmp_path, "overrides", "--store", s, "recover") == 0
    state = _state(root)
    assert state.legacy_markers_retired
    assert (state.stats_reset, state.excluded_requests) == (migrated.stats_reset,
                                                            migrated.excluded_requests)


@pytest.mark.parametrize("kind", ["s3", "gcs", "blob"])
@pytest.mark.parametrize("argv", [("exclude", "--request-id", "req_1"),
                                  ("reset-stats", "--at", "2026-09-01T00:00:00Z"),
                                  ("exclude", "--clear"), ("reset-stats", "--clear")])
def test_writer_only_credentials_get_a_clear_refusal(tmp_path, capsys, monkeypatch, kind, argv):
    """Mutation: drop the CLI's StoreForbidden branch, or a store's 403 mapping."""
    import test_store_conformance as fakes

    install, url = {"s3": (fakes._install_fake_boto3, fakes.S3_URL),
                    "gcs": (fakes._install_fake_gcs, fakes.GCS_URL),
                    "blob": (fakes._install_fake_azure, fakes.BLOB_URL)}[kind]
    backend = install(monkeypatch)
    store = backend.make_store("seed")
    _init(store)
    if argv[1] == "--clear":
        apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_0"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
        apply_change(store, ADMIN, Change(ov.ACTION_RESET, value="2026-08-01T00:00:00Z"),
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    backend.deny_write("audit/runtime-overrides/")
    backend.deny_write("state/runtime-overrides.json")
    command, *rest = argv
    assert _run(tmp_path, command, "--store", url, *rest) == 2
    err = capsys.readouterr().err
    assert "refused: these credentials may not write the runtime overrides audit prefix" in err
    assert "control identity" in err and "Traceback" not in err



# A made-up org id, set only through the environment as policy.yaml does.
ORG_ID = "00000000-0000-4000-8000-00000000c0de"
ORG_SECTIONS = {
    "orgs": {"orgs": [{"id": "$FORGD_ORG_ID_PROD", "label": "prod"}]},
    "compliance": {"compliance": {"orgs": [{"id": "$FORGD_ORG_ID_PROD", "label": "prod"}]}},
    "otel.orgs": {"otel": {"orgs": [{"id": "$FORGD_ORG_ID_PROD", "label": "prod"}]}},
}


@pytest.mark.parametrize("section", sorted(ORG_SECTIONS))
@pytest.mark.parametrize("value", [ORG_ID, ORG_ID.upper()])
def test_the_cli_refuses_to_exclude_an_org_id(tmp_path, capsys, monkeypatch, section, value):
    """Mutation: drop the org id check, or pass the CLI no org ids."""
    monkeypatch.setenv("FORGD_ORG_ID_PROD", ORG_ID)
    root = tmp_path / "s"
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({**ORG_SECTIONS[section], **ADMINS}))
    from forgd_verdict.cli import main

    _init(LocalFileStore(root, instance="admin"))
    audits = LocalFileStore(root).list_audit()
    assert main(["--policy", str(policy), "exclude", "--store", str(root),
                 "--request-id", value]) == 2
    out, err = capsys.readouterr()
    assert "is a configured organization id" in err
    assert ORG_ID not in (out + err).lower()
    assert LocalFileStore(root).list_audit() == audits
    assert main(["--policy", str(policy), "exclude", "--store", str(root),
                 "--request-id", "req_1"]) == 0
