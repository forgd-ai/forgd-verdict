"""The writer lockout probe, and the dashboard's refusal without its reports.

A writer role honours runtime overrides only while a create under the audit
prefix, made with its own credentials, is refused with a 403. The mutations:
a store that lets the probe create disables the overrides, fails readiness
and blocks admin actions; one that refuses it with a 403 honours them.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import pytest
from conftest import DETECTORS, OVERRIDES_KEY, OVERRIDES_PUBLIC_TEXT  # noqa: I001
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forgd_verdict import lockout
from forgd_verdict import overrides_signing as sig
from forgd_verdict.lockout import (
    ENV_WRITER_ROLES,
    LOCKOUT_MISSING,
    PROBE_S,
    RESULT_ALLOWED,
    RESULT_DENIED,
    RESULT_EXEMPT,
    RESULT_UNPROVEN,
    RETRY_S,
    UNPROVABLE_STORE,
    VERIFIED_FRESH_S,
    LockoutProbe,
    LockoutReports,
    expected_roles,
    is_probe,
    lockout_status,
    probe,
    report_name,
)
from forgd_verdict.overrides import (
    ACTION_INIT,
    ACTION_SET,
    ENV_ENABLED,
    ERROR_UNINITIALIZED,
    KEY_MODE,
    STATUS_DISABLED,
    Change,
    RuntimeOverrides,
    apply_change,
    highest_revision,
    history,
    reader_for,
    readiness,
)
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import AUDIT_PREFIX, StoreConflict, StoreForbidden, StoreReadError

ON = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
     "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}
ACTOR = {"issuer": "cli", "subject": "t", "name": "t", "verified": False}
NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=UTC)


WRITER = "arn:aws:iam::111111111111:role/forgd-verdict-writer"
COLLECTOR = "arn:aws:iam::111111111111:role/forgd-collector-writer"


def _verified(store, failing=None, at=None, identities=(WRITER, COLLECTOR)):
    """A verification record, as the control identity writes it, showing
    every identity locked out but those in `failing`."""
    results = {i: (failing or {}).get(i) for i in identities}
    return lockout.write_verification(store, results, "s3", at or datetime.now(UTC),
                                      OVERRIDES_KEY)


def _unverify(store):
    for path in store.root.rglob(f"{lockout.VERIFY_PREFIX}*.json"):
        path.unlink()


class CloudStore(LocalFileStore):
    """A local store that answers the probe as a cloud store would: with a
    403 when `deny`, and with a create otherwise. Control writes succeed, as
    they do for the control identity. With `verified`, it starts with a
    fresh verification record showing every writer locked out."""

    lockout_provable = True

    def __init__(self, root, deny: bool = True, error: Exception | None = None,
                 verified: bool = True):
        super().__init__(root, instance="t")
        self.deny = deny
        self.error = error
        self.probes: list[str] = []
        if verified:
            _verified(self)

    def put_audit(self, name, body):
        if name.rsplit("/", 1)[-1].startswith(lockout.PROBE_PREFIX):
            self.probes.append(name)
            if self.error is not None:
                raise self.error
            if self.deny:
                raise StoreForbidden("the runtime overrides audit prefix")
        super().put_audit(name, body)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv(ENV_ENABLED, "true")
    monkeypatch.setenv(ENV_WRITER_ROLES, "verdict")
    monkeypatch.setattr(lockout, "_unprovable_allowed", False)
    monkeypatch.setenv("FORGD_OVERRIDES_VERIFY_KEY", OVERRIDES_PUBLIC_TEXT)


def _anchoring(store):
    """The dashboard's verifier, which writes a record naming each head a
    change writes."""
    from forgd_verdict.lockout_evidence.verifier import Verifier

    return Verifier(store, identities=(WRITER, COLLECTOR),
                    evaluate=lambda s, ids, **_: dict.fromkeys(ids), signing_key=OVERRIDES_KEY)


def _init(store):
    apply_change(store, ACTOR, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY,
                 after_write=_anchoring(store).after_write)


def _enforce(store):
    apply_change(store, ACTOR, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS,
                 signing_key=OVERRIDES_KEY, after_write=_anchoring(store).after_write)


def _report(store, role):
    blob = store.get_state(report_name(role))
    return json.loads(blob) if blob else None


# -- the probe -------------------------------------------------------------


def test_a_403_proves_the_lockout(tmp_path):
    store = CloudStore(tmp_path, deny=True, verified=False)
    found = probe(store, "verdict", "i-1", NOW)
    assert found.result == RESULT_DENIED and found.proven
    assert store.list_audit() == []
    assert store.probes == ["2026-09-28/probe-verdict-i-1-20260928T120000Z.json"]


def test_a_create_that_succeeds_is_a_missing_lockout(tmp_path):
    store = CloudStore(tmp_path, deny=False, verified=False)
    found = probe(store, "collector", "i-1", NOW)
    assert found.result == RESULT_ALLOWED and not found.proven
    assert store.list_audit() == ["2026-09-28/probe-collector-i-1-20260928T120000Z.json"]


@pytest.mark.parametrize("error,name", [
    (StoreConflict("exists"), "StoreConflict"),
    (StoreReadError("down"), "StoreReadError"),
    (OSError("reset"), "OSError"),
])
def test_any_other_outcome_proves_nothing(tmp_path, error, name):
    found = probe(CloudStore(tmp_path, error=error), "intake", "i-1", NOW)
    assert (found.result, found.error, found.proven) == (RESULT_UNPROVEN, name, False)


def test_a_local_store_cannot_prove_it(tmp_path, monkeypatch):
    monkeypatch.setattr(lockout, "_unprovable_allowed", False)
    store = LocalFileStore(tmp_path)
    found = probe(store, "verdict", "i-1", NOW)
    assert (found.result, found.error) == (RESULT_UNPROVEN, UNPROVABLE_STORE)
    assert store.list_audit() == []
    monkeypatch.setattr(lockout, "_unprovable_allowed", True)
    assert probe(store, "verdict", "i-1", NOW).result == RESULT_EXEMPT


def test_the_cloud_stores_say_they_can_prove_it():
    from forgd_verdict.store.blob import BlobStore
    from forgd_verdict.store.gcs import GCSStore
    from forgd_verdict.store.s3 import S3Store

    assert all(lockout.provable(c) for c in (S3Store, GCSStore, BlobStore))
    assert not lockout.provable(LocalFileStore)
    assert not lockout.provable(object())


def test_probe_names_are_unique_per_instance_and_fit_an_audit_name():
    from forgd_verdict.store.base import safe_audit_name

    a, b = lockout.new_instance(), lockout.new_instance()
    assert a != b
    name = lockout.probe_name("ingest", a, NOW)
    assert safe_audit_name(name) == name and is_probe(name)
    assert not is_probe("2026-09-28/20260928T120000Z-0123456789ab-request.json")


# -- the reader ------------------------------------------------------------


def test_mutation_an_allowed_create_disables_overrides(tmp_path, enabled, caplog):
    store = CloudStore(tmp_path, deny=False)
    _init(store)
    _enforce(store)
    with caplog.at_level(logging.ERROR, "forgd_verdict"):
        reader = reader_for(ON, store, "verdict", baseline={KEY_MODE: "observe"})
        snap = reader.refresh()
    assert reader.mode("observe") == "observe"
    assert (snap.status, snap.error, snap.ready, snap.in_error) == (
        STATUS_DISABLED, LOCKOUT_MISSING, False, True)
    assert snap.fields()["lockout"] == RESULT_ALLOWED
    assert readiness(reader) == (503, {
        "status": "not_ready", "reason": f"runtime overrides {LOCKOUT_MISSING}",
        "runtime_overrides": STATUS_DISABLED})
    assert _report(store, "verdict")["result"] == RESULT_ALLOWED
    assert any("writer lockout missing" in r.getMessage() and r.levelno == logging.ERROR
               for r in caplog.records)


def test_mutation_a_denied_create_honours_overrides(tmp_path, enabled):
    store = CloudStore(tmp_path, deny=True)
    _init(store)
    _enforce(store)
    reader = reader_for(ON, store, "verdict", baseline={KEY_MODE: "observe"})
    snap = reader.refresh()
    assert reader.mode("observe") == "enforce"
    assert snap.ready and not snap.in_error
    assert snap.fields()["lockout"] == RESULT_DENIED
    assert readiness(reader) == (200, {"status": "ok"})
    report = _report(store, "verdict")
    assert report["result"] == RESULT_DENIED and report["role"] == "verdict"


@pytest.mark.parametrize("role", ["verdict", "collector", "intake", "ingest"])
def test_every_writer_role_probes(tmp_path, enabled, role):
    store = CloudStore(tmp_path, deny=False)
    reader = reader_for(ON, store, role)
    assert reader.lockout is not None and reader.fleet is not None
    snap = reader.refresh()
    assert (snap.error, snap.ready) == (LOCKOUT_MISSING, False)


@pytest.mark.parametrize("role", ["dashboard", "connector", "cli"])
def test_readers_that_are_not_writers_do_not_probe(tmp_path, enabled, role):
    store = CloudStore(tmp_path, deny=False)
    reader = reader_for(ON, store, role)
    assert reader.lockout is None and reader.fleet is not None
    reader.refresh()
    assert store.probes == []


def test_nothing_probes_with_the_feature_off(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_ENABLED, raising=False)
    store = CloudStore(tmp_path, deny=False)
    reader_for(ON, store, "verdict").refresh()
    reader_for({}, store, "verdict").refresh()
    assert store.probes == []


def test_a_local_store_disables_overrides_without_the_test_opt_in(tmp_path, enabled):
    store = LocalFileStore(tmp_path)
    _init(store)
    _enforce(store)
    reader = reader_for(ON, store, "intake", baseline={KEY_MODE: "observe"})
    snap = reader.refresh()
    assert (snap.error, snap.lockout, snap.ready) == (LOCKOUT_MISSING, RESULT_UNPROVEN, False)
    assert reader.mode("observe") == "observe"


def test_a_local_store_honours_overrides_with_the_test_opt_in(tmp_path, enabled, monkeypatch):
    monkeypatch.setattr(lockout, "_unprovable_allowed", True)
    store = LocalFileStore(tmp_path)
    _init(store)
    _enforce(store)
    reader = reader_for(ON, store, "intake", baseline={KEY_MODE: "observe"})
    assert reader.refresh().lockout == RESULT_EXEMPT
    assert reader.mode("observe") == "enforce"
    assert store.get_state(report_name("intake")) is None


def test_a_lockout_lost_while_running_keeps_the_last_known_good(tmp_path, enabled):
    store = CloudStore(tmp_path, deny=True)
    _init(store)
    _enforce(store)
    clock = Clock()
    reader = RuntimeOverrides(store, "verdict", baseline={KEY_MODE: "observe"}, clock=clock,
                              lockout=LockoutProbe(store, "verdict", clock=clock))
    assert reader.refresh().ready and reader.mode("observe") == "enforce"
    store.deny = False
    clock.t = PROBE_S
    snap = reader.refresh()
    assert (snap.lockout, snap.source, snap.status, snap.error) == (
        RESULT_ALLOWED, "last_known_good", STATUS_DISABLED, LOCKOUT_MISSING)
    assert not snap.ready and snap.in_error and snap.fields()["in_error"] == 1
    assert snap.state.value(KEY_MODE) == "enforce"
    assert reader.mode("observe") == "enforce"
    assert readiness(reader) == (503, {
        "status": "not_ready", "reason": f"runtime overrides {LOCKOUT_MISSING}",
        "runtime_overrides": STATUS_DISABLED})
    store.deny = True
    clock.t += RETRY_S
    assert reader.refresh().ready and reader.mode("observe") == "enforce"


# -- cadence ---------------------------------------------------------------


def test_a_proven_lockout_is_reproven_hourly(tmp_path):
    store, clock = CloudStore(tmp_path), Clock()
    p = LockoutProbe(store, "verdict", clock=clock)
    p.check()
    clock.t = PROBE_S - 1
    p.check()
    assert len(store.probes) == 1
    clock.t = PROBE_S
    p.check()
    assert len(store.probes) == 2


def test_a_missing_lockout_is_retried_every_few_minutes(tmp_path):
    store, clock = CloudStore(tmp_path, deny=False), Clock()
    p = LockoutProbe(store, "verdict", clock=clock)
    p.check()
    clock.t = RETRY_S - 1
    p.check()
    assert len(store.probes) == 1
    clock.t = RETRY_S
    p.check()
    assert len(store.probes) == 2


def test_an_error_keeps_a_recent_proof_and_retries(tmp_path):
    store, clock = CloudStore(tmp_path), Clock()
    p = LockoutProbe(store, "verdict", clock=clock)
    assert p.check().proven
    store.error = StoreReadError("down")
    clock.t = PROBE_S
    assert p.check().proven
    clock.t += 1
    assert p.check().proven
    assert len(store.probes) == 3
    clock.t = 2 * PROBE_S
    assert p.check().result == RESULT_UNPROVEN


def test_an_error_before_any_proof_is_unproven_and_retried(tmp_path):
    store, clock = CloudStore(tmp_path, error=OSError("x")), Clock()
    p = LockoutProbe(store, "collector", clock=clock)
    assert p.check().result == RESULT_UNPROVEN
    assert p.check().result == RESULT_UNPROVEN
    assert len(store.probes) == 2
    assert _report(store, "collector")["error"] == "OSError"


# -- probe records are not audit records -----------------------------------


def test_probe_records_are_ignored_by_audit_parsing(tmp_path, enabled):
    store = CloudStore(tmp_path, deny=False)
    reader_for(ON, store, "verdict").refresh()
    assert [n for n in store.list_audit() if is_probe(n)]
    cold = RuntimeOverrides(store, "dashboard")
    snap = cold.refresh()
    assert (snap.status, snap.error, snap.ready) == ("absent", ERROR_UNINITIALIZED, False), (
        "a probe record is not an orphaned chain")
    assert highest_revision(store) == 0
    assert history(store, None).not_applied == []
    _init(store)
    assert cold.refresh().ready
    _enforce(store)
    applied = history(store, cold.refresh().state).applied
    assert [r["action"] for r in applied] == [ACTION_SET, ACTION_INIT]


# -- the dashboard's view --------------------------------------------------


def _publish(store, role, result=RESULT_DENIED, at=NOW):
    body = {"version": 1, "role": role, "instance": "i", "result": result,
            "at": at.strftime("%Y-%m-%dT%H:%M:%SZ")}
    store.put_state(report_name(role), json.dumps(body).encode())


def test_expected_roles_come_from_the_environment():
    assert expected_roles({}) is None
    assert expected_roles({ENV_WRITER_ROLES: " , "}) is None
    assert expected_roles({ENV_WRITER_ROLES: "verdict, collector,verdict"}) == (
        "verdict", "collector")
    with pytest.raises(ValueError, match="dashboard"):
        expected_roles({ENV_WRITER_ROLES: "verdict,dashboard"})


def test_only_a_fresh_chained_verification_proves_the_lockout(tmp_path, monkeypatch):
    """Mutation: skip the freshness, chain or identity check in lockout_status."""
    monkeypatch.setattr(lockout, "_unprovable_allowed", False)
    store = CloudStore(tmp_path, verified=False)
    roles = ("verdict", "collector", "ingest")
    assert lockout_status(store, None, NOW).problems == {"*": "not configured"}
    assert lockout_status(store, roles, NOW).problems == {"*": "no verification"}
    _verified(store, at=NOW)
    assert lockout_status(store, roles, NOW).ok
    assert lockout_status(store, roles, NOW + timedelta(seconds=VERIFIED_FRESH_S)).ok
    assert lockout_status(store, roles, NOW + timedelta(seconds=VERIFIED_FRESH_S + 1)).problems \
        == {"*": "verification stale"}
    assert lockout_status(store, roles, NOW - timedelta(hours=1)).problems == {
        "*": "verification stale"}
    _verified(store, {COLLECTOR: "no_deny_for_writer"}, at=NOW + timedelta(minutes=1))
    assert lockout_status(store, roles, NOW).problems == {COLLECTOR: "no_deny_for_writer"}
    _verified(store, at=NOW + timedelta(minutes=2), identities=())
    assert lockout_status(store, roles, NOW).problems == {"*": "no writer identities verified"}


def test_a_forged_writer_report_is_not_proof(tmp_path, monkeypatch):
    """Every writer role reports a fresh denial, as a writer that can write
    `state/` could forge; with no verification record nothing is proven.

    Mutation: accept the writers' reports again."""
    monkeypatch.setattr(lockout, "_unprovable_allowed", False)
    store = CloudStore(tmp_path, verified=False)
    for role in ("verdict", "collector"):
        _publish(store, role, at=NOW)
    assert lockout_status(store, ("verdict", "collector"), NOW).problems == {
        "*": "no verification"}


@pytest.mark.parametrize("tamper", ["base-rewritten", "base-deleted", "unlinked", "garbled",
                                    "bad-identity", "bad-reason"])
def test_a_verification_record_that_does_not_check_out_is_not_trusted(tmp_path, monkeypatch,
                                                                      tamper):
    """Mutation: skip the base link, or the identity and reason formats."""
    monkeypatch.setattr(lockout, "_unprovable_allowed", False)
    store = CloudStore(tmp_path, verified=False)
    first = _verified(store, at=NOW - timedelta(minutes=5))
    newest = _verified(store, at=NOW)
    root = store.root / "audit"
    [base] = root.rglob(f"{lockout.VERIFY_PREFIX}{first['id']}.json")
    [head] = root.rglob(f"{lockout.VERIFY_PREFIX}{newest['id']}.json")
    if tamper == "base-rewritten":
        base.write_bytes(base.read_bytes().replace(b'"ok": true', b'"ok":  true'))
    elif tamper == "base-deleted":
        base.unlink()
    else:
        if tamper == "unlinked":
            third = _verified(store, at=NOW)
            [head] = root.rglob(f"{lockout.VERIFY_PREFIX}{third['id']}.json")
        record = json.loads(head.read_bytes())
        if tamper == "unlinked":
            record.update(base_id=None, base_hash=None)
        elif tamper == "garbled":
            record = "{"
        elif tamper == "bad-identity":
            record["identities"] = {"AKIA secret value": None}
        else:
            record["identities"] = {WRITER: "Access denied for AKIAIOSFODNN7EXAMPLE"}
        head.write_text(record if isinstance(record, str) else json.dumps(record))
    problems = lockout_status(store, ("verdict",), NOW).problems
    assert problems == {"*": "verification unreadable" if tamper in (
        "garbled", "bad-identity", "bad-reason") else "verification chain broken"}


def test_verification_records_are_not_audit_records(tmp_path):
    """The cold-start check ignores them, as it does probe records."""
    store = CloudStore(tmp_path)
    assert all(is_probe(n) for n in store.list_audit())
    assert all(n.rsplit("/", 1)[-1].startswith(lockout.VERIFY_PREFIX)
               for n in store.list_audit())


def test_the_dashboard_on_a_local_store_needs_the_test_opt_in(tmp_path, monkeypatch):
    store = LocalFileStore(tmp_path)
    monkeypatch.setattr(lockout, "_unprovable_allowed", False)
    assert lockout_status(store, ("verdict",), NOW).problems == {"*": "store cannot prove it"}
    monkeypatch.setattr(lockout, "_unprovable_allowed", True)
    assert lockout_status(store, ("verdict",), NOW).ok


def test_a_writers_own_denial_is_not_what_the_dashboard_accepts(tmp_path, enabled):
    store = CloudStore(tmp_path, verified=False)
    reader_for(ON, store, "verdict").refresh()
    assert _report(store, "verdict")["result"] == RESULT_DENIED
    assert lockout_status(store, ("verdict",)).problems == {"*": "no verification"}


jwt = pytest.importorskip("jwt", reason="needs forgd-verdict[dashboard]")


def _dashboard(store, auth, roles):
    import test_dashboard_admin as t

    from forgd_verdict.dashboard.app import Dashboard

    overrides = RuntimeOverrides(store, "dashboard", baseline={KEY_MODE: "observe"})
    overrides.refresh()
    return Dashboard(store, auth=auth, admins=t._admins(auth), overrides=overrides,
                     baseline_mode="observe", lockout=LockoutReports(store, roles))


@pytest.fixture
def auth_pem(monkeypatch):
    import test_dashboard_admin as t
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from forgd_verdict.dashboard.auth import AuthConfig
    from forgd_verdict.entitlements import MODE_OIDC_JWT

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = (key, key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    cfg = AuthConfig.parse({"mode": MODE_OIDC_JWT, "header": t.HEADER,
                            "jwks_url": "https://example.invalid/keys",
                            "issuer": t.ISSUER, "audience": t.AUDIENCE})

    public = key.public_key()

    class _Signing:
        key = public

    class _Client:
        def get_signing_key_from_jwt(self, _token):
            return _Signing()

    monkeypatch.setattr(cfg, "_keys", lambda *_: _Client())
    return cfg, pem


async def test_mutation_admin_actions_are_refused_until_every_writer_reports(
        tmp_path, enabled, signing_env, auth_pem, caplog):
    import test_dashboard_admin as t

    auth, pem = auth_pem
    store = CloudStore(tmp_path / "s")
    _init(store)
    app = _dashboard(store, auth, ("verdict", "collector"))
    _verified(store, {COLLECTOR: "no_deny_for_writer"})

    status, _, page = await t._call(app, "GET", "/policy", {t.HEADER: t._token(pem)})
    assert status == 200
    assert b"Admin actions are refused: writer lockout missing" in page
    assert f"{COLLECTOR}: no_deny_for_writer".encode() in page
    assert b'action="/admin/actions"' not in page, "no forms while a lockout is missing"
    with caplog.at_level(logging.WARNING, "forgd_verdict"):
        status, _, _ = await t._call(app, "POST", "/admin/actions", t._headers(pem),
                                     t._form(app, ACTION_SET, KEY_MODE, "enforce", 1))
    assert status == 403
    assert t._mode(store) is None
    assert any(getattr(r, "fields", {}).get("reason") == "writer_lockout"
               for r in caplog.records)

    _verified(store)
    status, _, page = await t._call(app, "GET", "/policy", {t.HEADER: t._token(pem)})
    status, headers, _ = await t._call(app, "POST", "/admin/actions", t._headers(pem),
                                       t._form(app, ACTION_SET, KEY_MODE, "enforce", 1))
    assert status == 303 and headers[b"location"] == b"/policy?result=applied"
    assert t._mode(store) == "enforce"


async def test_the_dashboard_refuses_without_the_expected_roles(tmp_path, enabled, auth_pem,
                                                                 monkeypatch):
    import test_dashboard_admin as t

    from forgd_verdict.dashboard.app import Dashboard

    auth, pem = auth_pem
    monkeypatch.delenv(ENV_WRITER_ROLES, raising=False)
    store = CloudStore(tmp_path / "s")
    overrides = RuntimeOverrides(store, "dashboard")
    app = Dashboard(store, auth=auth, admins=t._admins(auth), overrides=overrides)
    _publish(store, "verdict", at=datetime.now(UTC))
    status, _, page = await t._call(app, "GET", "/", {t.HEADER: t._token(pem)})
    assert b"not configured" in page and ENV_WRITER_ROLES.encode() in page
    status, _, _ = await t._call(app, "POST", "/admin/actions", t._headers(pem),
                                 t._form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert status == 403
    monkeypatch.setenv(ENV_WRITER_ROLES, "verdict")
    app = Dashboard(store, auth=auth, admins=t._admins(auth), overrides=overrides)
    status, _, _ = await t._call(app, "POST", "/admin/actions", t._headers(pem),
                                 t._form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert status == 303


# -- ingest ----------------------------------------------------------------


def test_ingest_exits_when_the_lockout_is_unproven(tmp_path, enabled, capsys, monkeypatch):
    from forgd_verdict.cli import main

    ran = []
    monkeypatch.setattr("forgd_verdict.compliance.ingest.run_ingest",
                        lambda *a, **k: ran.append("compliance") or {})
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"compliance": {"api_key": "sk-ant-admin01-" + "x" * 20},
                                  **ON}))
    assert main(["--policy", str(policy), "ingest", "--store", str(tmp_path / "s")]) == 1
    assert ran == []
    out = capsys.readouterr()
    assert f"refusing to ingest: {LOCKOUT_MISSING}" in out.err
    assert json.loads(out.out)["runtime_overrides"]["lockout"] == RESULT_UNPROVEN


# -- every reader checks every writer's report ------------------------------


def _forge_newer(store):
    """A newer object with a head record that verifies: what a writer
    without the lockout could write."""
    apply_change(store, ACTOR, Change("override.clear", KEY_MODE), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


@pytest.fixture
def fleet(monkeypatch, enabled):
    monkeypatch.setenv(ENV_WRITER_ROLES, "verdict,collector")


def _verdict_server(store):
    from conftest import WHSEC, make_policy

    from forgd_verdict.server.app import VerdictServer

    return VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": None,
                "store_flush_s": 3600}, **ON), store=store)


async def test_mutation_a_collector_without_its_lockout_stops_the_verdict_server_adopting(
        tmp_path, fleet):
    """The verdict server's own lockout holds; the newest verification
    shows the collector's role without its Deny, so the collector could have
    forged the object."""
    from conftest import ASGIClient

    store = CloudStore(tmp_path, deny=True)
    _init(store)
    _enforce(store)
    warm = _verdict_server(store)
    try:
        assert warm.mode == "enforce"
        assert warm.overrides.current().ready

        _verified(store, {COLLECTOR: "no_deny_for_writer"})
        _forge_newer(store)
        snap = warm.overrides.refresh()
        assert warm.mode == "enforce", "the newer object is not adopted"
        assert (snap.source, snap.status, snap.error) == ("last_known_good", STATUS_DISABLED,
                                                          LOCKOUT_MISSING)
        assert snap.ready and snap.in_error
        assert snap.fields()["writers"] == {COLLECTOR: "no_deny_for_writer"}
        assert snap.state.revision == 2
        assert warm._metrics_body()["runtime_overrides"]["in_error"] == 1

        cold = _verdict_server(store)
        try:
            snap = cold.overrides.current()
            assert cold.mode == "observe" and not snap.ready
            status, body = await ASGIClient(cold).get("/readyz")
            assert status == 503 and body["reason"] == f"runtime overrides {LOCKOUT_MISSING}"
            assert (await ASGIClient(cold).get("/healthz"))[0] == 200
        finally:
            cold.close()

        _verified(store)
        snap = warm.overrides.refresh()
        assert warm.mode == "observe" and snap.status == "ok" and snap.state.revision == 3
    finally:
        warm.close()


async def test_a_warm_verdict_server_whose_lockout_is_lost_is_not_ready_but_live(
        tmp_path, enabled):
    """Mutation: answer /readyz 200 while not ready, or /healthz 503."""
    from conftest import ASGIClient

    store = CloudStore(tmp_path, deny=True)
    _init(store)
    _enforce(store)
    warm = _verdict_server(store)
    try:
        assert await ASGIClient(warm).get("/readyz") == (200, {"status": "ok"})
        store.deny = False
        warm.overrides.lockout.clock = lambda: 10.0 ** 9
        snap = warm.overrides.refresh()
        assert (snap.lockout, snap.source, snap.ready) == (
            RESULT_ALLOWED, "last_known_good", False)
        assert warm.mode == "enforce"
        status, body = await ASGIClient(warm).get("/readyz")
        assert (status, body["reason"]) == (503, f"runtime overrides {LOCKOUT_MISSING}")
        for path in ("/healthz", "/health"):
            status, body = await ASGIClient(warm).get(path)
            assert (status, body["status"], body["mode"]) == (200, "ok", "enforce"), path
    finally:
        warm.close()


@pytest.mark.parametrize("problem", ["missing", "stale", "failing", "forged"])
def test_a_verification_that_is_not_fresh_and_passing_holds_every_reader(tmp_path, fleet,
                                                                        problem):
    """Mutation: adopt without a fresh, passing verification."""
    store = CloudStore(tmp_path, deny=True)
    _init(store)
    _enforce(store)
    reader = reader_for(ON, store, "dashboard", baseline={KEY_MODE: "observe"})
    assert reader.refresh().state.value(KEY_MODE) == "enforce"
    if problem == "failing":
        _verified(store, {WRITER: "deny_misses_resource"})
    else:
        _unverify(store)
        if problem == "stale":
            _verified(store, at=datetime.now(UTC) - timedelta(seconds=VERIFIED_FRESH_S + 60))
        elif problem == "forged":
            for role in ("verdict", "collector"):
                _publish(store, role, at=datetime.now(UTC))
    _forge_newer(store)
    snap = reader.refresh()
    assert snap.source == "last_known_good" and snap.state.value(KEY_MODE) == "enforce"
    assert snap.error == LOCKOUT_MISSING and snap.ready
    assert snap.writers == ({WRITER: "deny_misses_resource"} if problem == "failing" else {
        "*": {"missing": "no verification", "forged": "no verification",
              "stale": "verification stale"}[problem]})


def test_a_cold_reader_is_not_ready_even_on_an_empty_store(tmp_path, fleet):
    store = CloudStore(tmp_path, deny=True, verified=False)
    reader = reader_for(ON, store, "verdict", baseline={KEY_MODE: "observe"})
    snap = reader.refresh()
    assert snap.fields()["writers"] == {"*": "no verification"}
    assert (snap.source, snap.error, snap.ready, snap.in_error) == (
        "baseline", LOCKOUT_MISSING, False, True)
    assert readiness(reader)[0] == 503
    _verified(store)
    snap = reader.refresh()
    assert (snap.error, snap.ready) == (ERROR_UNINITIALIZED, False)
    assert readiness(reader) == (503, {
        "status": "not_ready", "reason": "runtime overrides are not initialized",
        "runtime_overrides": "absent"})
    _init(store)
    assert reader.refresh().ready


def test_without_the_writer_roles_nothing_is_adopted(tmp_path, enabled, monkeypatch):
    monkeypatch.delenv(ENV_WRITER_ROLES)
    store = CloudStore(tmp_path, deny=True)
    _init(store)
    _enforce(store)
    snap = reader_for(ON, store, "connector").refresh()
    assert snap.writers == {"*": "not configured"} and not snap.ready


def test_a_bad_writer_roles_value_stops_a_service(tmp_path, enabled, monkeypatch):
    monkeypatch.setenv(ENV_WRITER_ROLES, "verdict,verdcit")
    with pytest.raises(ValueError, match="verdcit"):
        reader_for(ON, CloudStore(tmp_path), "collector")


def test_a_warm_writer_keeps_its_last_known_good_when_its_reprobe_fails(tmp_path, enabled):
    store = CloudStore(tmp_path, deny=True)
    _init(store)
    _enforce(store)
    clock = Clock()
    reader = reader_for(ON, store, "verdict", baseline={KEY_MODE: "observe"}, clock=clock,
                        lockout=LockoutProbe(store, "verdict", clock=clock))
    assert reader.refresh().state.value(KEY_MODE) == "enforce"
    store.error = OSError("reset")
    clock.t = 2 * PROBE_S
    snap = reader.refresh()
    assert (snap.lockout, snap.source, snap.ready) == (RESULT_UNPROVEN, "last_known_good", True)
    assert reader.mode("observe") == "enforce"
    store.error, store.deny = None, False
    clock.t += 1
    snap = reader.refresh()
    assert (snap.lockout, snap.source, snap.ready) == (RESULT_ALLOWED, "last_known_good", False)
    assert reader.mode("observe") == "enforce"


def test_the_dashboard_and_the_connector_check_the_reports(tmp_path, fleet, monkeypatch):
    from conftest import DEFAULT_POLICY

    from forgd_verdict.connector.tools import reader_from_policy
    from forgd_verdict.policy import Policy, _deep_merge

    store = CloudStore(tmp_path, deny=True)
    policy = Policy(_deep_merge(DEFAULT_POLICY, ON))

    class Cfg:
        auth = None
        entitlements = None

    reader = reader_from_policy(policy, Cfg(), store)
    assert reader.overrides.fleet is not None
    assert reader.overrides.fleet.roles == ("verdict", "collector")


# -- signed verification records ------------------------------------------


def _keys():
    from conftest import OVERRIDES_PUBLIC

    return (OVERRIDES_PUBLIC,)


def _verification_file(store, record):
    return store.root / "audit" / "runtime-overrides" / lockout.verification_name(record["id"])


def test_a_signed_verification_and_its_signed_base_are_trusted(tmp_path):
    store = CloudStore(tmp_path, verified=False)
    _verified(store, at=NOW - timedelta(minutes=5))
    newest = _verified(store, at=NOW)
    assert newest["signature"]["kid"] == sig.key_id(OVERRIDES_KEY.public_key())
    assert lockout_status(store, ("verdict",), NOW, _keys()).ok


def test_an_unsigned_verification_with_a_correct_hash_is_not_trusted(tmp_path):
    """What a writer without the lockout could forge: well formed, chained
    by hash, unsigned. Mutation: skip the signature check."""
    store = CloudStore(tmp_path, verified=False)
    _verified(store, {COLLECTOR: "no_deny_for_writer"}, at=NOW - timedelta(minutes=5))
    lockout.write_verification(store, {WRITER: None, COLLECTOR: None}, "s3", NOW)
    assert lockout_status(store, ("verdict",), NOW).ok
    assert lockout_status(store, ("verdict",), NOW, _keys()).problems == {
        "*": "verification signature invalid"}


def test_a_forged_base_is_not_trusted(tmp_path):
    """The newest record is signed, its base is signed by a key not listed.
    Mutation: check only the newest record."""
    store = CloudStore(tmp_path, verified=False)
    lockout.write_verification(store, {WRITER: None}, "s3", NOW - timedelta(minutes=5),
                               Ed25519PrivateKey.generate())
    _verified(store, at=NOW)
    assert lockout_status(store, ("verdict",), NOW, _keys()).problems == {
        "*": "verification signature invalid"}


def test_a_verification_signed_by_an_unlisted_key_is_not_trusted(tmp_path):
    store = CloudStore(tmp_path, verified=False)
    rogue = Ed25519PrivateKey.generate()
    lockout.write_verification(store, {WRITER: None}, "s3", NOW, rogue)
    assert lockout_status(store, ("verdict",), NOW, _keys()).problems == {
        "*": "verification signature invalid"}
    assert lockout_status(store, ("verdict",), NOW, (*_keys(), rogue.public_key())).ok
    assert lockout_status(store, ("verdict",), NOW, ()).problems == {
        "*": "verification signature invalid"}


@pytest.mark.parametrize("damage", ["no_signature", "bad_signature", "wrong_alg", "not_base64"])
def test_a_verification_with_a_malformed_signature_is_not_trusted(tmp_path, damage):
    store = CloudStore(tmp_path, verified=False)
    record = _verified(store, at=NOW)
    field = dict(record["signature"])
    if damage == "no_signature":
        record.pop("signature")
    else:
        if damage == "bad_signature":
            field["sig"] = sig.encode(bytes(64))
        elif damage == "wrong_alg":
            field["alg"] = "HS256"
        else:
            field["sig"] = "!!!"
        record["signature"] = field
    _verification_file(store, record).write_text(json.dumps(record, sort_keys=True) + "\n")
    assert lockout_status(store, ("verdict",), NOW, _keys()).problems == {
        "*": "verification signature invalid"}


def test_a_reader_holds_an_object_while_the_verification_is_unsigned(tmp_path, fleet):
    """reader_for passes the policy's verify keys to the fleet check.
    Mutation: build LockoutReports without them."""
    store = CloudStore(tmp_path, deny=True)
    _init(store)
    _enforce(store)
    reader = reader_for(ON, store, "dashboard", baseline={KEY_MODE: "observe"})
    assert reader.refresh().state.value(KEY_MODE) == "enforce"
    lockout.write_verification(store, {WRITER: None, COLLECTOR: None}, "s3", datetime.now(UTC))
    _forge_newer(store)
    snap = reader.refresh()
    assert snap.source == "last_known_good" and snap.state.value(KEY_MODE) == "enforce"
    assert snap.writers == {"*": "verification signature invalid"}


def test_signing_a_verification_discloses_no_private_key(tmp_path, caplog):
    from conftest import OVERRIDES_KEY_TEXT

    store = CloudStore(tmp_path, verified=False)
    with caplog.at_level(logging.DEBUG):
        _verified(store, at=NOW)
        lockout.write_verification(store, {WRITER: None}, "s3", NOW,
                                   Ed25519PrivateKey.generate())
        status = lockout_status(store, ("verdict",), NOW, _keys())
    stored = b"".join(p.read_bytes() for p in store.root.rglob(f"{lockout.VERIFY_PREFIX}*"))
    assert OVERRIDES_KEY_TEXT.encode() not in stored
    assert OVERRIDES_KEY_TEXT not in caplog.text
    assert OVERRIDES_KEY_TEXT not in json.dumps(status.fields())


# -- concurrent verification writes ---------------------------------------


class _Replica:
    """A dashboard replica's view of `store`: its listing is the one taken
    when it began, so it writes on the newest record it saw then."""

    def __init__(self, store):
        self._store = store
        self._listed = list(store.list_audit())

    def list_audit(self, day=None, leaf=""):
        scope = f"{day}/{leaf}" if day is not None else ""
        return [n for n in self._listed if n.startswith(scope)]

    def audit_days(self):
        return sorted({n.split("/", 1)[0] for n in self._listed})

    def __getattr__(self, name):
        return getattr(self._store, name)


def _write(store, at, key=OVERRIDES_KEY, results=None):
    return lockout.write_verification(store, results or {WRITER: None, COLLECTOR: None},
                                      "s3", at, key)


@pytest.mark.parametrize("stale_is_newer", [True, False])
def test_two_replicas_verifying_at_once_leave_a_trusted_fork(tmp_path, stale_is_newer):
    """Both replicas list the store before either writes, so both records
    name the same base. Mutation: require the base to be the record just
    before the newest."""
    store = CloudStore(tmp_path, verified=False)
    base = _write(store, NOW - timedelta(minutes=60))
    a, b = _Replica(store), _Replica(store)
    first, second = (b, a) if stale_is_newer else (a, b)
    one = _write(first, NOW - timedelta(minutes=1))
    two = _write(second, NOW)
    assert one["base_id"] == two["base_id"] == base["id"]
    assert lockout_status(store, ("verdict",), NOW, _keys()).ok
    after = _write(store, NOW + timedelta(minutes=1))
    assert after["base_id"] == two["id"]
    assert lockout_status(store, ("verdict",), NOW, _keys()).ok


def test_two_replicas_writing_the_first_verification_at_once_are_trusted(tmp_path):
    store = CloudStore(tmp_path, verified=False)
    a, b = _Replica(store), _Replica(store)
    assert _write(a, NOW - timedelta(seconds=1))["base_id"] is None
    assert _write(b, NOW)["base_id"] is None
    assert lockout_status(store, ("verdict",), NOW, _keys()).ok


def test_a_fork_whose_newest_member_fails_is_trusted_by_nobody(tmp_path):
    """The newest record decides; an older fork member that passes does not
    stand in for it."""
    store = CloudStore(tmp_path, verified=False)
    _write(store, NOW - timedelta(minutes=60))
    a, b = _Replica(store), _Replica(store)
    _write(a, NOW - timedelta(minutes=1))
    _write(b, NOW, results={WRITER: None, COLLECTOR: "no_deny_for_writer"})
    assert lockout_status(store, ("verdict",), NOW, _keys()).problems == {
        COLLECTOR: "no_deny_for_writer"}


@pytest.mark.parametrize("member", ["unsigned", "unlisted", "garbled"])
def test_a_bad_fork_member_is_ignored_when_older_and_refused_when_newest(tmp_path, member):
    """The newest record decides: a failing one is not passed over for an
    older one that passes, which a writer able to garble the newest record
    could otherwise use to bring back a passing one."""
    store = CloudStore(tmp_path, verified=False)
    _write(store, NOW - timedelta(minutes=60))
    a, b = _Replica(store), _Replica(store)

    def bad(view, at):
        if member == "garbled":
            record = _write(view, at)
            _verification_file(store, record).write_text("{")
            return
        _write(view, at, None if member == "unsigned" else Ed25519PrivateKey.generate())

    bad(a, NOW - timedelta(minutes=1))
    _write(b, NOW)
    assert lockout_status(store, ("verdict",), NOW, _keys()).ok

    later = _Replica(store)
    _write(store, NOW + timedelta(minutes=1))
    bad(later, NOW + timedelta(minutes=2))
    assert lockout_status(store, ("verdict",), NOW + timedelta(minutes=2), _keys()).problems == {
        "*": "verification unreadable" if member == "garbled" else
        "verification signature invalid"}


def test_the_dashboard_fallback_fleet_check_uses_the_readers_verify_keys(tmp_path, enabled,
                                                                        auth_pem):
    """A Dashboard given a reader without its own fleet check builds one.
    Mutation: build it without the reader's verify keys."""
    import test_dashboard_admin as t

    from forgd_verdict.dashboard.app import Dashboard

    auth, _ = auth_pem
    store = CloudStore(tmp_path / "s", verified=False)
    overrides = RuntimeOverrides(store, "dashboard", verify_keys=_keys())
    app = Dashboard(store, auth=auth, admins=t._admins(auth), overrides=overrides)
    assert app.lockout is not None and app.lockout is not overrides.fleet
    lockout.write_verification(store, {WRITER: None}, "s3", datetime.now(UTC))
    assert app.lockout.refresh().problems == {"*": "verification signature invalid"}
    _verified(store, identities=(WRITER,))
    assert app.lockout.refresh().problems == {"*": "verification signature invalid"}, \
        "its base is the forged record"
    _verified(store, identities=(WRITER,))
    assert app.lockout.refresh().ok


def _minted(store, minted, at, base=None):
    """A signed verification record whose id carries `minted` and whose
    `at` is `at`, on `base` (a record) or on nothing."""
    stamp = f"{minted:%Y%m%dT%H%M%S%f}Z"
    audit_id = f"{stamp}-{'ab' * 6}"
    base_blob = store.get_audit(lockout.verification_name(base["id"])) if base else None
    record = {"version": lockout.REPORT_VERSION, "kind": lockout.VERIFY_KIND, "id": audit_id,
              "at": f"{at:%Y-%m-%dT%H:%M:%SZ}", "store": "s3",
              "identities": {WRITER: None, COLLECTOR: None}, "ok": True,
              "base_id": base["id"] if base else None,
              "base_hash": lockout._sha256(base_blob) if base else None}
    record = lockout.sign_record(record, OVERRIDES_KEY)
    store.put_audit(lockout.verification_name(audit_id),
                    (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
    return record


def _problem(store):
    return lockout._checked_verification(store, NOW, [OVERRIDES_KEY.public_key()])[1]


@pytest.mark.parametrize("ahead, ok", [(300, True), (301, False)])
def test_a_verification_id_too_far_ahead_of_now_is_refused(tmp_path, ahead, ok):
    """`at` is within the skew of the id, so only the id's distance from
    now decides. Mutation: drop the id-versus-now check."""
    store = CloudStore(tmp_path, verified=False)
    base = _verified(store, at=NOW - timedelta(minutes=30))
    _minted(store, NOW + timedelta(seconds=ahead), NOW + timedelta(seconds=290), base)
    assert _problem(store) == (None if ok else lockout.PROBLEM_VERIFY_CLOCK)


@pytest.mark.parametrize("apart, ok", [(300, True), (301, False), (-301, False)])
def test_a_verification_id_away_from_its_at_is_refused(tmp_path, apart, ok):
    """The id is in the past, so only its distance from `at` decides.
    Mutation: drop the id-versus-at check."""
    store = CloudStore(tmp_path, verified=False)
    base = _verified(store, at=NOW - timedelta(hours=1, minutes=30))
    _minted(store, NOW - timedelta(minutes=20) + timedelta(seconds=apart),
            NOW - timedelta(minutes=20), base)
    assert _problem(store) == (None if ok else lockout.PROBLEM_VERIFY_CLOCK)


def test_a_head_on_a_base_with_a_bad_clock_is_refused(tmp_path):
    """Mutation: check only the head's clock."""
    store = CloudStore(tmp_path, verified=False)
    base = _minted(store, NOW - timedelta(minutes=50), NOW - timedelta(hours=1, minutes=30))
    _minted(store, NOW - timedelta(minutes=10), NOW - timedelta(minutes=10), base)
    assert _problem(store) == lockout.PROBLEM_VERIFY_CLOCK


# -- a verification record dated in the future ----------------------------


def _records(store):
    return sorted(store.root.rglob(f"{lockout.VERIFY_PREFIX}*.json"))


def _refused(caplog):
    return [r for r in caplog.records if r.levelno == logging.ERROR
            and getattr(r, "fields", {}).get("code") == lockout.ERROR_VERIFY_BASE_FUTURE]


@pytest.mark.parametrize("ahead, written", [(299, True), (301, False)])
def test_a_record_on_a_future_dated_base_is_not_written(tmp_path, caplog, ahead, written):
    """A record's id follows its base's, so one on a base dated past the
    skew would carry that date and every reader would refuse it. Mutation:
    drop the clock check from write_verification."""
    store = CloudStore(tmp_path, verified=False)
    base = _minted(store, NOW + timedelta(seconds=ahead), NOW + timedelta(seconds=ahead))
    with caplog.at_level(logging.ERROR, "forgd_verdict.lockout"):
        record = _write(store, NOW)
    assert (record is not None) == written
    assert len(_records(store)) == (2 if written else 1)
    if written:
        assert record["base_id"] == base["id"] and _problem(store) is None
        assert not _refused(caplog)
    else:
        [logged] = _refused(caplog)
        assert logged.fields["base_id"] == base["id"]


def test_a_run_after_a_future_dated_record_is_refused_until_it_is_deleted(tmp_path, caplog):
    """A CLI with a clock ten minutes fast writes a record; the dashboard's
    runs and anchors write nothing and log the code, and do not raise. With
    that record deleted, the next run writes one readers trust. Mutation:
    drop the clock check from write_verification."""
    from forgd_verdict.lockout_evidence.verifier import Verifier

    store = CloudStore(tmp_path)
    now = datetime.now(UTC)
    future = _write(store, now + timedelta(minutes=10))
    head = {"revision": 0, "audit_id": None, "audit_hash": None}
    verifier = Verifier(store, signing_key=OVERRIDES_KEY, verify_keys=_keys(),
                        identities=(WRITER, COLLECTOR), trusted=lambda: head,
                        evaluate=lambda s, ids, **_: dict.fromkeys(ids))
    with caplog.at_level(logging.ERROR, "forgd_verdict.lockout"):
        assert verifier.once() is None
        assert verifier.anchor(head) is None
    assert verifier.pending == head
    assert len(_refused(caplog)) == 2
    assert _records(store)[-1].name == f"{lockout.VERIFY_PREFIX}{future['id']}.json"
    assert lockout._checked_verification(store, now, _keys())[1] in (
        lockout.PROBLEM_VERIFY_STALE, lockout.PROBLEM_VERIFY_CLOCK)

    store.root.joinpath(AUDIT_PREFIX, lockout.verification_name(future["id"])).unlink()
    record = verifier.once()
    assert record is not None and verifier.pending is None
    assert lockout._checked_verification(store, datetime.now(UTC), _keys()) == (record, None)
