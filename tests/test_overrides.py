"""Runtime overrides: the allowlist, the reader's fallbacks, and the audit chain.

docs/design/overrides.md is the design these pin; "Tests for the four
cases" there lists the `test_case_*` functions and what each asserts.
"""

from __future__ import annotations

import inspect
import json
import logging
from datetime import UTC, datetime, timedelta

import pytest
from conftest import (
    DETECTORS,
    FAKE_AWS_KEY,
    FAKE_GITHUB_TOKEN,
    OVERRIDES_KEY,
    OVERRIDES_PUBLIC,
    make_policy,
)

from forgd_verdict import overrides as ov
from forgd_verdict.models import CONTROL_STATE
from forgd_verdict.overrides import (
    ACTION_CLEAR,
    ACTION_CLEAR_ALL,
    ACTION_EXCLUDE,
    ACTION_INIT,
    ACTION_MIGRATE,
    ACTION_RECOVER,
    ACTION_RESET,
    ACTION_SET,
    ACTION_UNEXCLUDE,
    ALLOWLIST,
    KEY_MODE,
    Change,
    InvalidState,
    NoChange,
    OverlaidStore,
    OverrideEntry,
    Refused,
    RuntimeOverrides,
    apply_change,
    audit_name,
    durability_warning,
    history,
    parse_state,
    request_id_ok,
    screen,
)
from forgd_verdict.policy import ENV_OVERRIDES, SECRET_LIST_PATHS, SECRET_PATHS
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import AUDIT_PREFIX, STATE_PREFIX, StoreConflict

ADMIN = {"issuer": "https://idp.example/", "subject": "sub-1", "name": "a.person",
         "via_group": "ops", "verified": True}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Flaky:
    """A store whose control read can be made to fail, as a denied grant does."""

    def __init__(self, store):
        self.store = store
        self.fail = False

    def __getattr__(self, name):
        return getattr(self.store, name)

    def read_control(self):
        if self.fail:
            raise ov.StoreReadError("AccessDenied")
        return self.store.read_control()


def _obj(store, **overrides) -> None:
    for key, value in overrides.items():
        apply_change(store, ADMIN, Change(ACTION_SET, key, value), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


def _control(store):
    return store.root / STATE_PREFIX / CONTROL_STATE


def _reader(store, clock=None, baseline="observe"):
    return RuntimeOverrides(store, "test", baseline={KEY_MODE: baseline},
                            clock=clock or Clock())


def _init(store):
    apply_change(store, ADMIN, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    return store


@pytest.fixture
def bare(tmp_path):
    """A store `overrides init` has not run against."""
    return LocalFileStore(tmp_path / "store", instance="t")


@pytest.fixture
def store(bare):
    return _init(bare)


# -- the allowlist ---------------------------------------------------------


def test_the_allowlist_never_reaches_detection_privacy_auth_or_a_secret():
    """The same boundary as the ENV_OVERRIDES test, for a remote control
    surface."""
    secret = {tuple(p) for p in SECRET_PATHS} | {
        (*parents, key) for parents, key in SECRET_LIST_PATHS}
    for key, (path, _) in ALLOWLIST.items():
        assert path[0] not in ("detectors", "privacy"), key
        assert path[:2] not in (("dashboard", "auth"), ("dashboard", "entitlements"),
                                ("dashboard", "admins")), key
        assert path not in secret, key
        assert path not in {("server", "secrets"), ("server", "require_signature"),
                            ("server", "on_internal_error")}, key
        assert ".".join(path) == key


def test_the_allowlist_is_server_mode_alone():
    assert set(ALLOWLIST) == {"server.mode"}


def test_dashboard_admins_is_not_an_env_override():
    assert all(path[:2] != ("dashboard", "admins") for path, _ in ENV_OVERRIDES.values())


@pytest.mark.parametrize("key", [
    "detectors.t0_regex.enabled", "detectors.t0_regex.severity", "privacy.hash_salt",
    "dashboard.auth.mode", "server.require_signature", "server.on_internal_error",
    "compliance.api_key",
])
def test_a_key_off_the_allowlist_is_never_applied(store, caplog, key):
    _obj(store, **{KEY_MODE: "enforce"})
    raw = json.loads(_control(store).read_bytes())
    raw["overrides"][key] = {"value": False}
    _control(store).write_text(json.dumps(raw))
    with caplog.at_level(logging.ERROR):
        reader = _reader(store)
        snap = reader.refresh()
    assert set(snap.state.overrides) == {"server.mode"}
    assert snap.state.ignored == (key,)
    assert reader.mode("observe") == "enforce"
    named = [r for r in caplog.records if r.levelno == logging.ERROR
             and r.fields.get("keys") == 1]
    assert named, "the ignored key is counted"
    assert not any(key in r.getMessage() or key in json.dumps(getattr(r, "fields", {}))
                   for r in caplog.records), "the ignored key is not logged"
    if key.startswith(("detectors.", "privacy.")):
        assert "detection or privacy" in named[0].getMessage()


def test_a_write_names_no_key_off_the_allowlist(store):
    before = (_control(store).read_bytes(), store.list_audit())
    with pytest.raises(Refused):
        apply_change(store, ADMIN, Change(ACTION_SET, "detectors.t0_regex.enabled", False),
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert (_control(store).read_bytes(), store.list_audit()) == before


@pytest.mark.parametrize("value", ["archive", "off", "", None, True])
def test_mode_takes_observe_or_enforce_only(store, value):
    with pytest.raises(Refused):
        apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, value), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


@pytest.mark.parametrize("raw", [
    b"{", b"[]", b'{"version": 2}', b'{"version": 1, "revision": -1}',
    b'{"version": 1, "overrides": []}',
    b'{"version": 1, "overrides": {"server.mode": {"value": "archive"}}}',
    b'{"version": 1, "excluded_requests": ["has space"]}',
    b'{"version": 1, "stats_reset": "yesterday"}',
])
def test_malformed_objects_are_invalid(raw):
    with pytest.raises(InvalidState):
        parse_state(raw)


# -- the four reader cases -------------------------------------------------


def test_case_1_a_running_replica_keeps_its_last_known_good(store, caplog):
    flaky = Flaky(store)
    clock = Clock()
    _obj(store, **{KEY_MODE: "enforce"})
    reader = _reader(flaky, clock)
    assert reader.refresh().source == "object"
    assert reader.mode("observe") == "enforce"

    flaky.fail = True
    with caplog.at_level(logging.ERROR):
        for _ in range(2):
            snap = reader.refresh()
            assert (snap.source, snap.status) == ("last_known_good", "unreadable")
            assert reader.mode("observe") == "enforce"
    assert len([r for r in caplog.records if "keeping the values last read"
                in r.getMessage()]) == 2

    flaky.fail = False
    (store.root / STATE_PREFIX / CONTROL_STATE).write_bytes(b"{not json")
    snap = reader.refresh()
    assert (snap.source, snap.status) == ("last_known_good", "invalid")
    assert reader.mode("observe") == "enforce"

    (store.root / STATE_PREFIX / CONTROL_STATE).unlink()
    snap = reader.refresh()
    assert (snap.source, snap.status) == ("last_known_good", "absent")
    assert reader.mode("observe") == "enforce"


def test_case_2_a_cold_start_uses_the_baseline_then_adopts(store, caplog):
    flaky = Flaky(store)
    flaky.fail = True
    clock = Clock()
    _obj(store, **{KEY_MODE: "enforce"})
    with caplog.at_level(logging.ERROR):
        reader = _reader(flaky, clock)
        snap = reader.refresh()
    assert (snap.source, snap.status) == ("baseline", "unreadable")
    assert reader.mode("observe") == "observe"
    assert any("running on policy.yaml and environment settings only" in r.getMessage()
               for r in caplog.records)
    assert reader.refresh().source == "baseline", "a failed read is never a last-known-good"

    flaky.fail = False
    clock.t += reader.ttl_s - 1
    assert reader.mode("observe") == "observe", "not re-read inside the window"
    clock.t += 1
    assert reader.mode("observe") == "enforce"
    assert reader.current().source == "object"


def test_case_2_a_cold_start_on_an_invalid_object_adopts_once_valid(store):
    (store.root / STATE_PREFIX / CONTROL_STATE).write_bytes(b"[]")
    clock = Clock()
    reader = _reader(store, clock)
    assert reader.refresh().source == "baseline"
    apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode="enforce", detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    clock.t += reader.ttl_s
    assert reader.mode("observe") == "enforce"


def test_case_3_a_valid_object_that_clears_an_override_is_applied(store):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    reader = _reader(store)
    reader.refresh()
    assert reader.mode("observe") == "enforce"
    apply_change(store, ADMIN, Change(ACTION_CLEAR, KEY_MODE), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    reader.refresh()
    assert reader.mode("observe") == "observe"
    assert reader.current().source == "object"


def test_absence_after_a_valid_read_retains_and_logs_error_every_refresh(store, caplog):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    reader = _reader(store)
    reader.refresh()
    (store.root / STATE_PREFIX / CONTROL_STATE).unlink()
    with caplog.at_level(logging.INFO):
        for _ in range(3):
            snap = reader.refresh()
            assert (snap.source, snap.status) == ("last_known_good", "absent")
            assert snap.fields()["source"] == "last_known_good"
            assert reader.mode("observe") == "enforce"
    errors = [r for r in caplog.records if r.levelno == logging.ERROR
              and "keeping the values last read" in r.getMessage()]
    assert len(errors) == 3


def test_a_cold_start_on_a_store_never_initialized_is_not_ready(bare, caplog):
    with caplog.at_level(logging.INFO):
        reader = _reader(bare)
        snap = reader.refresh()
    assert (snap.source, snap.status, snap.ready) == ("baseline", "absent", False)
    assert snap.error == ov.ERROR_UNINITIALIZED
    assert ov.readiness(reader)[0] == 503
    assert [r for r in caplog.records if r.levelno == logging.ERROR
            and "not initialized" in r.getMessage()]
    assert reader.mode("observe") == "observe"


def test_init_makes_a_cold_reader_ready_on_an_empty_object(bare):
    reader = _reader(bare)
    assert not reader.refresh().ready
    applied = apply_change(bare, ADMIN, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    snap = _reader(bare).refresh()
    assert (snap.source, snap.status, snap.ready) == ("object", "ok", True)
    assert ov.readiness(_reader(bare))[0] == 200
    assert snap.state == parse_state(bare.read_control().body)
    assert (snap.state.revision, snap.state.audit_id) == (1, applied.audit_id)
    assert (dict(snap.state.overrides), snap.state.stats_reset,
            snap.state.excluded_requests, snap.state.legacy_markers_retired) == (
        {}, None, frozenset(), False)
    requests = [r for r in _records(bare) if r["kind"] == "request"]
    assert [(r["action"], r["principal"], r["old_value"], r["new_value"], r["base_revision"],
             r["base_audit_id"], r["base_hash"]) for r in requests] == [
        (ACTION_INIT, ADMIN, None, {}, 0, None, None)]
    assert history(bare, snap.state).applied == requests


def test_case_4_the_durability_warning_is_for_enforce_over_observe(store):
    """The dashboard's rendering is pinned in test_dashboard_admin.py."""
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    state = _reader(store).refresh().state
    assert durability_warning("observe", state)
    assert not durability_warning("enforce", state)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert not durability_warning("observe", _reader(store).refresh().state)
    assert not durability_warning("observe", None)


def test_a_change_is_picked_up_within_the_refresh_window(store):
    clock = Clock()
    reader = _reader(store, clock)
    reader.refresh()
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert reader.mode("observe") == "observe"
    clock.t += ov.REFRESH_S
    assert reader.mode("observe") == "enforce"
    assert ov.REFRESH_S == 60.0


def test_an_archive_baseline_ignores_a_mode_override(store):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    reader = _reader(store, baseline="archive")
    reader.refresh()
    assert reader.mode("archive") == "archive"


def test_no_store_is_the_baseline():
    reader = RuntimeOverrides(None, "test")
    assert reader.refresh().fields() == {"status": "disabled", "source": "baseline",
                                         "in_error": 0, "ready": True}
    assert reader.mode("enforce") == "enforce"


# -- recovery --------------------------------------------------------------


def test_recover_an_absent_object_that_a_replica_holds(store):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    reader = _reader(store)
    reader.refresh()
    (store.root / STATE_PREFIX / CONTROL_STATE).unlink()
    assert reader.refresh().source == "last_known_good"
    applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.revision == 3
    record = json.loads(store.get_audit(audit_name(applied.audit_id, "request")))
    assert (record["action"], record["old_value"]) == (ACTION_RECOVER,
                                                        {"status": "absent", "kept": True})
    assert parse_state(store.read_control().body).audit_id == applied.audit_id
    snap = reader.refresh()
    assert (snap.source, snap.status) == ("object", "ok")
    assert reader.mode("observe") == "enforce", "the chain is verifiable, so the mode is kept"


def test_recover_an_invalid_object_keeping_the_mode(store):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    reader = _reader(store)
    reader.refresh()
    (store.root / STATE_PREFIX / CONTROL_STATE).write_bytes(b"{broken")
    assert reader.refresh().status == "invalid"
    with pytest.raises(InvalidState):
        apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode="enforce", detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert reader.refresh().source == "object"
    assert reader.mode("observe") == "enforce"


def test_recover_refuses_while_the_read_fails(store):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    flaky = Flaky(store)
    flaky.fail = True
    with pytest.raises(ov.StoreReadError):
        apply_change(flaky, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert len(store.list_audit()) == 4, "no request record for a refused recover"


def test_recover_refuses_a_valid_object(store):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    with pytest.raises(Refused):
        apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


# -- the audit protocol ----------------------------------------------------


def _records(store):
    return [json.loads(store.get_audit(n)) for n in store.list_audit()]


def test_every_change_writes_a_request_record_with_the_principal(store):
    applied = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"),
                           detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    request = json.loads(store.get_audit(audit_name(applied.audit_id, "request")))
    assert request["kind"] == "request"
    assert request["principal"] == ADMIN
    assert (request["action"], request["key"], request["old_value"],
            request["new_value"]) == (ACTION_SET, KEY_MODE, None, "enforce")
    genesis = [r for r in _records(store) if r.get("action") == ACTION_INIT][0]
    assert (request["base_revision"], request["base_audit_id"]) == (1, genesis["id"])
    assert "outcome" not in request
    state = parse_state(store.read_control().body)
    assert (state.revision, state.audit_id) == (2, applied.audit_id)
    assert state.overrides[KEY_MODE].set_by == ADMIN


def test_no_record_carries_a_token_or_a_secret(store, monkeypatch):
    secret = "whsec_" + "Q" * 40
    monkeypatch.setenv("FORGD_DASHBOARD_FORM_KEY", secret)
    for change in (Change(ACTION_SET, KEY_MODE, "enforce"),
                   Change(ACTION_EXCLUDE, value="req_01"), Change(ACTION_RESET)):
        apply_change(store, ADMIN, change, detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    for name in store.list_audit():
        record = json.loads(store.get_audit(name))
        record.pop("signature", None)
        body = json.dumps(record)
        for needle in (secret, "token", "Bearer", "eyJ"):
            assert needle not in body, (name, needle)


def test_the_request_record_is_written_before_the_state(store, monkeypatch):
    order = []
    real_audit, real_write = store.put_audit, store.write_control
    monkeypatch.setattr(store, "put_audit",
                        lambda n, b: (order.append(n.rsplit("-", 1)[-1]), real_audit(n, b)))
    monkeypatch.setattr(store, "write_control",
                        lambda b, e: (order.append("state"), real_write(b, e)))
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert order == ["request.json", "state", "outcome.json"]


def test_a_lost_race_leaves_a_request_off_the_chain(store, monkeypatch):
    first = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    real_put = store.put_audit

    raced = []

    def racing(name, body):
        if not raced and name.endswith("-request.json"):
            raced.append(True)
            apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_x"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
        return real_put(name, body)

    monkeypatch.setattr(store, "put_audit", racing)
    with pytest.raises(StoreConflict):
        apply_change(store, ADMIN, Change(ACTION_CLEAR, KEY_MODE), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    monkeypatch.undo()
    state = parse_state(store.read_control().body)
    assert state.value(KEY_MODE) == "enforce", "the losing change did not land"
    h = history(store, state)
    assert [r["action"] for r in h.applied] == [ACTION_EXCLUDE, ACTION_SET, ACTION_INIT]
    assert h.applied[-2]["id"] == first.audit_id
    assert [r["action"] for r in h.not_applied] == [ACTION_CLEAR]
    outcomes = [r for r in _records(store) if r["kind"] == "outcome"]
    assert {r["result"] for r in outcomes} == {"applied", "conflict"}


def test_a_stale_revision_is_refused_before_anything_is_written(store):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    before = store.list_audit()
    with pytest.raises(StoreConflict):
        apply_change(store, ADMIN, Change(ACTION_CLEAR, KEY_MODE), expect_revision=0,
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert store.list_audit() == before


def test_the_outcome_record_is_best_effort(store, monkeypatch):
    real = store.put_audit

    def no_outcomes(name, body):
        if name.endswith("-outcome.json"):
            raise OSError("denied")
        return real(name, body)

    monkeypatch.setattr(store, "put_audit", no_outcomes)
    applied = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"),
                           detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert parse_state(store.read_control().body).audit_id == applied.audit_id


def test_a_failed_request_record_changes_nothing(store, monkeypatch):
    def refuse(name, body):
        raise OSError("denied")

    before = _control(store).read_bytes()
    monkeypatch.setattr(store, "put_audit", refuse)
    with pytest.raises(OSError):
        apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert _control(store).read_bytes() == before


def test_clear_all_writes_an_empty_overrides_object_and_keeps_markers(store):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_CLEAR_ALL), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    state = parse_state(store.read_control().body)
    assert dict(state.overrides) == {}
    assert state.excluded_requests == {"req_1"}
    with pytest.raises(NoChange):
        apply_change(store, ADMIN, Change(ACTION_CLEAR_ALL), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


# -- markers ---------------------------------------------------------------


def test_readers_combine_the_legacy_objects_with_the_fields(store):
    store.set_excluded(["req_legacy"])
    store.set_reset_marker("2026-09-01T00:00:00Z")
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_new"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_RESET, value="2026-09-10T00:00:00Z"),
                 detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    overlaid = OverlaidStore(store, _reader(store))
    assert overlaid.get_excluded() == {"req_legacy", "req_new"}
    assert overlaid.describe()["reset_at"] == "2026-09-10T00:00:00Z"
    assert overlaid.describe()["legacy_reset_at"] == "2026-09-01T00:00:00Z"
    store.set_reset_marker("2026-09-20T00:00:00Z")
    assert overlaid.describe()["reset_at"] == "2026-09-20T00:00:00Z"


def test_migration_folds_and_is_idempotent(store):
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_new"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    legacy = ("2026-09-01T00:00:00Z", frozenset({"req_legacy"}))
    apply_change(store, ov.cli_actor(), Change(ACTION_MIGRATE), migrate=legacy, detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    state = parse_state(store.read_control().body)
    assert state.excluded_requests == {"req_new", "req_legacy"}
    assert state.stats_reset == "2026-09-01T00:00:00Z"
    with pytest.raises(NoChange):
        apply_change(store, ov.cli_actor(), Change(ACTION_MIGRATE), migrate=legacy,
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)


def test_the_cli_actor_is_unverified():
    actor = ov.cli_actor()
    assert (actor["issuer"], actor["verified"]) == ("cli", False)


def test_audit_ids_sort_by_time():
    early = ov.new_audit_id(datetime(2026, 9, 1, tzinfo=UTC))
    late = ov.new_audit_id(datetime(2026, 9, 2, tzinfo=UTC))
    assert early < late
    assert audit_name(early, "request").startswith("2026-09-01/")


# -- the hash chain --------------------------------------------------------


def _record_path(store, audit_id):
    return store.root / AUDIT_PREFIX / audit_name(audit_id, "request")


def _rewrite(path, **fields):
    body = json.loads(path.read_bytes())
    body.update(fields)
    path.write_bytes((json.dumps(body, sort_keys=True) + "\n").encode())


def _logged(caplog) -> str:
    """Every log message and its structured fields, as one string."""
    return caplog.text + json.dumps([getattr(r, "fields", {}) for r in caplog.records],
                                    default=str)


def _refused(snap, caplog, held="enforce"):
    """The reader kept its last-known-good, said so at ERROR, and named no value."""
    assert (snap.source, snap.status) == ("last_known_good", "invalid")
    assert snap.state.value(KEY_MODE) == held
    errors = [r for r in caplog.records if r.levelno == logging.ERROR
              and "keeping the values last read" in r.getMessage()]
    assert errors
    for text in [snap.error, *(json.dumps(r.fields) for r in errors)]:
        for value in ("observe", "req_forged", "mallory"):
            assert value not in text, (value, text)


def test_each_record_links_to_the_hash_of_the_one_before(store):
    first = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    second = apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    genesis = [r for r in _records(store) if r.get("action") == ACTION_INIT][0]
    assert genesis["base_hash"] is None
    assert first.record["base_hash"] == ov._sha256(
        store.get_audit(audit_name(genesis["id"], "request")))
    head = store.get_audit(audit_name(second.audit_id, "request"))
    state = parse_state(store.read_control().body)
    assert state.audit_hash == ov._sha256(head)
    assert second.record["base_hash"] == ov._sha256(
        store.get_audit(audit_name(first.audit_id, "request")))
    assert second.record["state_sha256"] == ov.state_digest(state)


def test_an_object_without_a_record_is_not_adopted(store, caplog):
    """Mutation: skip verification of an object that names no record."""
    reader = _reader(store)
    _obj(store, **{KEY_MODE: "enforce"})
    reader.refresh()
    _control(store).write_text(json.dumps(
        {"version": 1, "revision": 2, "overrides": {KEY_MODE: {"value": "observe"}}}))
    with caplog.at_level(logging.ERROR):
        snap = reader.refresh()
    _refused(snap, caplog)
    assert snap.error == "object_names_no_record"
    assert reader.mode("observe") == "enforce"

    cold = _reader(store).refresh()
    assert (cold.source, cold.status) == ("baseline", "invalid")
    with pytest.raises(InvalidState):
        apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode="enforce", detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert (reader.refresh().source, reader.mode("observe")) == ("object", "enforce")


def test_an_object_naming_a_record_it_did_not_come_from_is_not_adopted(store, caplog):
    reader = _reader(store)
    _obj(store, **{KEY_MODE: "enforce"})
    reader.refresh()
    first = parse_state(_control(store).read_bytes())
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    # The first record's id and hash, on an object that also clears the mode.
    raw = json.loads(_control(store).read_bytes())
    raw.update(audit_id=first.audit_id, audit_hash=first.audit_hash, revision=1)
    _control(store).write_text(json.dumps(raw))
    with caplog.at_level(logging.ERROR):
        _refused(reader.refresh(), caplog)


def test_a_head_record_that_does_not_match_its_hash_is_not_adopted(store, caplog):
    """Mutation: drop the hash comparison in `_request`."""
    reader = _reader(store)
    _obj(store, **{KEY_MODE: "enforce"})
    reader.refresh()
    head = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _rewrite(_record_path(store, head.audit_id),
             principal={**ADMIN, "name": "mallory"})
    with caplog.at_level(logging.ERROR):
        snap = reader.refresh()
    _refused(snap, caplog)
    assert snap.error == "chain_hash_mismatch"
    assert _reader(store).refresh().status == "invalid", "a cold start refuses it too"


def test_an_object_that_is_not_what_its_record_produced_is_not_adopted(store, caplog):
    reader = _reader(store)
    _obj(store, **{KEY_MODE: "enforce"})
    reader.refresh()
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    raw = json.loads(_control(store).read_bytes())
    raw["excluded_requests"] = ["req_forged"]
    _control(store).write_text(json.dumps(raw))
    with caplog.at_level(logging.ERROR):
        snap = reader.refresh()
    _refused(snap, caplog)
    assert snap.error == "head_state_mismatch"


def test_a_forged_middle_record_breaks_the_chain(store, caplog):
    """Mutation: verify the head alone, not the links back to the last head."""
    reader = _reader(store)
    _obj(store, **{KEY_MODE: "enforce"})
    reader.refresh()
    middle = apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _rewrite(_record_path(store, middle.audit_id), new_value="req_forged")
    with caplog.at_level(logging.ERROR):
        snap = reader.refresh()
    _refused(snap, caplog)
    assert snap.error == "chain_hash_mismatch"


def test_a_rolled_back_object_is_not_adopted(store, caplog):
    reader = _reader(store)
    _obj(store, **{KEY_MODE: "observe"})
    old = _control(store).read_bytes()
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    reader.refresh()
    _control(store).write_bytes(old)
    with caplog.at_level(logging.ERROR):
        snap = reader.refresh()
    _refused(snap, caplog)
    assert snap.error == "revision_not_after_trusted"


def test_a_reader_follows_several_changes_in_one_refresh(store):
    reader = _reader(store)
    _obj(store, **{KEY_MODE: "enforce"})
    reader.refresh()
    for change in (Change(ACTION_EXCLUDE, value="req_1"), Change(ACTION_RESET),
                   Change(ACTION_SET, KEY_MODE, "observe")):
        apply_change(store, ADMIN, change, detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    snap = reader.refresh()
    assert (snap.source, snap.status, snap.state.revision) == ("object", "ok", 5)


def test_history_flags_an_overwritten_record_on_the_chain(store):
    """Mutation: never add to `tampered`."""
    first = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    middle = apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    head = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    state = parse_state(store.read_control().body)
    assert history(store, state).tampered == frozenset()
    _rewrite(_record_path(store, middle.audit_id), new_value="req_forged")
    h = history(store, state)
    assert [r["id"] for r in h.applied][:3] == [head.audit_id, middle.audit_id, first.audit_id]
    assert h.tampered == {middle.audit_id}


def test_a_head_record_that_names_another_change_is_refused(store):
    """Mutation: `_names_change` always true."""
    _obj(store, **{KEY_MODE: "enforce"})
    state = parse_state(store.read_control().body)
    ov.verify_head(store, state)
    record = json.loads(store.get_audit(audit_name(state.audit_id, "request")))
    record.update(id=ov.new_audit_id(), action=ACTION_CLEAR)
    state = ov.replace(state, audit_id=record["id"],
                       overrides={KEY_MODE: ov.replace(state.overrides[KEY_MODE],
                                                       audit_id=record["id"])})
    record["state_sha256"] = ov.state_digest(state)
    blob = ov._record_bytes(record)
    store.put_audit(audit_name(record["id"], "request"), blob)
    state = ov.replace(state, audit_hash=ov._sha256(blob))
    with pytest.raises(InvalidState, match="^head_change_mismatch$"):
        ov.verify_head(store, state)


def test_a_cold_start_refuses_a_forged_middle_record(store, caplog):
    """Mutation: verify the head alone when there is no last-known-good."""
    _obj(store, **{KEY_MODE: "enforce"})
    middle = apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert _reader(store).refresh().status == "ok"
    _rewrite(_record_path(store, middle.audit_id), new_value="req_forged")
    with caplog.at_level(logging.ERROR):
        snap = _reader(store).refresh()
    assert (snap.source, snap.status) == ("baseline", "invalid")
    assert snap.error == "chain_hash_mismatch"
    assert "req_forged" not in json.dumps([r.fields for r in caplog.records
                                           if hasattr(r, "fields")])


def test_a_cold_start_walks_past_a_recover_to_its_start(store):
    _obj(store, **{KEY_MODE: "enforce"})
    _control(store).write_bytes(b"{broken")
    apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode="observe", detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    snap = _reader(store).refresh()
    assert (snap.source, snap.status) == ("object", "ok")
    assert snap.state.value(KEY_MODE) == "observe"


def _forge_head(store, **fields):
    """Replace the head with a record and object consistent with each other,
    as a writer to both the audit prefix and the object could, with `fields`
    changed on the record."""
    state = parse_state(store.read_control().body)
    record = json.loads(store.get_audit(audit_name(state.audit_id, "request")))
    record.update(id=ov.new_audit_id(), **fields)
    state = ov.replace(state, audit_id=record["id"], revision=record["base_revision"] + 1)
    record["state_sha256"] = ov.state_digest(state)
    blob = ov._record_bytes(record)
    store.put_audit(audit_name(record["id"], "request"), blob)
    _control(store).write_bytes(ov.replace(state, audit_hash=ov._sha256(blob)).to_bytes())


def test_a_chain_that_skips_a_revision_is_refused(store):
    """Mutation: drop the one-revision-per-link check."""
    _obj(store, **{KEY_MODE: "enforce"})
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    head = json.loads(store.get_audit(audit_name(
        parse_state(store.read_control().body).audit_id, "request")))
    _forge_head(store, base_revision=3, base_audit_id=head["base_audit_id"],
                base_hash=head["base_hash"])
    snap = _reader(store).refresh()
    assert (snap.source, snap.status) == ("baseline", "invalid")
    assert snap.error == "chain_skips_revision"


def test_a_start_of_chain_that_names_a_base_hash_is_refused(store):
    """Mutation: drop the check that a record with no base names no base hash."""
    _obj(store, **{KEY_MODE: "enforce"})
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    head = json.loads(store.get_audit(audit_name(
        parse_state(store.read_control().body).audit_id, "request")))
    _forge_head(store, base_audit_id=None, base_hash=head["base_hash"])
    snap = _reader(store).refresh()
    assert snap.error == "base_hash_without_record"


def test_a_link_to_another_records_bytes_is_refused(store):
    """Mutation: drop the check that a record is the one it is named for."""
    first = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    decoy = ov.new_audit_id()
    blob = store.get_audit(audit_name(first.audit_id, "request"))
    store.put_audit(audit_name(decoy, "request"), blob)
    _forge_head(store, base_audit_id=decoy, base_hash=ov._sha256(blob))
    snap = _reader(store).refresh()
    assert snap.error == "chain_record_misnamed"


# -- retiring the legacy markers ---------------------------------------------


def _legacy(store):
    store.set_excluded(["req_legacy"])
    store.set_reset_marker("2026-09-01T00:00:00Z")


def _migrate(store):
    return apply_change(store, ov.cli_actor(), Change(ACTION_MIGRATE),
                        migrate=(store.get_reset_marker(), frozenset(store.get_excluded())),
                        detectors=DETECTORS, signing_key=OVERRIDES_KEY)


def test_before_retirement_a_writer_changing_a_legacy_marker_still_applies(store):
    """Mutation: treat the legacy markers as retired always."""
    _legacy(store)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_new"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    overlaid = OverlaidStore(store, _reader(store))
    store.set_excluded(["req_written"])
    store.set_reset_marker("2026-09-20T00:00:00Z")
    assert overlaid.get_excluded() == {"req_written", "req_new"}
    assert overlaid.describe()["reset_at"] == "2026-09-20T00:00:00Z"


def test_after_retirement_a_writer_changing_a_legacy_marker_changes_nothing(store):
    """Mutation: drop the retirement check from either effective reader."""
    _legacy(store)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_new"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _migrate(store)
    flaky = Flaky(store)
    overlaid = OverlaidStore(store, _reader(flaky))
    expected = ({"req_new", "req_legacy"}, "2026-09-01T00:00:00Z")
    assert (overlaid.get_excluded(), overlaid.describe()["reset_at"]) == expected
    for ids, when in ((["req_written"], "2099-01-01T00:00:00Z"), ([], "")):
        store.set_excluded(ids)
        store.set_reset_marker(when)
        assert (overlaid.get_excluded(), overlaid.describe()["reset_at"]) == expected
    flaky.fail = True
    overlaid.overrides.refresh()
    store.set_excluded(["req_written"])
    assert overlaid.get_excluded() == expected[0], "a last-known-good keeps them retired"


def test_migration_is_audited_idempotent_and_hash_bound(store):
    """Mutation: let a second migration through once retired."""
    _legacy(store)
    applied = _migrate(store)
    assert applied.record["action"] == ACTION_MIGRATE
    assert applied.record["new_value"][ov.FIELD_RETIRED] is True
    reader = _reader(store)
    assert reader.refresh().status == "ok" and reader.legacy_retired()
    store.set_excluded(["req_later"])
    before = store.list_audit()
    with pytest.raises(NoChange):
        _migrate(store)
    assert store.list_audit() == before
    raw = json.loads(_control(store).read_bytes())
    del raw[ov.FIELD_RETIRED], raw[ov.FIELD_RETIRED_BY]
    _control(store).write_text(json.dumps(raw))
    snap = _reader(store).refresh()
    assert (snap.status, snap.error) == (
        "invalid", "head_retirement_mismatch")


def test_an_object_without_the_flag_keeps_its_bytes_and_parses_as_not_retired(store):
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    body = store.read_control().body
    assert ov.FIELD_RETIRED.encode() not in body
    assert parse_state(body).legacy_markers_retired is False
    with pytest.raises(InvalidState):
        parse_state(json.dumps({"version": 1, ov.FIELD_RETIRED: "yes"}).encode())


@pytest.mark.parametrize("when", ["2026-02-30T00:00:00Z", "2026-13-01T00:00:00Z",
                                  "2026-09-28T24:00:00Z", "2026-09-28T12:60:00Z",
                                  "2025-02-29T00:00:00.5Z"])
def test_an_impossible_reset_time_is_refused(store, when):
    """Mutation: check the shape only, not that the date exists."""
    before = store.list_audit()
    with pytest.raises(Refused):
        apply_change(store, ADMIN, Change(ACTION_RESET, value=when), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    with pytest.raises(InvalidState):
        parse_state(json.dumps({"version": 1, "stats_reset": when}).encode())
    assert store.list_audit() == before


@pytest.mark.parametrize("when", ["2024-02-29T23:59:59Z", "2026-09-28T14:03:11.123456Z"])
def test_a_real_reset_time_is_accepted(store, when):
    applied = apply_change(store, ADMIN, Change(ACTION_RESET, value=when),
                           detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.stats_reset == when


# -- the error gauge -----------------------------------------------------------


def test_the_error_gauge_is_one_exactly_when_a_read_fails(store, caplog):
    """Alongside the ERROR log, every time. Mutation: never raise the gauge."""
    flaky = Flaky(store)
    reader = _reader(flaky)
    assert reader.refresh().fields()["in_error"] == 0, "a cold-start absence is not an error"
    flaky.fail = True
    assert reader.refresh().fields()["in_error"] == 1, "unreadable with nothing held"
    flaky.fail = False
    _obj(store, **{KEY_MODE: "enforce"})
    assert reader.refresh().fields()["in_error"] == 0
    cases = [
        lambda: setattr(flaky, "fail", True),
        lambda: _control(store).write_bytes(b"{broken"),
        lambda: _control(store).unlink(),
    ]
    for break_it in cases:
        break_it()
        with caplog.at_level(logging.ERROR):
            caplog.clear()
            snap = reader.refresh()
        assert snap.source == "last_known_good"
        assert snap.fields()["in_error"] == 1, snap.status
        assert [r for r in caplog.records if r.levelno == logging.ERROR]
        flaky.fail = False
        _control(store).unlink(missing_ok=True)
        apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode="enforce",
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
        assert reader.refresh().fields()["in_error"] == 0


def test_the_error_gauge_is_raised_by_a_tampered_chain(store):
    reader = _reader(store)
    _obj(store, **{KEY_MODE: "enforce"})
    reader.refresh()
    head = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "observe"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _rewrite(_record_path(store, head.audit_id), principal={**ADMIN, "name": "mallory"})
    assert reader.refresh().fields()["in_error"] == 1


# -- request ids -------------------------------------------------------------


# 919108f7-... is the RFC 9562 Appendix A.3 UUIDv4 example.
@pytest.mark.parametrize("rid", [
    "req_01_simple_text", "msg_01EXAMPLEaBcDeFgHiJkLmNoPq",
    "UserPromptSubmit:prompt", "UserPromptSubmit:prompt:919108f7-52d1-4320-9bac-f847db4148a8",
    "PreToolUse:Bash:toolu_01EXAMPLEa1b2c3d4e5f6g7",
    "PreToolUse:mcp__plugin_example_data-eu__list_items:01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "UserPromptExpansion:prompt:01ARZ3NDEKTSV4RRFFQ69G5FAV", "PostToolUse:01ARZ3NDEKTSV4RRFFQ69G5FAV",
])
def test_a_request_id_in_a_producers_format_is_accepted(rid):
    assert request_id_ok(rid)


@pytest.mark.parametrize("rid", [
    "", "req 1", "req.1", "req/1", "../x", "req_1\n", "req:1", "Stop:prompt:x",
    "PreToolUse:", "PreToolUse:Bash:", "PreToolUse:Bash:x:y", "a" * 129, "prompt:é",
    "<script>", "req_1;rm",
])
def test_a_request_id_in_no_producers_format_is_refused(store, rid):
    """Mutation: restore the printable-ASCII pattern."""
    assert not request_id_ok(rid)
    before = store.list_audit()
    with pytest.raises(Refused):
        apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value=rid), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert store.list_audit() == before


def test_the_hook_and_intake_ids_are_request_ids(tmp_path):
    from forgd_verdict.hook.cli import run
    from forgd_verdict.models import ulid
    from forgd_verdict.store.spool import Spool

    policy = make_policy(detectors={"gitleaks": {"enabled": False, "severity": "block"}},
                         hook={"spool": str(tmp_path / "spool"), "ship_mode": "off",
                               "enabled_events": ["UserPromptSubmit", "PreToolUse"]})
    # The prompt id is the RFC 9562 Appendix A.3 UUIDv4 example.
    run({"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "prompt_id": "919108f7-52d1-4320-9bac-f847db4148a8", "prompt": "hello"}, policy)
    run({"hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": "hello"}, policy)
    run({"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash",
         "tool_use_id": "toolu_01EXAMPLEa1b2c3d4e5f6g7",
         "tool_input": {"command": "ls"}}, policy)
    spool = Spool(tmp_path / "spool")
    ids = [r.request_id for batch in spool.claim() for r in Spool.read(batch)]
    assert len(ids) == 3
    assert all(request_id_ok(rid) for rid in ids), ids
    for event in ("UserPromptSubmit", "UserPromptExpansion", "PreToolUse", "PostToolUse"):
        assert request_id_ok(f"{event}:{ulid()}")


def test_the_golden_frames_carry_request_ids():
    from pathlib import Path

    golden = sorted((Path(__file__).parent / "golden").glob("*.json"))
    assert golden
    for path in golden:
        assert request_id_ok(json.loads(path.read_text())["frame"]["request_id"]), path.name


# -- values a detector matches ---------------------------------------------


def _stored_bytes(store) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(store.root.rglob("*")) if p.is_file()
                    and "markers" not in p.parts)


SECRET_CHANGES = [
    Change(ACTION_EXCLUDE, value=FAKE_GITHUB_TOKEN),
    Change(ACTION_EXCLUDE, value=f"PreToolUse:Bash:{FAKE_GITHUB_TOKEN}"),
    Change(ACTION_EXCLUDE, value=FAKE_AWS_KEY),
    Change(ACTION_UNEXCLUDE, value=FAKE_GITHUB_TOKEN),
    Change(ACTION_SET, KEY_MODE, FAKE_GITHUB_TOKEN),
    Change(ACTION_SET, FAKE_GITHUB_TOKEN, "enforce"),
    Change(ACTION_CLEAR, FAKE_GITHUB_TOKEN),
    Change(ACTION_RESET, value=FAKE_GITHUB_TOKEN),
]


@pytest.mark.parametrize("change", SECRET_CHANGES, ids=lambda c: c.action)
def test_a_value_a_detector_matches_is_refused_and_never_stored(store, caplog, change):
    """Mutation: drop the screen at the top of apply_change."""
    _obj(store, **{KEY_MODE: "enforce"})
    before = (_control(store).read_bytes(), store.list_audit())
    with caplog.at_level(logging.DEBUG), pytest.raises(Refused) as exc:
        apply_change(store, ADMIN, change, detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert str(exc.value).startswith("the change matched a detector: regex:")
    assert (_control(store).read_bytes(), store.list_audit()) == before
    for secret in (FAKE_GITHUB_TOKEN, FAKE_AWS_KEY):
        assert secret not in str(exc.value)
        assert secret.encode() not in _stored_bytes(store)
        assert secret not in _logged(caplog)


def test_a_recover_mode_a_detector_matches_is_refused(store):
    _control(store).write_bytes(b"{broken")
    before = store.list_audit()
    with pytest.raises(Refused, match="matched a detector"):
        apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode=FAKE_GITHUB_TOKEN,
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert store.list_audit() == before


def test_a_migration_leaves_behind_legacy_values_a_detector_matches(store, caplog):
    """Mutation: fold a legacy id in without scanning it."""
    legacy = (None, frozenset({"req_legacy", FAKE_GITHUB_TOKEN}))
    with caplog.at_level(logging.DEBUG):
        applied = apply_change(store, ov.cli_actor(), Change(ACTION_MIGRATE), migrate=legacy,
                               detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.excluded_requests == {"req_legacy"}
    assert applied.state.legacy_markers_retired is True
    assert applied.record["new_value"]["excluded_requests"] == ["req_legacy"]
    assert FAKE_GITHUB_TOKEN.encode() not in _stored_bytes(store)
    assert FAKE_GITHUB_TOKEN not in _logged(caplog)
    assert "left legacy exclusions behind" in caplog.text


def test_a_migration_leaves_behind_a_legacy_reset_that_is_not_a_time(store):
    applied = apply_change(store, ov.cli_actor(), Change(ACTION_MIGRATE),
                           migrate=(FAKE_GITHUB_TOKEN, frozenset()), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.stats_reset is None
    assert FAKE_GITHUB_TOKEN.encode() not in _stored_bytes(store)
    assert parse_state(_control(store).read_bytes()) == applied.state


def test_no_detectors_or_one_that_did_not_run_refuses(store):
    from forgd_verdict.detectors.base import TIER_T0, DetectorFailed

    class Broken:
        name, tier = "broken", TIER_T0

        def scan(self, units):
            raise DetectorFailed("down")

    before = store.list_audit()
    for detectors, match in (((), "no detectors"), ((Broken(),), "broken did not run")):
        with pytest.raises(Refused, match=match):
            apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"),
                         detectors=detectors)
    with pytest.raises(Refused, match="broken did not run"):
        apply_change(store, ov.cli_actor(), Change(ACTION_MIGRATE),
                     migrate=(None, frozenset({"req_legacy"})), detectors=(Broken(),))
    assert store.list_audit() == before
    screen(["req_1", {"k": ["v"]}, None, 3], DETECTORS)


class Blind:
    """A detector that finds nothing, to plant a value in a valid chain."""

    name, tier = "blind", 0

    def scan(self, units):
        return []


@pytest.mark.parametrize("field,secret", [
    ("name", FAKE_GITHUB_TOKEN), ("subject", FAKE_AWS_KEY), ("issuer", FAKE_GITHUB_TOKEN)])
def test_a_principal_a_detector_matches_never_reaches_a_record(store, caplog, field, secret):
    """Mutation: drop the scan of the finished record."""
    _obj(store, **{KEY_MODE: "enforce"})
    before = (_control(store).read_bytes(), store.list_audit())
    with caplog.at_level(logging.DEBUG), pytest.raises(Refused) as exc:
        apply_change(store, {**ADMIN, field: secret}, Change(ACTION_SET, KEY_MODE, "observe"),
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert str(exc.value).startswith("the change matched a detector: regex:")
    assert secret not in str(exc.value) and secret not in _logged(caplog)
    assert (_control(store).read_bytes(), store.list_audit()) == before
    assert secret.encode() not in _stored_bytes(store)


def test_a_secret_already_in_the_state_never_reaches_a_new_record(store, caplog):
    """Mutation: drop both scans; either one alone refuses it."""
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value=FAKE_GITHUB_TOKEN),
                 detectors=(Blind(),))
    planted = set(store.list_audit())
    with caplog.at_level(logging.DEBUG), pytest.raises(Refused) as exc:
        apply_change(store, ADMIN, Change(ACTION_UNEXCLUDE, value=FAKE_GITHUB_TOKEN),
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert str(exc.value) == "the change matched a detector: regex:github-token"
    assert set(store.list_audit()) == planted
    assert FAKE_GITHUB_TOKEN not in _logged(caplog)

    cleared = apply_change(store, ADMIN, Change(ov.ACTION_EXCLUDE_CLEAR), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert cleared.record["old_value"] == 1
    new = set(store.list_audit()) - planted
    assert new and all(FAKE_GITHUB_TOKEN.encode() not in store.get_audit(n) for n in new)
    assert FAKE_GITHUB_TOKEN.encode() not in _control(store).read_bytes()


# -- retirement is one-way -------------------------------------------------


def _at_of(audit_id, offset_s=0):
    """The `at` a record minted as `audit_id` carries, `offset_s` later."""
    minted = datetime.strptime(audit_id[:16], "%Y%m%dT%H%M%SZ")
    return f"{minted + timedelta(seconds=offset_s):%Y-%m-%dT%H:%M:%SZ}"


def _forge_next(store, action, new_value=None, start=False, audit_id=None, at=None,
                **state_fields):
    """Write a record and object consistent with each other, as the control
    identity could: the next revision after the head, linked to it unless
    `start`, with `state_fields` changed on the object."""
    head = parse_state(store.read_control().body)
    audit_id = audit_id or ov.new_audit_id()
    at = at or _at_of(audit_id)
    state = ov._stamped(ov.replace(head, revision=head.revision + 1, audit_id=audit_id,
                                   audit_hash=None, updated_at=at, **state_fields), None)
    record = {
        "version": 1, "kind": "request", "id": audit_id, "at": at, "principal": ADMIN,
        "action": action, "key": None, "old_value": None, "new_value": new_value,
        "base_revision": head.revision,
        "base_audit_id": None if start else head.audit_id,
        "base_hash": None if start else head.audit_hash,
        "state_sha256": ov.state_digest(state),
        ov.FIELD_RETIRED: state.legacy_markers_retired, "retired_by": None,
        ov.FIELD_MIN_READER: state.min_reader_version,
    }
    if action in (ACTION_RECOVER, ov.ACTION_CHECKPOINT):
        record["new_value"] = ov.snapshot_of(state)
    blob = ov._record_bytes(record)
    store.put_audit(audit_name(audit_id, "request"), blob)
    _control(store).write_bytes(ov.replace(state, audit_hash=ov._sha256(blob)).to_bytes())


def _forge_reset(store, n):
    """`n` stats resets forged on the head, each a transition apply_change
    could have written, as the control identity could."""
    head = parse_state(store.read_control().body)
    for i in range(n):
        audit_id = ov.new_audit_id()
        at = _at_of(audit_id)
        when = f"2026-{1 + i % 12:02d}-{1 + (i // 12) % 28:02d}T{(i // 336) % 24:02d}:00:00Z"
        record = {
            "version": 1, "kind": "request", "id": audit_id, "at": at, "principal": ADMIN,
            "action": ACTION_RESET, "key": ov.FIELD_RESET, "old_value": head.stats_reset,
            "new_value": when, "base_revision": head.revision, "base_audit_id": head.audit_id,
            "base_hash": head.audit_hash, ov.FIELD_RETIRED: head.legacy_markers_retired,
            "retired_by": None, ov.FIELD_MIN_READER: head.min_reader_version,
        }
        state = ov._transition(head, record)
        record["state_sha256"] = ov.state_digest(state)
        blob = ov._record_bytes(record)
        store.put_audit(audit_name(audit_id, "request"), blob)
        head = ov.replace(state, audit_hash=ov._sha256(blob))
    _control(store).write_bytes(head.to_bytes())


def _retired_store(store):
    _legacy(store)
    migration = _migrate(store)
    reader = _reader(store)
    assert reader.refresh().status == "ok" and reader.legacy_retired()
    return migration, reader


def test_later_writes_keep_the_markers_retired(store):
    _retired_store(store)
    for change in (Change(ACTION_SET, KEY_MODE, "enforce"), Change(ACTION_EXCLUDE, value="req_2"),
                   Change(ACTION_RESET, value="2026-09-20T00:00:00Z"), Change(ACTION_CLEAR_ALL),
                   Change(ov.ACTION_EXCLUDE_CLEAR), Change(ov.ACTION_RESET_CLEAR)):
        applied = apply_change(store, ADMIN, change, detectors=DETECTORS, signing_key=OVERRIDES_KEY)
        assert applied.state.legacy_markers_retired, change.action
        assert applied.record[ov.FIELD_RETIRED] is True
        assert applied.record["retired_by"] is None
    reader = _reader(store)
    assert reader.refresh().status == "ok" and reader.legacy_retired()


def test_recovery_after_retirement_keeps_the_markers_retired(store):
    """Mutation: recover as not retired."""
    migration, warm = _retired_store(store)
    raw = json.loads(_control(store).read_bytes())
    raw["version"] = 99
    _control(store).write_text(json.dumps(raw))
    applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode="enforce",
                           detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.legacy_markers_retired
    assert applied.state.retired_by == migration.audit_id
    assert applied.record["retired_by"] == {
        "id": migration.audit_id,
        "sha256": ov._sha256(store.get_audit(audit_name(migration.audit_id, "request")))}
    assert (applied.state.stats_reset, applied.state.excluded_requests) == (
        migration.state.stats_reset, migration.state.excluded_requests)
    for reader in (warm, _reader(store)):
        snap = reader.refresh()
        assert (snap.status, snap.source, snap.error) == ("ok", "object", None)
        assert reader.legacy_retired()
    store.set_excluded(["req_writer"])
    assert "req_writer" not in OverlaidStore(store, _reader(store)).get_excluded()
    with pytest.raises(NoChange, match="already retired"):
        _migrate(store)

def test_recovery_before_any_migration_is_not_retired(store):
    _obj(store, **{KEY_MODE: "enforce"})
    _control(store).unlink()
    applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert not applied.state.legacy_markers_retired
    assert applied.record["retired_by"] is None
    assert _reader(store).refresh().status == "ok"


def test_a_restored_pre_retirement_object_is_refused_cold_and_warm(store):
    """Restoring the object to its version before the migration, with the
    migration record gone: its own chain is intact and signed. The warm
    reader's retired state refuses it, and a cold reader refuses it because
    the fresh verification record names the retired head. Mutation: drop
    the retired-to-not check on the trusted state, or the anchor check."""
    from forgd_verdict import lockout
    from forgd_verdict.lockout import LockoutReports
    from forgd_verdict.lockout_evidence import verifier

    keys = (OVERRIDES_PUBLIC,)
    store.lockout_provable = True
    _legacy(store)
    before = _control(store).read_bytes()
    migration = _migrate(store)
    verifier.verify(store, ("writer",), evaluate=lambda s, ids, **_: {"writer": None},
                    signing_key=OVERRIDES_KEY, verify_keys=keys,
                    trusted=lambda: ov.anchor_of(parse_state(store.read_control().body)))

    def reader():
        return RuntimeOverrides(store, "test", baseline={KEY_MODE: "observe"}, clock=Clock(),
                                verify_keys=keys,
                                fleet=LockoutReports(store, ("verdict",), verify_keys=keys))

    warm = reader()
    assert warm.refresh().status == "ok" and warm.legacy_retired()
    _record_path(store, migration.audit_id).unlink()
    _control(store).write_bytes(before)
    snap = warm.refresh()
    assert (snap.source, snap.status) == ("last_known_good", "invalid")
    assert snap.error == "object_unretires"
    assert warm.legacy_retired()
    cold = reader()
    snap = cold.refresh()
    assert (snap.status, snap.error, snap.ready) == ("invalid", "object_before_anchor", False)
    assert not cold.legacy_retired()
    assert lockout.anchored_head(store, keys)["revision"] == migration.state.revision


def test_recovering_an_unparseable_object_keeps_the_retirement_its_chain_holds(store):
    """The object names nothing, but the newest applied record's chain
    verifies, so the recover keeps what it produced."""
    migration, warm = _retired_store(store)
    _control(store).write_bytes(b"{broken")
    applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.legacy_markers_retired
    assert applied.state.excluded_requests == migration.state.excluded_requests
    for reader in (warm, _reader(store)):
        assert reader.refresh().status == "ok" and reader.legacy_retired()


def test_a_cold_reader_refuses_a_link_that_un_retires(store):
    """Mutation: drop the un-retire check on a link."""
    _retired_store(store)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_2"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _forge_next(store, ACTION_CLEAR_ALL, {}, legacy_markers_retired=False)
    snap = _reader(store).refresh()
    assert (snap.status, snap.error) == ("invalid", "link_unretires")


def test_only_a_migration_retires_the_legacy_markers(store):
    """Mutation: let a link, or a start naming no migration, retire."""
    _obj(store, **{KEY_MODE: "enforce"})
    _forge_next(store, ACTION_CLEAR_ALL, {}, overrides={}, legacy_markers_retired=True,
                retired_by=ov.new_audit_id())
    snap = _reader(store).refresh()
    assert snap.error == "link_retires_without_migration"

    _forge_next(store, ACTION_RECOVER, {KEY_MODE: None}, start=True, overrides={},
                legacy_markers_retired=True, retired_by=ov.new_audit_id())
    snap = _reader(store).refresh()
    assert snap.error == "start_retired_unnamed"


def _set_outcome(store, audit_id, result):
    """Replace or remove `audit_id`'s outcome record."""
    path = store.root / AUDIT_PREFIX / audit_name(audit_id, "outcome")
    if result is None:
        path.unlink()
    else:
        path.write_text(json.dumps({"version": 1, "kind": "outcome", "request_id": audit_id,
                                    "result": result, "at": "2026-09-28T12:00:00Z"}))


def _forge_start_naming(store, target):
    """A retired recover start naming `target`, by id and stored hash, as
    the control identity could write it."""
    _forge_next(store, ACTION_RECOVER, {KEY_MODE: None}, start=True, overrides={},
                stats_reset=None, excluded_requests=frozenset(), retired_by=target)
    state = parse_state(store.read_control().body)
    path = _record_path(store, state.audit_id)
    record = json.loads(path.read_bytes())
    record["retired_by"] = {"id": target, "sha256": ov._stored_hash(store, target)}
    blob = ov._record_bytes(record)
    path.write_bytes(blob)
    _control(store).write_bytes(ov.replace(state, audit_hash=ov._sha256(blob)).to_bytes())


def test_a_start_that_names_something_other_than_a_migration_is_refused(store):
    """Mutation: accept a named record that is not a migration."""
    _legacy(store)
    _migrate(store)
    target = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"),
                          detectors=DETECTORS, signing_key=OVERRIDES_KEY).audit_id
    _forge_start_naming(store, target)
    assert _reader(store).refresh().error == "start_names_non_migration"


@pytest.mark.parametrize("named", ["conflict", "error", "unknown", "unreadable"])
def test_a_start_naming_a_migration_does_not_read_its_outcome(store, named):
    """The start, a verified record, vouches for the migration by hash; an
    outcome record decides nothing. Mutation: refuse on the outcome."""
    _legacy(store)
    migration = _migrate(store)
    target = migration.audit_id
    if named == "unreadable":
        (store.root / AUDIT_PREFIX / audit_name(target, "outcome")).write_text("{broken")
    else:
        _set_outcome(store, target, named)
    _forge_start_naming(store, target)
    reader = _reader(store)
    assert reader.refresh().status == "ok" and reader.legacy_retired()


def test_a_start_naming_a_migration_with_no_outcome_is_accepted(store):
    """The outcome record is best effort. Mutation: require one."""
    _legacy(store)
    migration = _migrate(store)
    _set_outcome(store, migration.audit_id, None)
    _forge_start_naming(store, migration.audit_id)
    reader = _reader(store)
    assert reader.refresh().status == "ok" and reader.legacy_retired()


def test_a_start_naming_a_migration_whose_bytes_changed_is_refused(store):
    """Mutation: take the named hash from the stored bytes, not the start."""
    _legacy(store)
    migration = _migrate(store)
    _set_outcome(store, migration.audit_id, None)
    _forge_start_naming(store, migration.audit_id)
    path = _record_path(store, migration.audit_id)
    path.write_bytes(path.read_bytes() + b" ")
    snap = _reader(store).refresh()
    assert (snap.status, snap.error) == (
        "invalid", "chain_hash_mismatch")

def test_recover_has_no_keep_markers_option():
    assert "keep_markers" not in inspect.signature(apply_change).parameters


def test_a_migration_that_conflicted_does_not_retire_a_recovery(store, monkeypatch):
    """Mutation: count a migration whose outcome says it conflicted."""
    _obj(store, **{KEY_MODE: "enforce"})
    _legacy(store)
    real = store.write_control

    def conflict(body, etag):
        raise StoreConflict("raced")

    monkeypatch.setattr(store, "write_control", conflict)
    with pytest.raises(StoreConflict):
        _migrate(store)
    monkeypatch.setattr(store, "write_control", real)
    migration = [n for n in store.list_audit() if n.endswith("-request.json")][-1]
    raw = json.loads(_control(store).read_bytes())
    raw.update(version=99, **{ov.FIELD_RETIRED_BY: migration.split("/")[1][:-13]})
    _control(store).write_text(json.dumps(raw))
    applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert not applied.state.legacy_markers_retired
    assert applied.record["retired_by"] is None
    assert _reader(store).refresh().status == "ok"

def test_a_migration_with_no_outcome_still_retires_a_recovery(store):
    """Mutation: count a migration only with an `applied` outcome."""
    migration, warm = _retired_store(store)
    _set_outcome(store, migration.audit_id, None)
    raw = json.loads(_control(store).read_bytes())
    raw["version"] = 99
    _control(store).write_text(json.dumps(raw))
    applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.legacy_markers_retired
    assert applied.state.retired_by == migration.audit_id
    assert applied.record["retired_by"] == {
        "id": migration.audit_id, "sha256": ov._stored_hash(store, migration.audit_id)}
    assert applied.state.excluded_requests == migration.state.excluded_requests
    for reader in (warm, _reader(store)):
        snap = reader.refresh()
        assert (snap.status, snap.source) == ("ok", "object") and reader.legacy_retired()
    store.set_excluded(["req_writer"])
    assert "req_writer" not in OverlaidStore(store, _reader(store)).get_excluded()
    with pytest.raises(NoChange, match="already retired"):
        _migrate(store)


def test_a_recovery_keeps_the_retirement_the_invalid_object_names(store, caplog):
    """The newest chains do not verify, so the kept state predates the
    migration; the invalid object still names it. Mutation: take
    retirement from the kept state only."""
    _obj(store, **{KEY_MODE: "enforce"})
    _legacy(store)
    migration = _migrate(store)
    _set_outcome(store, migration.audit_id, None)
    path = _record_path(store, migration.audit_id)
    record = json.loads(path.read_bytes())
    record["at"] = _at_of(migration.audit_id, 60)
    path.write_bytes(ov._record_bytes(record))
    raw = json.loads(_control(store).read_bytes())
    raw["version"] = 99
    _control(store).write_text(json.dumps(raw))
    with caplog.at_level(logging.WARNING, "forgd_verdict"):
        applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.legacy_markers_retired
    assert applied.state.retired_by == migration.audit_id
    assert any("retirement the invalid object names" in r.getMessage() for r in caplog.records)
    reader = _reader(store)
    assert reader.refresh().status == "ok" and reader.legacy_retired()


def test_a_recovery_keeps_a_retirement_its_chain_holds_whatever_the_outcome_says(store):
    """The kept chain walks through the migration, whose outcome record says
    it conflicted. The chain decides. Mutation: consult the outcome."""
    migration, _ = _retired_store(store)
    _set_outcome(store, migration.audit_id, "conflict")
    raw = json.loads(_control(store).read_bytes())
    raw["version"] = 99
    _control(store).write_text(json.dumps(raw))
    applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS,
                           signing_key=OVERRIDES_KEY)
    assert applied.state.legacy_markers_retired
    assert applied.state.retired_by == migration.audit_id


def test_a_checkpoint_carries_a_retirement_whose_migration_has_no_outcome(store):
    """Mutation: refuse a checkpoint whose migration has no outcome."""
    migration, _ = _retired_store(store)
    _set_outcome(store, migration.audit_id, None)
    for i in range(ov.CHECKPOINT_EVERY + 1):
        apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value=f"req_{i}"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    starts = [n for n in store.list_audit() if n.endswith("-request.json")
              and json.loads(store.get_audit(n))["action"] == ov.ACTION_CHECKPOINT]
    assert len(starts) == 1
    reader = _reader(store)
    assert reader.refresh().status == "ok" and reader.legacy_retired()


# -- the bounded walk ------------------------------------------------------


def _chain(store, links):
    """`links` records on the genesis record, each consistent with the last."""
    _forge_reset(store, links)


def _nth_back(store, n):
    """The request record `n` links back from the head."""
    audit_id = parse_state(store.read_control().body).audit_id
    for _ in range(n):
        audit_id = json.loads(store.get_audit(audit_name(audit_id, "request")))["base_audit_id"]
    return audit_id


EVERY = ov.CHECKPOINT_EVERY


def _counting(store, monkeypatch):
    """A list that grows by one name for every audit record `store` reads."""
    reads: list[str] = []
    real = store.get_audit

    def get_audit(name):
        reads.append(name)
        return real(name)

    monkeypatch.setattr(store, "get_audit", get_audit)
    return reads


def _checkpoints(store):
    return [n for n in store.list_audit() if n.endswith("-request.json")
            and json.loads(store.get_audit(n))["action"] == ov.ACTION_CHECKPOINT]


def _excluded(store, first, last):
    for i in range(first, last):
        apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value=f"req_{i}"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


def test_250_real_changes_stay_cold_readable_in_about_100_reads(store, monkeypatch):
    """Mutation: write no checkpoint; do not end a walk at one."""
    _excluded(store, 0, 250)
    assert len(_checkpoints(store)) == 2
    reads = _counting(store, monkeypatch)
    snap = _reader(store).refresh()
    assert (snap.source, snap.status, snap.ready) == ("object", "ok", True)
    assert snap.state.excluded_requests == {f"req_{i}" for i in range(250)}
    assert snap.state.revision == 1 + 250 + 2
    assert len(reads) <= EVERY + 5, len(reads)


def test_a_checkpoint_is_written_before_the_change_that_would_pass_the_bound(store):
    """Init plus EVERY changes puts the head EVERY links from its start; the
    next change writes a checkpoint first, then itself on top of it."""
    _excluded(store, 0, EVERY)
    assert _checkpoints(store) == []
    applied = apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_next"),
                           detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    [name] = _checkpoints(store)
    checkpoint = json.loads(store.get_audit(name))
    assert applied.record["base_audit_id"] == checkpoint["id"]
    assert checkpoint["new_value"][ov.FIELD_EXCLUDED] == sorted(f"req_{i}" for i in range(EVERY))
    assert "req_next" in applied.state.excluded_requests


def test_a_warm_reader_reads_only_the_records_after_its_head(store, monkeypatch):
    _excluded(store, 0, 3)
    reader = _reader(store)
    reader.refresh()
    _excluded(store, 3, 8)
    reads = _counting(store, monkeypatch)
    snap = reader.refresh()
    assert (snap.source, snap.status) == ("object", "ok")
    assert len([n for n in reads if n.endswith("-request.json")]) == 5, reads


def test_a_warm_reader_far_behind_ends_its_walk_at_the_newest_checkpoint(store, monkeypatch):
    reader = _reader(store)
    reader.refresh()
    _excluded(store, 0, 150)
    reads = _counting(store, monkeypatch)
    snap = reader.refresh()
    assert (snap.source, snap.status) == ("object", "ok")
    assert len(snap.state.excluded_requests) == 150
    assert len(reads) <= EVERY + 5, len(reads)


def test_a_removed_checkpoint_is_refused_cold_and_warm(store):
    """Mutation: walk past a missing record."""
    _excluded(store, 0, EVERY)
    warm = _reader(store)
    held = warm.refresh().state
    _excluded(store, EVERY, EVERY + 5)
    [name] = _checkpoints(store)
    (store.root / AUDIT_PREFIX / name).unlink()
    cold = _reader(store).refresh()
    assert (cold.source, cold.status, cold.ready) == ("baseline", "invalid", False)
    assert cold.error == "chain_record_missing"
    snap = warm.refresh()
    assert (snap.source, snap.status, snap.state) == ("last_known_good", "invalid", held)


def test_a_rewritten_checkpoint_is_refused(store):
    _excluded(store, 0, EVERY + 1)
    [name] = _checkpoints(store)
    _rewrite(store.root / AUDIT_PREFIX / name,
             new_value={**json.loads(store.get_audit(name))["new_value"],
                        ov.FIELD_EXCLUDED: ["req_forged"]})
    snap = _reader(store).refresh()
    assert (snap.status, snap.error) == (
        "invalid", "chain_hash_mismatch")


def test_a_checkpoint_that_changes_its_parents_state_is_refused_by_its_holder(store):
    """Consistent with its record, a checkpoint that adds an exclusion is a
    chain start to a cold reader, as a recover is; a reader holding its
    parent refuses it.

    Mutation: drop the check that a checkpoint carries its parent's state."""
    _excluded(store, 0, 2)
    warm = _reader(store)
    held = warm.refresh().state
    _forge_next(store, ov.ACTION_CHECKPOINT, excluded_requests=held.excluded_requests | {"req_x"})
    snap = warm.refresh()
    assert (snap.source, snap.status, snap.state) == ("last_known_good", "invalid", held)
    assert snap.error == "checkpoint_state_mismatch"


def test_a_head_more_than_the_bound_past_its_start_is_refused(store):
    """Forged honest-looking links, as the control identity could write
    them without apply_change's checkpoints: EVERY are adopted, EVERY + 1
    are not, cold or by a reader holding the start.

    Mutation: raise the bound by one; drop it."""
    warm = _reader(store)
    held = warm.refresh().state
    _forge_reset(store, EVERY)
    assert _reader(store).refresh().status == "ok"
    _forge_reset(store, 1)
    cold = _reader(store).refresh()
    assert (cold.source, cold.status, cold.ready) == ("baseline", "invalid", False)
    assert cold.error == "chain_beyond_checkpoint"
    snap = warm.refresh()
    assert (snap.source, snap.status, snap.state) == ("last_known_good", "invalid", held)
    with pytest.raises(InvalidState, match="^chain_beyond_checkpoint$"):
        apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)


def test_a_forged_transition_behind_a_checkpoint_is_refused_by_a_reader_holding_its_parent(
        store, caplog):
    """An `exclusion.add` that also sets the mode, then honest changes that
    carry it past a checkpoint: a reader that held the object before the
    forgery walks to it and refuses."""
    _excluded(store, 0, 3)
    warm = _reader(store)
    warm.refresh()
    head = parse_state(store.read_control().body)
    _forge_on(store, ACTION_EXCLUDE, ov.FIELD_EXCLUDED, None, "req_forged",
              overrides=_enforced(head))
    _forge_reset(store, 20)
    held = warm.refresh()
    assert (held.source, held.status, held.state) == ("last_known_good", "invalid", head)
    assert held.error == "record_state_mismatch"


def test_recover_keeps_everything_a_verifiable_chain_holds(store):
    """Mutation: recover from empty whatever the chain holds."""
    migration, _ = _retired_store(store)
    apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_kept"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_RESET, value="2026-09-20T00:00:00Z"),
                 detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    before = parse_state(store.read_control().body)
    _control(store).unlink()
    applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.effective() == before.effective()
    assert applied.state.retired_by == migration.audit_id
    assert applied.record["old_value"] == {"status": "absent", "kept": True}
    assert applied.record["new_value"] == ov.snapshot_of(applied.state)
    snap = _reader(store).refresh()
    assert snap.status == "ok" and snap.state.effective() == before.effective()


def test_recover_with_a_mode_sets_it_over_the_kept_state(store):
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_kept"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _control(store).write_bytes(b"{broken")
    applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode="enforce",
                           detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.excluded_requests == {"req_kept"}
    assert applied.state.value(KEY_MODE) == "enforce"


def test_recover_drops_state_only_when_no_chain_verifies_and_says_so(store, caplog):
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_lost"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    for name in store.list_audit():
        if name.endswith("-request.json"):
            _rewrite(store.root / AUDIT_PREFIX / name, principal="tampered")
    _control(store).write_bytes(b"{broken")
    with caplog.at_level(logging.WARNING):
        applied = apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.state.excluded_requests == frozenset()
    assert applied.record["old_value"] == {"status": "invalid", "kept": False}
    assert "recover found no verifiable audit chain" in caplog.text
    assert _reader(store).refresh().status == "ok"


def _rehead(store, **state_fields):
    """Change the object, and rewrite its head record to match, as the
    control identity could."""
    state = ov.replace(parse_state(store.read_control().body), audit_hash=None, **state_fields)
    path = _record_path(store, state.audit_id)
    record = json.loads(path.read_bytes())
    record["state_sha256"] = ov.state_digest(state)
    blob = ov._record_bytes(record)
    path.write_bytes(blob)
    _control(store).write_bytes(ov.replace(state, audit_hash=ov._sha256(blob)).to_bytes())


def test_a_migrated_object_names_its_own_migration(store):
    """Mutation: drop the check that a migrated object names its migration."""
    _legacy(store)
    _migrate(store)
    _rehead(store, retired_by=ov.new_audit_id())
    snap = _reader(store).refresh()
    assert snap.error == "migrated_object_unnamed"


def test_a_recovered_object_names_the_migration_its_record_names(store):
    """Mutation: drop the check that a recover's object and record agree."""
    _legacy(store)
    _migrate(store)
    raw = json.loads(_control(store).read_bytes())
    raw["version"] = 99
    _control(store).write_text(json.dumps(raw))
    apply_change(store, ADMIN, Change(ACTION_RECOVER), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _rehead(store, retired_by=ov.new_audit_id())
    snap = _reader(store).refresh()
    assert snap.error == "head_migration_mismatch"


def test_a_chain_broken_below_the_head_can_be_recovered(store):
    """Mutation: check only the head before a change."""
    _obj(store, **{KEY_MODE: "enforce"})
    middle = apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_1"),
                          detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_2"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _record_path(store, middle.audit_id).unlink()
    assert _reader(store).refresh().status == "invalid"
    audits = store.list_audit()
    with pytest.raises(InvalidState):
        apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_3"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert store.list_audit() == audits
    apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode="enforce",
                 detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    snap = _reader(store).refresh()
    assert (snap.status, snap.state.value(KEY_MODE)) == ("ok", "enforce")


def test_removing_an_exclusion_needs_a_request_id(store):
    """Mutation: drop the format check on exclusion.remove."""
    _obj(store, **{KEY_MODE: "enforce"})
    audits = store.list_audit()
    with pytest.raises(Refused, match="not a request id"):
        apply_change(store, ADMIN, Change(ACTION_UNEXCLUDE, value="req 1"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    with pytest.raises(Refused, match="allowlist"):
        apply_change(store, ADMIN, Change(ACTION_CLEAR, "server.nope"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert store.list_audit() == audits


def test_a_records_key_is_the_field_its_action_changes(store):
    """Mutation: record the caller's key for an action that has a field."""
    applied = apply_change(store, ADMIN, Change(ACTION_EXCLUDE, "anything", "req_1"),
                           detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.record["key"] == "excluded_requests"
    applied = apply_change(store, ADMIN, Change(ACTION_RESET, "anything",
                                                "2026-09-01T00:00:00Z"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert applied.record["key"] == "stats_reset"


ORG_ID = "00000000-0000-4000-8000-00000000c0de"


def test_org_ids_of_resolves_every_section_from_the_environment(monkeypatch):
    monkeypatch.setenv("FORGD_ORG_ID_PROD", ORG_ID.upper())
    monkeypatch.setenv("FORGD_ORG_ID_DEV", "dev-org")
    policy = make_policy(orgs=[{"id": "$FORGD_ORG_ID_PROD"}],
                         compliance={"orgs": [{"id": "$FORGD_ORG_ID_DEV"}]},
                         otel={"orgs": [{"id": "literal-org"}]})
    assert ov.org_ids_of(policy) == {ORG_ID, "dev-org", "literal-org"}


@pytest.mark.parametrize("value", [ORG_ID, ORG_ID.upper()])
def test_an_org_id_is_refused_as_an_exclusion_before_anything_is_read(store, value):
    """Mutation: drop the org id check."""
    def boom(*_a, **_k):
        raise AssertionError("read")

    store.read_control = boom
    with pytest.raises(Refused) as exc:
        apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value=value), detectors=DETECTORS, signing_key=OVERRIDES_KEY,
                     org_ids={ORG_ID})
    assert ORG_ID not in str(exc.value).lower()


def test_a_migration_leaves_an_org_id_behind(store):
    """Mutation: fold an org id in with the other legacy exclusions."""
    applied = apply_change(store, ADMIN, Change(ACTION_MIGRATE), detectors=DETECTORS, signing_key=OVERRIDES_KEY,
                           org_ids={ORG_ID}, migrate=(None, frozenset({ORG_ID, "req_1"})))
    assert applied.state.excluded_requests == {"req_1"}


def test_screened_identity():
    """Mutation: pass a matched or unscanned name through."""
    assert ov.screened_identity("dana", DETECTORS) == {"who": "dana"}
    matched = ov.screened_identity(FAKE_GITHUB_TOKEN, DETECTORS, "salt")
    assert matched["who"] == ov.screened_identity(FAKE_GITHUB_TOKEN, DETECTORS, "salt")["who"]
    assert matched["who"].startswith("who") and matched["who_matched"]
    assert FAKE_GITHUB_TOKEN not in json.dumps(matched)
    unsalted = ov.screened_identity(FAKE_GITHUB_TOKEN, DETECTORS)
    assert unsalted["who"] == ov.WITHHELD and unsalted["who_matched"] == matched["who_matched"]
    assert ov.screened_identity(FAKE_GITHUB_TOKEN, ()) == {"who": ov.WITHHELD,
                                                             "who_unscanned": True}


# -- exact transitions -----------------------------------------------------


def _forge_on(store, action, key, old, new, **state_fields):
    """A record on the head naming `action`, and an object that is what the
    action makes from the head with `state_fields` changed too, consistent
    with each other, as the control identity could write them."""
    head = parse_state(store.read_control().body)
    audit_id = ov.new_audit_id()
    record = {
        "version": 1, "kind": "request", "id": audit_id, "at": _at_of(audit_id),
        "principal": ADMIN, "action": action, "key": key, "old_value": old, "new_value": new,
        "base_revision": head.revision, "base_audit_id": head.audit_id,
        "base_hash": head.audit_hash, ov.FIELD_RETIRED: head.legacy_markers_retired,
        "retired_by": None,
        ov.FIELD_MIN_READER: (head.min_reader_version or ov._current_version()
                              if (action, key) == (ACTION_SET, KEY_MODE)
                              else None if action in (ACTION_CLEAR, ACTION_CLEAR_ALL)
                              else head.min_reader_version),
    }
    state = ov.replace(ov._transition(head, record), **state_fields)
    record["state_sha256"] = ov.state_digest(state)
    blob = ov._record_bytes(record)
    store.put_audit(audit_name(audit_id, "request"), blob)
    _control(store).write_bytes(ov.replace(state, audit_hash=ov._sha256(blob)).to_bytes())
    return state


def _enforced(state):
    return {KEY_MODE: OverrideEntry("enforce", state.updated_at, ADMIN, state.audit_id)}


def test_an_exclusion_that_also_flips_the_mode_is_refused_cold_and_warm(store, caplog):
    """The record names `exclusion.add`; the object also sets server.mode.
    The head's action is in the object, so only replaying it finds the
    extra change.

    Mutation: skip the exact comparison at the head."""
    warm = _reader(store)
    warm.refresh()
    head = parse_state(store.read_control().body)
    forged = _forge_on(store, ACTION_EXCLUDE, ov.FIELD_EXCLUDED, None, "req_forged",
                       overrides=_enforced(head))
    assert forged.value(KEY_MODE) == "enforce" and "req_forged" in forged.excluded_requests
    with caplog.at_level(logging.INFO):
        cold = _reader(store).refresh()
        held = warm.refresh()
    assert (cold.source, cold.status, cold.ready) == ("baseline", "invalid", False)
    assert cold.error == "record_state_mismatch"
    assert (held.source, held.status, held.state.value(KEY_MODE)) == (
        "last_known_good", "invalid", None)
    assert warm.mode("observe") == "observe"


def test_a_forged_middle_link_is_refused_though_a_later_change_hides_it(store, caplog):
    """A middle record names `exclusion.add` and also rewrites who set the
    mode; the next record clears the mode, so the head is the object an
    honest chain would end with. Only checking the middle link finds it.

    Mutation: skip the exact comparison in a middle link."""
    _obj(store, **{KEY_MODE: "enforce"})
    warm = _reader(store)
    warm.refresh()
    head = parse_state(store.read_control().body)
    entry = head.overrides[KEY_MODE]
    _forge_on(store, ACTION_EXCLUDE, ov.FIELD_EXCLUDED, None, "req_1",
              overrides={KEY_MODE: OverrideEntry("enforce", entry.set_at, {"name": "mallory"},
                                                 entry.audit_id)})
    _forge_on(store, ACTION_CLEAR, KEY_MODE, "enforce", None)
    with caplog.at_level(logging.INFO):
        cold = _reader(store).refresh()
        _refused(warm.refresh(), caplog)
    assert (cold.source, cold.status) == ("baseline", "invalid")
    assert cold.error == "record_state_mismatch"


def test_an_honest_forged_chain_is_adopted(store):
    """The helper above, with nothing extra, writes what apply_change would."""
    warm = _reader(store)
    warm.refresh()
    _forge_on(store, ACTION_EXCLUDE, ov.FIELD_EXCLUDED, None, "req_1")
    _forge_on(store, ACTION_SET, KEY_MODE, None, "enforce")
    for snap in (_reader(store).refresh(), warm.refresh()):
        assert (snap.source, snap.status) == ("object", "ok")
        assert snap.state.value(KEY_MODE) == "enforce" and snap.state.excluded_requests == {"req_1"}


@pytest.mark.parametrize("field,value", [
    ("old_value", "enforce"), ("key", "server.other"), ("new_value", "req_other"),
])
def test_a_record_whose_values_are_not_its_change_is_refused(store, field, value):
    """Mutation: drop the check of the record's key and values."""
    _forge_on(store, ACTION_EXCLUDE, ov.FIELD_EXCLUDED, None, "req_1")
    record_path = _record_path(store, parse_state(store.read_control().body).audit_id)
    record = json.loads(record_path.read_bytes())
    record[field] = value
    blob = ov._record_bytes(record)
    record_path.write_bytes(blob)
    state = parse_state(store.read_control().body)
    _control(store).write_bytes(ov.replace(state, audit_hash=ov._sha256(blob)).to_bytes())
    snap = _reader(store).refresh()
    assert (snap.source, snap.status) == ("baseline", "invalid")


def test_a_migration_that_drops_an_exclusion_is_refused(store):
    apply_change(store, ADMIN, Change(ACTION_EXCLUDE, value="req_kept"), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    head = parse_state(store.read_control().body)
    audit_id = ov.new_audit_id()
    record = {
        "version": 1, "kind": "request", "id": audit_id, "at": _at_of(audit_id),
        "principal": ADMIN, "action": ACTION_MIGRATE, "key": None,
        "old_value": {ov.FIELD_RESET: None, ov.FIELD_EXCLUDED: 1, ov.FIELD_RETIRED: False},
        "new_value": {ov.FIELD_RESET: None, ov.FIELD_EXCLUDED: ["req_legacy"],
                      ov.FIELD_RETIRED: True},
        "base_revision": head.revision, "base_audit_id": head.audit_id,
        "base_hash": head.audit_hash, ov.FIELD_RETIRED: True, "retired_by": None,
    }
    with pytest.raises(InvalidState, match="^migration_drops_state$"):
        ov._transition(head, record)


def test_every_action_replays_exactly_cold_and_from_a_last_known_good(store):
    """Each change apply_change writes is adopted by a reader holding the
    one before it and by a cold one, across a recover and a migration."""
    warm = _reader(store)
    warm.refresh()

    def step(change, **kw):
        apply_change(store, ADMIN if change.action != ACTION_MIGRATE else ov.cli_actor(), change,
                     detectors=DETECTORS, signing_key=OVERRIDES_KEY, **kw)
        for snap in (warm.refresh(), _reader(store).refresh()):
            assert (snap.source, snap.status) == ("object", "ok"), (change.action, snap.error)
            assert snap.state == parse_state(store.read_control().body)

    for change in (Change(ACTION_SET, KEY_MODE, "enforce"), Change(ACTION_EXCLUDE, value="req_1"),
                   Change(ACTION_EXCLUDE, value="req_2"), Change(ACTION_UNEXCLUDE, value="req_1"),
                   Change(ACTION_RESET, value="2026-09-01T00:00:00Z"), Change(ov.ACTION_RESET_CLEAR),
                   Change(ov.ACTION_EXCLUDE_CLEAR), Change(ACTION_SET, KEY_MODE, "observe"),
                   Change(ACTION_CLEAR, KEY_MODE), Change(ACTION_SET, KEY_MODE, "enforce"),
                   Change(ACTION_CLEAR_ALL)):
        step(change)
    _legacy(store)
    step(Change(ACTION_MIGRATE), migrate=(store.get_reset_marker(), frozenset(store.get_excluded())))
    step(Change(ACTION_SET, KEY_MODE, "enforce"))
    # Invalid, and still naming the migration, so the recover keeps it.
    _control(store).write_text(_control(store).read_text().replace('"version": 1', '"version": 99'))
    warm.refresh()
    apply_change(store, ADMIN, Change(ACTION_RECOVER), recover_mode="enforce", detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    for snap in (warm.refresh(), _reader(store).refresh()):
        assert (snap.source, snap.status) == ("object", "ok"), snap.error
    step(Change(ACTION_EXCLUDE, value="req_3"))


# -- error codes -----------------------------------------------------------


def test_every_invalid_state_is_a_fixed_code():
    """Mutation: raise InvalidState with a message built from the object."""
    import ast
    import re

    code = re.compile(r"[a-z][a-z0-9_]*")
    tree = ast.parse(inspect.getsource(ov))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id in ("InvalidState", "_timestamp")]
    assert len(calls) > 50
    for call in calls:
        arg = call.args[0] if call.func.id == "InvalidState" else call.args[1]
        if isinstance(arg, ast.Constant):
            assert isinstance(arg.value, str) and code.fullmatch(arg.value), ast.unparse(call)
        else:
            assert ast.unparse(arg) in ("code", "_INVALID_VALUE[key]"), ast.unparse(call)
    assert all(code.fullmatch(c) for c in ov._INVALID_VALUE.values())
    assert set(ov._INVALID_VALUE) == set(ov.ALLOWLIST)


@pytest.mark.parametrize("field, secret, code", [
    ("version", FAKE_AWS_KEY, "unknown_version"),
    ("mode", FAKE_GITHUB_TOKEN, "invalid_mode"),
])
def test_a_secret_in_the_object_reaches_no_log_field_page_or_cli_output(
        store, tmp_path, caplog, capsys, monkeypatch, field, secret, code):
    """Mutation: put the stored value in the InvalidState message."""
    from conftest import OVERRIDES_KEY_TEXT, OVERRIDES_PUBLIC_TEXT

    from forgd_verdict.cli import main

    monkeypatch.setenv("FORGD_OVERRIDES_SIGNING_KEY", OVERRIDES_KEY_TEXT)
    monkeypatch.setenv("FORGD_OVERRIDES_VERIFY_KEY", OVERRIDES_PUBLIC_TEXT)
    from forgd_verdict.dashboard.controls import banners

    _obj(store, **{KEY_MODE: "enforce"})
    raw = json.loads(_control(store).read_bytes())
    if field == "version":
        raw["version"] = secret
    else:
        raw["overrides"][KEY_MODE]["value"] = secret
    _control(store).write_text(json.dumps(raw))
    assert secret in _control(store).read_text()
    with caplog.at_level(logging.DEBUG):
        warm = _reader(store)
        snap = warm.refresh()
        exposed = [json.dumps(snap.fields(), default=str), json.dumps(ov.readiness(warm)),
                   banners(snap, "observe")]
        with pytest.raises(InvalidState) as raised:
            parse_state(_control(store).read_bytes())
        exposed.append(str(raised.value))

        policy = tmp_path / "admins.json"
        policy.write_text(json.dumps({"dashboard": {"admins": {"groups": [{"group": "ops"}]}}}))
        root = str(store.root)
        assert main(["--policy", str(policy), "overrides", "--store", root, "show"]) == 0
        shown = capsys.readouterr()
        assert main(["--policy", str(policy), "overrides", "--store", root,
                     "set", KEY_MODE, "observe"]) == 1
        changed = capsys.readouterr()
        exposed += [shown.out, shown.err, changed.out, changed.err]
    exposed += [r.getMessage() + json.dumps(getattr(r, "fields", {}), default=str)
                + (r.exc_text or "") for r in caplog.records]
    for text in exposed:
        assert secret not in text
    assert (snap.status, snap.error) == ("invalid", code)
    assert str(raised.value) == raised.value.code == code
    assert json.loads(shown.out)["runtime_overrides"]["error"] == code
    assert f"({code})" in changed.err


def test_an_invalid_stored_mode_is_not_in_the_error_or_its_chain(store):
    """A `log.exception`, or the stderr fallback when a handler's stream is
    closed, prints the whole exception chain."""
    import traceback

    with pytest.raises(ValueError) as bad:
        ov._mode_value(FAKE_GITHUB_TOKEN)
    assert FAKE_GITHUB_TOKEN not in str(bad.value)

    _obj(store, **{KEY_MODE: "enforce"})
    raw = json.loads(_control(store).read_bytes())
    raw["overrides"][KEY_MODE]["value"] = FAKE_GITHUB_TOKEN
    with pytest.raises(InvalidState) as raised:
        parse_state(json.dumps(raw).encode())
    err = raised.value
    assert err.__cause__ is None and err.__suppress_context__
    assert FAKE_GITHUB_TOKEN not in "".join(traceback.format_exception(err))


def test_a_handler_on_a_closed_stream_does_not_print_the_stored_value(store, capsys):
    """The order-dependent failure, in one test: a handler whose stream has
    closed fails inside `except InvalidState`, and logging prints the
    failure with the exception it was raised during."""
    import io

    _obj(store, **{KEY_MODE: "enforce"})
    raw = json.loads(_control(store).read_bytes())
    raw["overrides"][KEY_MODE]["value"] = FAKE_GITHUB_TOKEN
    stream = io.StringIO()
    stream.close()
    lg = logging.getLogger("forgd_verdict.test_closed_stream")
    lg.addHandler(logging.StreamHandler(stream))
    lg.propagate = False
    try:
        try:
            parse_state(json.dumps(raw).encode())
        except InvalidState:
            lg.error("runtime overrides object is invalid")
    finally:
        lg.handlers.clear()
    err = capsys.readouterr().err
    assert "Logging error" in err
    assert FAKE_GITHUB_TOKEN not in err


@pytest.mark.parametrize("fields, code", [
    ({"version": 2}, "unknown_version"),
    ({"revision": -1}, "revision_malformed"),
    ({"audit_id": "x"}, "audit_id_malformed"),
    ({"audit_hash": "x"}, "audit_hash_malformed"),
    ({"updated_at": "x"}, "updated_at_malformed"),
    ({"overrides": []}, "overrides_not_mapping"),
    ({"overrides__server.mode": "enforce"}, "override_entry_malformed"),
    ({"overrides__server.mode__value": "x"}, "invalid_mode"),
    ({"overrides__server.mode__set_by": "x"}, "override_set_by_malformed"),
    ({"overrides__server.mode__audit_id": 1}, "override_audit_id_malformed"),
    ({"overrides__server.mode__set_at": "x"}, "override_set_at_malformed"),
    ({"stats_reset": "2026-02-30T00:00:00Z"}, "stats_reset_malformed"),
    ({"excluded_requests": ["x y"]}, "excluded_requests_malformed"),
    ({ov.FIELD_RETIRED: "yes"}, "retired_malformed"),
    ({ov.FIELD_RETIRED: True}, "retired_by_malformed"),
])
def test_each_malformed_field_has_its_own_code(store, fields, code):
    _obj(store, **{KEY_MODE: "enforce"})
    raw = json.loads(_control(store).read_bytes())
    for path, value in fields.items():
        *parents, leaf = path.split("__")
        node = raw
        for p in parents:
            node = node[p]
        node[leaf] = value
    with pytest.raises(InvalidState) as raised:
        parse_state(json.dumps(raw).encode())
    assert raised.value.code == code


def test_the_codes_are_distinct_for_distinct_failures():
    import ast

    tree = ast.parse(inspect.getsource(ov.parse_state))
    args = [n.args[0] if n.func.id == "InvalidState" else n.args[1] for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id in ("InvalidState", "_timestamp")]
    literals = [a.value for a in args if isinstance(a, ast.Constant)]
    assert len(literals) == len(set(literals))
    assert {"not_json", "not_object"} <= set(literals)
    for blob, code in ((b"{", "not_json"), (b"[]", "not_object")):
        with pytest.raises(InvalidState, match=f"^{code}$"):
            parse_state(blob)


def _stamp_id(moment):
    return f"{moment:%Y%m%dT%H%M%SZ}-{'cd' * 6}"


@pytest.mark.parametrize("ahead, ok", [(290, True), (310, False)])
def test_an_audit_id_too_far_ahead_of_now_is_refused(store, ahead, ok):
    """`at` is within the skew of the id, so only the id's distance from
    now decides. Mutation: drop the id-versus-now check."""
    minted = datetime.now(UTC) + timedelta(seconds=ahead)
    _forge_next(store, ov.ACTION_CHECKPOINT, audit_id=_stamp_id(minted),
                at=f"{minted - timedelta(seconds=250):%Y-%m-%dT%H:%M:%SZ}")
    snap = _reader(store).refresh()
    assert (snap.status, snap.error) == (("ok", None) if ok else ("invalid", "chain_record_clock"))


@pytest.mark.parametrize("apart, ok", [(300, True), (301, False), (-301, False)])
def test_an_audit_id_away_from_its_at_is_refused(store, apart, ok):
    """The id is in the past, so only its distance from `at` decides.
    Mutation: drop the id-versus-at check."""
    minted = datetime.now(UTC) - timedelta(minutes=20)
    _forge_next(store, ov.ACTION_CHECKPOINT, audit_id=_stamp_id(minted),
                at=f"{minted - timedelta(seconds=apart):%Y-%m-%dT%H:%M:%SZ}")
    snap = _reader(store).refresh()
    assert (snap.status, snap.error) == (("ok", None) if ok else ("invalid", "chain_record_clock"))


def test_a_base_with_a_bad_clock_is_refused_under_a_good_head(store):
    """Every record walked is checked, not only the head. Mutation: check
    only the head."""
    minted = datetime.now(UTC) - timedelta(minutes=30)
    _forge_next(store, ov.ACTION_CHECKPOINT, audit_id=_stamp_id(minted),
                at=f"{minted - timedelta(minutes=10):%Y-%m-%dT%H:%M:%SZ}")
    _forge_reset(store, 1)
    snap = _reader(store).refresh()
    assert (snap.status, snap.error) == ("invalid", "chain_record_clock")


def test_a_history_record_with_a_bad_clock_is_tampered(store):
    minted = datetime.now(UTC) + timedelta(hours=1)
    _forge_next(store, ov.ACTION_CHECKPOINT, audit_id=_stamp_id(minted), at=_at_of(_stamp_id(minted)))
    state = parse_state(store.read_control().body)
    assert history(store, state).tampered == {state.audit_id}


@pytest.mark.parametrize("result", ["applied", "error", "unknown"])
@pytest.mark.parametrize("when", ["future", "mismatched"])
def test_an_outcome_with_a_bad_clock_changes_nothing(store, result, when):
    """No reader parses an outcome record, so a future-dated one, or one
    whose `at` is far from its request's id, leaves the reader, the history
    and the next change as they were."""
    applied = apply_change(store, ADMIN, Change(ACTION_SET, key=KEY_MODE, value="enforce"),
                           detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    before = (_reader(store).refresh().status, history(store, applied.state))
    at = datetime.now(UTC) + timedelta(days=1) if when == "future" else \
        datetime.now(UTC) - timedelta(days=30)
    path = store.root / AUDIT_PREFIX / audit_name(applied.state.audit_id, "outcome")
    path.write_text(json.dumps({"version": 1, "kind": "outcome", "request_id": applied.state.audit_id,
                                "result": result, "at": f"{at:%Y-%m-%dT%H:%M:%SZ}"}))
    snap = _reader(store).refresh()
    assert (snap.status, snap.state.value(KEY_MODE)) == ("ok", "enforce")
    assert (snap.status, history(store, applied.state)) == before
    later = apply_change(store, ADMIN, Change(ACTION_SET, key=KEY_MODE, value="observe"),
                         detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    assert later.state.value(KEY_MODE) == "observe"


def test_a_cold_reader_applies_no_writer_written_legacy_marker(bare):
    """With overrides on and no object adopted, the writer-writable markers
    exclude nothing and move no floor. Mutation: fall back to the legacy
    markers whenever the markers are not retired."""
    bare.set_excluded(["req-hide-me-0001"])
    bare.set_reset_marker("2099-01-01T00:00:00Z")
    reader = _reader(bare)
    assert reader.refresh().state is None
    overlaid = OverlaidStore(bare, reader)
    assert overlaid.get_excluded() == set()
    assert overlaid.describe()["reset_at"] is None
    assert overlaid.get_legacy_excluded() == {"req-hide-me-0001"}
    assert overlaid.describe()["legacy_reset_at"] == "2099-01-01T00:00:00Z"
    assert ov.effective_excluded({"x"}, None) == {"x"}, "overrides off reads the markers"
    assert ov.effective_reset("2026-01-01T00:00:00Z", None) == "2026-01-01T00:00:00Z"


def test_a_reader_applies_legacy_markers_once_it_adopts_an_unretired_object(bare):
    bare.set_excluded(["req_legacy"])
    reader = _reader(bare)
    overlaid = OverlaidStore(bare, reader)
    assert overlaid.get_excluded() == set()
    _init(bare)
    reader.refresh()
    assert overlaid.get_excluded() == {"req_legacy"}
