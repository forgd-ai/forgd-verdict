"""The signed freshness anchor: every lockout verification record names the
overrides head, and no reader adopts an object behind the head the newest
fresh record names.

The attack is a storage administrator without the signing key restoring an
older version of the object, whose records are genuinely signed. Each test
names the mutation that makes it fail.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import pytest
from conftest import DETECTORS, OVERRIDES_KEY, OVERRIDES_PUBLIC

from forgd_verdict import lockout
from forgd_verdict import overrides as ov
from forgd_verdict import overrides_signing as sig
from forgd_verdict.dashboard.controls import banners
from forgd_verdict.lockout import VERIFIED_FRESH_S, LockoutReports
from forgd_verdict.lockout_evidence import verifier
from forgd_verdict.models import CONTROL_STATE
from forgd_verdict.overrides import (
    ACTION_EXCLUDE,
    ACTION_INIT,
    ACTION_MIGRATE,
    ACTION_RECOVER,
    ACTION_SET,
    KEY_MODE,
    Change,
    InvalidState,
    RuntimeOverrides,
    anchor_of,
    apply_change,
    audit_name,
    parse_state,
    readiness,
)
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import AUDIT_PREFIX, STATE_PREFIX

ADMIN = {"issuer": "https://idp.example/", "subject": "sub-1", "name": "a.person",
         "via_group": "ops", "verified": True}
KEYS = (OVERRIDES_PUBLIC,)
WRITER = "arn:aws:iam::111111111111:role/forgd-verdict-writer"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Provable(LocalFileStore):
    """A local store whose lockout counts as provable, so readers read the
    verification records as they do on a cloud store."""

    lockout_provable = True


@pytest.fixture
def store(tmp_path):
    store = Provable(tmp_path / "store", instance="t")
    _change(store, Change(ACTION_INIT))
    return store


def _change(store, change, **kwargs):
    return apply_change(store, ADMIN, change, detectors=DETECTORS, signing_key=OVERRIDES_KEY,
                        verify_keys=KEYS, **kwargs)


def _reader(store):
    return RuntimeOverrides(store, "test", baseline={KEY_MODE: "observe"}, clock=Clock(),
                            verify_keys=KEYS,
                            fleet=LockoutReports(store, ("verdict",), verify_keys=KEYS))


def _control(store):
    return store.root / STATE_PREFIX / CONTROL_STATE


def _head(store):
    return parse_state(store.read_control().body)


def _anchor(store, trusted=None, at=None):
    """A verification record as the dashboard writes it, naming `trusted`
    (the store's head by default)."""
    head = anchor_of(_head(store)) if trusted is None else trusted
    return verifier.verify(store, (WRITER,), evaluate=lambda s, ids, **_: {WRITER: None},
                           signing_key=OVERRIDES_KEY, trusted=lambda: head, verify_keys=KEYS,
                           now=at)


def _unanchor(store):
    for path in store.root.rglob(f"{lockout.VERIFY_PREFIX}*.json"):
        path.unlink()


def _rolled_back(store):
    """rev 2 excludes a request; rev 3 sets enforce and is anchored. The
    object is then restored to rev 2, pre-enforce, as a storage version
    restore does. Returns (rev 2 bytes, rev 3 state)."""
    _change(store, Change(ACTION_EXCLUDE, value="req_1"))
    old = _control(store).read_bytes()
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    newest = _head(store)
    _anchor(store)
    _control(store).write_bytes(old)
    return old, newest


# -- adopted ---------------------------------------------------------------


def test_a_cold_reader_adopts_the_object_the_fresh_anchor_names(store):
    """Mutation: drop the same-revision clause from check_anchor."""
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _anchor(store)
    snap = _reader(store).refresh()
    assert (snap.status, snap.source, snap.ready) == ("ok", "object", True)
    assert snap.state.value(KEY_MODE) == "enforce"


def test_a_cold_reader_refuses_an_object_after_the_anchor(store):
    """A change the anchor does not name yet: a cold reader is not ready,
    and a reader that adopted the anchored head adopts it. Mutation: let a
    cold reader through on a later revision in check_anchor."""
    _anchor(store)
    warm = _reader(store)
    assert warm.refresh().status == "ok"
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    snap = _reader(store).refresh()
    assert (snap.status, snap.error, snap.ready) == ("invalid", "object_not_anchored", False)
    assert snap.state is None
    snap = warm.refresh()
    assert (snap.status, snap.ready, snap.state.value(KEY_MODE)) == ("ok", True, "enforce")


def test_a_same_revision_head_with_another_id_is_behind_the_anchor(store):
    """Mutation: compare revisions only."""
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    head = anchor_of(_head(store))
    _anchor(store, trusted={**head, "audit_hash": "0" * 64})
    snap = _reader(store).refresh()
    assert (snap.status, snap.error, snap.ready) == ("invalid", "object_before_anchor", False)


# -- refused ---------------------------------------------------------------


def test_a_restored_older_object_is_refused_by_a_cold_reader(store, caplog):
    """Mutation: skip check_anchor in _read_object."""
    _rolled_back(store)
    reader = _reader(store)
    with caplog.at_level(logging.ERROR, logger="forgd_verdict.overrides"):
        snap = reader.refresh()
    assert (snap.status, snap.source, snap.ready) == ("invalid", "baseline", False)
    assert snap.error == ov.ERROR_BEFORE_ANCHOR and snap.in_error
    assert readiness(reader) == (503, {
        "status": "not_ready", "runtime_overrides": "invalid",
        "reason": "runtime overrides are not the head the signed head anchor names"})
    assert any("Restoring an older version of the object is refused" in r.getMessage()
               and r.levelno == logging.ERROR for r in caplog.records)
    assert "not the head the signed lockout verification names" in banners(
        snap, "observe")


def test_a_restored_older_object_is_refused_by_a_warm_reader(store):
    """A reader that adopted rev 1 would verify rev 1 -> rev 2 as a valid
    transition; only the anchor refuses it. Mutation: check the anchor for
    cold readers only."""
    _anchor(store)
    warm = _reader(store)
    assert warm.refresh().state.revision == 1
    _rolled_back(store)
    snap = warm.refresh()
    assert (snap.status, snap.source, snap.error) == ("invalid", "last_known_good",
                                                      "object_before_anchor")
    assert snap.state.revision == 1


def test_a_reader_that_holds_the_newest_head_refuses_the_restore(store):
    """The ordering checks a warm reader already had."""
    _change(store, Change(ACTION_EXCLUDE, value="req_1"))
    old = _control(store).read_bytes()
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _anchor(store)
    warm = _reader(store)
    assert warm.refresh().state.value(KEY_MODE) == "enforce"
    _control(store).write_bytes(old)
    snap = warm.refresh()
    assert (snap.source, snap.status) == ("last_known_good", "invalid")
    assert warm.mode("observe") == "enforce"


def test_with_the_anchors_deleted_a_cold_reader_is_not_ready(store):
    """Mutation: let lockout_status answer ok, and not read from a record,
    when there is no record."""
    _rolled_back(store)
    _unanchor(store)
    snap = _reader(store).refresh()
    assert (snap.ready, snap.state, snap.error) == (False, None, lockout.LOCKOUT_MISSING)
    assert snap.writers == {"*": lockout.PROBLEM_UNVERIFIED} and snap.in_error


def test_with_only_stale_anchors_a_cold_reader_is_not_ready(store):
    """The stale record names the old head exactly, so only its age refuses
    it. Mutation: drop the freshness check in _checked_verification."""
    _change(store, Change(ACTION_EXCLUDE, value="req_1"))
    old = _control(store).read_bytes()
    _anchor(store, at=datetime.now(UTC) - timedelta(seconds=VERIFIED_FRESH_S + 60))
    stale = sorted(store.root.rglob(f"{lockout.VERIFY_PREFIX}*.json"))
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _anchor(store)
    for path in store.root.rglob(f"{lockout.VERIFY_PREFIX}*.json"):
        if path not in stale:
            path.unlink()
    _control(store).write_bytes(old)
    snap = _reader(store).refresh()
    assert (snap.ready, snap.state, snap.error) == (False, None, lockout.LOCKOUT_MISSING)
    assert snap.writers == {"*": lockout.PROBLEM_VERIFY_STALE}


def _headless(store):
    """A fresh signed verification record with no head, as a build before
    the anchor wrote."""
    record = _anchor(store)
    path = next(store.root.rglob(f"{lockout.VERIFY_PREFIX}{record['id']}.json"))
    body = {k: v for k, v in record.items() if k not in ("head", sig.SIGNATURE_FIELD)}
    path.write_text(json.dumps(sig.sign(body, OVERRIDES_KEY), sort_keys=True) + "\n")


def test_a_cold_reader_needs_the_fresh_record_to_name_a_head(store):
    """Mutation: treat a missing head as no constraint for a cold reader."""
    _headless(store)
    snap = _reader(store).refresh()
    assert (snap.status, snap.error, snap.ready) == ("invalid", "head_anchor_missing", False)


def test_a_warm_reader_adopts_under_a_record_with_no_head(store):
    _anchor(store)
    warm = _reader(store)
    assert warm.refresh().status == "ok"
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _headless(store)
    snap = warm.refresh()
    assert (snap.status, snap.state.value(KEY_MODE)) == ("ok", "enforce")


def test_a_malformed_head_makes_the_record_untrusted(store):
    """Mutation: skip head_ok in _well_formed."""
    record = _anchor(store)
    path = next(store.root.rglob(f"{lockout.VERIFY_PREFIX}{record['id']}.json"))
    body = {k: v for k, v in record.items() if k != sig.SIGNATURE_FIELD}
    body["head"] = {"revision": -1, "audit_id": None, "audit_hash": None}
    path.write_text(json.dumps(sig.sign(body, OVERRIDES_KEY), sort_keys=True) + "\n")
    snap = _reader(store).refresh()
    assert snap.writers == {"*": lockout.PROBLEM_VERIFY_UNREADABLE} and not snap.ready


# -- what the dashboard names ------------------------------------------------


def test_the_verification_names_the_dashboards_head_and_never_goes_back(store):
    """Mutation: let a head the dashboard holds replace a later one the
    newest record names."""
    first = anchor_of(_head(store))
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    newest = anchor_of(_head(store))
    assert _anchor(store, trusted=newest)["head"] == newest
    assert _anchor(store, trusted=first)["head"] == newest
    assert verifier.verify(store, (WRITER,), evaluate=lambda s, ids, **_: {WRITER: None},
                           signing_key=OVERRIDES_KEY, trusted=lambda: None,
                           verify_keys=KEYS)["head"] == newest


def test_a_cold_dashboard_carries_the_anchor_over_a_restored_object(store):
    """The dashboard holds nothing and the store holds rev 2; the record
    still names rev 3."""
    _, newest = _rolled_back(store)
    record = verifier.verify(store, (WRITER,), evaluate=lambda s, ids, **_: {WRITER: None},
                             signing_key=OVERRIDES_KEY, trusted=lambda: None,
                             verify_keys=KEYS)
    assert record["head"] == anchor_of(newest)
    assert _reader(store).refresh().error == "object_before_anchor"


def test_an_unsigned_record_is_not_carried(store):
    """A storage administrator's own record is neither a head a recover
    keeps nor a fresh anchor a cold dashboard carries. Mutation: drop the
    signature check in anchored_head."""
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    newest = anchor_of(_head(store))
    _anchor(store)
    lockout.write_verification(store, {WRITER: None}, "s3")
    assert lockout.anchored_head(store, KEYS) == newest
    assert _cold_dashboard(store) is None


def _cold_dashboard(store):
    """The verification a dashboard that has just started, holding no
    verified state, writes."""
    return verifier.verify(store, (WRITER,), evaluate=lambda s, ids, **_: {WRITER: None},
                           signing_key=OVERRIDES_KEY, trusted=lambda: None, verify_keys=KEYS)


def _records(store):
    return sorted(store.root.rglob(f"{lockout.VERIFY_PREFIX}*.json"))


def test_a_cold_dashboard_does_not_refresh_a_stale_surviving_anchor(store, caplog):
    """The newer records are deleted and the object restored to the head
    the surviving, stale record names. A dashboard that restarts then
    writes nothing, and a cold reader stays not ready. Mutation: carry
    the head of a record that is not fresh."""
    _change(store, Change(ACTION_EXCLUDE, value="req_1"))
    old = _control(store).read_bytes()
    _anchor(store, at=datetime.now(UTC) - timedelta(seconds=VERIFIED_FRESH_S + 60))
    stale = _records(store)
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _anchor(store)
    for path in _records(store):
        if path not in stale:
            path.unlink()
    _control(store).write_bytes(old)
    with caplog.at_level(logging.ERROR, logger="forgd_verdict.lockout"):
        assert _cold_dashboard(store) is None
    assert _records(store) == stale
    assert any("verification not written" in r.getMessage() for r in caplog.records)
    snap = _reader(store).refresh()
    assert (snap.ready, snap.state, snap.writers) == (False, None,
                                                     {"*": lockout.PROBLEM_VERIFY_STALE})


def test_a_cold_dashboard_does_not_anchor_an_object_after_every_record_is_deleted(store):
    """Every verification and request record deleted, the object kept.
    Mutation: let `uninitialized` ignore a present object."""
    _rolled_back(store)
    _unanchor(store)
    for path in (store.root / AUDIT_PREFIX).rglob("*-request.json"):
        path.unlink()
    assert _cold_dashboard(store) is None
    assert _records(store) == []
    snap = _reader(store).refresh()
    assert (snap.ready, snap.state, snap.writers) == (False, None,
                                                     {"*": lockout.PROBLEM_UNVERIFIED})


def test_request_records_mean_the_store_was_initialized(store):
    """The object and every verification record deleted. Mutation: let
    `uninitialized` ignore request records."""
    _rolled_back(store)
    _unanchor(store)
    _control(store).unlink()
    assert _cold_dashboard(store) is None


def test_a_signed_head_means_the_store_was_initialized(store):
    """Everything but a signed record naming a head is deleted. Mutation:
    let `uninitialized` ignore signed heads."""
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _anchor(store, at=datetime.now(UTC) - timedelta(seconds=VERIFIED_FRESH_S + 60))
    _control(store).unlink()
    for path in (store.root / AUDIT_PREFIX).rglob("*-request.json"):
        path.unlink()
    assert _cold_dashboard(store) is None


def test_a_cold_dashboard_carries_a_fresh_anchor(store):
    """A fresh signed head is carried, so a record naming a head
    verifying no identity, as a recover from the CLI writes, is taken
    up by the dashboard's next verification."""
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    newest = anchor_of(_head(store))
    verifier.verify(store, (), evaluate=lambda s, ids, **_: {}, signing_key=OVERRIDES_KEY,
                    trusted=lambda: newest, verify_keys=KEYS)
    assert _reader(store).refresh().writers == {"*": lockout.PROBLEM_VERIFY_EMPTY}
    assert _cold_dashboard(store)["head"] == newest
    assert _reader(store).refresh().status == "ok"


def test_recover_over_a_valid_object_once_the_anchor_lapsed(store):
    """After a dashboard outage past the freshness limit nothing adopts
    the valid object, and the dashboard names no head; recover writes it
    again past the stale anchor, and a record naming it makes readers
    adopt it. Mutation: refuse a recover over a valid object always."""
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _anchor(store, at=datetime.now(UTC) - timedelta(seconds=VERIFIED_FRESH_S + 60))
    assert not _reader(store).refresh().ready
    assert _cold_dashboard(store) is None
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.value(KEY_MODE) == "enforce"
    _anchor(store, trusted=anchor_of(applied.state))
    snap = _reader(store).refresh()
    assert (snap.status, snap.state.revision) == ("ok", applied.state.revision)


def test_recover_over_a_valid_object_is_refused_while_the_anchor_is_fresh(store):
    """Mutation: treat the anchor as lapsed always."""
    _anchor(store)
    with pytest.raises(ov.Refused, match="nothing to recover"):
        _change(store, Change(ACTION_RECOVER))


def test_recover_over_a_valid_restored_object_keeps_the_stale_anchors_state(store):
    """Newer records deleted and the object restored to rev 2: recover
    keeps rev 3's state, which the surviving signed record names."""
    _change(store, Change(ACTION_EXCLUDE, value="req_1"))
    old = _control(store).read_bytes()
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _anchor(store, at=datetime.now(UTC) - timedelta(seconds=VERIFIED_FRESH_S + 60))
    _control(store).write_bytes(old)
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.value(KEY_MODE) == "enforce"


def test_the_cli_names_the_head_it_initializes_and_recovers(tmp_path, monkeypatch,
                                                           control_identity, signing_env):
    """Mutation: skip _anchor in the CLI's _change."""
    from conftest import OVERRIDES_PUBLIC_TEXT

    from forgd_verdict.cli import main

    monkeypatch.setattr(lockout, "provable", lambda store: True)
    policy = tmp_path / "admins.json"
    policy.write_text(json.dumps({"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
                                  "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}))
    root = tmp_path / "s"
    local = LocalFileStore(root, instance="t")

    def run(*argv):
        return main(["--policy", str(policy), "overrides", "--store", str(root), *argv])

    def newest_head():
        return json.loads(_records(local)[-1].read_text())["head"]

    assert run("init") == 0
    assert newest_head() == anchor_of(_head(local))
    _control(local).write_text("{nope")
    assert run("recover", "--mode", "enforce") == 0
    assert newest_head() == anchor_of(_head(local))
    assert newest_head()["revision"] == 2


def test_with_no_record_and_no_state_the_verification_names_no_head(tmp_path):
    record = verifier.verify(Provable(tmp_path), (WRITER,),
                             evaluate=lambda s, ids, **_: {WRITER: None},
                             signing_key=OVERRIDES_KEY, trusted=lambda: None, verify_keys=KEYS)
    assert record["head"] == lockout.NO_HEAD


def test_write_verification_refuses_a_malformed_head(tmp_path):
    with pytest.raises(ValueError, match="not an overrides head"):
        lockout.write_verification(Provable(tmp_path), {WRITER: None}, "s3",
                                   head={"revision": 3, "audit_id": None, "audit_hash": None})


# -- recovery ----------------------------------------------------------------


def test_a_write_over_a_restored_object_is_refused(store):
    """Mutation: skip the anchor in _base."""
    _rolled_back(store)
    with pytest.raises(InvalidState, match="object_before_anchor"):
        _change(store, Change(ACTION_SET, KEY_MODE, "observe"))


def test_a_write_behind_a_record_that_verifies_no_identity_is_refused(store):
    """The fresh record naming rev 3 verifies no writer identity, and rev
    3's request record is deleted, so only that record's head refuses a
    write over the restored rev 2. Mutation: count only records that
    verify an identity in _base."""
    _, newest = _rolled_back(store)
    _unanchor(store)
    verifier.verify(store, (), evaluate=lambda s, ids, **_: {}, signing_key=OVERRIDES_KEY,
                    trusted=lambda: anchor_of(newest), verify_keys=KEYS)
    (store.root / AUDIT_PREFIX / audit_name(newest.audit_id, "request")).unlink()
    assert ov.latest_request_revision(store, KEYS) < newest.revision
    with pytest.raises(InvalidState, match="^object_before_anchor$"):
        _change(store, Change(ACTION_EXCLUDE, value="req_2"))


def test_recover_restores_the_anchored_state_past_the_anchor(store):
    """Mutation: keep the record a restored object names as the first
    candidate."""
    _, newest = _rolled_back(store)
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.revision > newest.revision
    assert applied.state.value(KEY_MODE) == "enforce"
    _anchor(store)
    snap = _reader(store).refresh()
    assert (snap.status, snap.state.value(KEY_MODE)) == ("ok", "enforce")


def test_recover_writes_past_the_anchor_when_newer_records_are_gone(store):
    """With the anchored request record deleted, no request record reaches
    the anchored revision. Mutation: leave the anchor out of the recovered
    revision."""
    _, newest = _rolled_back(store)
    (store.root / AUDIT_PREFIX / audit_name(newest.audit_id, "request")).unlink()
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.revision > newest.revision
    _anchor(store)
    assert _reader(store).refresh().status == "ok"


def test_recover_keeps_the_anchored_head_over_a_replayed_sibling(store, monkeypatch):
    """A write that lost its conditional write leaves a signed request
    record that was never applied. The object is replaced with the state
    that record describes, at the anchored revision. Recover keeps the
    anchored head, not the sibling. Mutation: leave the anchor out of the
    candidates."""
    from forgd_verdict.store.base import StoreConflict

    _change(store, Change(ACTION_EXCLUDE, value="req_1"))
    real_put, real_write, lost = store.put_audit, store.write_control, []

    def capturing(body, etag):
        lost.append(body)
        return real_write(body, etag)

    def racing(name, body):
        if name.endswith("-request.json"):
            monkeypatch.setattr(store, "put_audit", real_put)
            _change(store, Change(ACTION_EXCLUDE, value="req_2"))
            monkeypatch.setattr(store, "write_control", capturing)
        return real_put(name, body)

    monkeypatch.setattr(store, "put_audit", racing)
    with pytest.raises(StoreConflict):
        _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    monkeypatch.undo()
    anchored = _head(store)
    _anchor(store)
    _control(store).write_bytes(lost[0])
    snap = _reader(store).refresh()
    assert (snap.status, snap.error) == ("invalid", "object_before_anchor")
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.value(KEY_MODE) is None
    assert applied.state.excluded_requests == anchored.excluded_requests
    _anchor(store)
    assert _reader(store).refresh().status == "ok"


def _restored_unanchored(store, change, **kwargs):
    """rev 2 is `change`. The object is then restored to rev 1 and every
    verification record deleted, so no signed record names a head. Returns
    rev 2's state."""
    old = _control(store).read_bytes()
    newest = _change(store, change, **kwargs).state
    _anchor(store)
    _control(store).write_bytes(old)
    _unanchor(store)
    return newest


def test_recover_over_an_unanchored_restore_keeps_the_later_signed_request(store):
    """No verification record names rev 2, and the restored rev 1 names
    its own record. Recover keeps rev 2's enforce, and a cold reader adopts
    it. Mutation: leave the latest request out of _recoverable's
    candidates."""
    _restored_unanchored(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    assert _records(store) == []
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.value(KEY_MODE) == "enforce"
    _anchor(store)
    snap = _reader(store).refresh()
    assert (snap.status, snap.state.value(KEY_MODE)) == ("ok", "enforce")


def test_recover_over_an_unanchored_restore_keeps_a_migration(store):
    """Mutations: leave the latest request out of _recoverable's
    candidates and take retirement from the kept state or the invalid
    object only (both at once)."""
    _restored_unanchored(store, Change(ACTION_MIGRATE), migrate=(None, frozenset({"req_1"})))
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.legacy_markers_retired
    _anchor(store)
    reader = _reader(store)
    assert reader.refresh().status == "ok" and reader.legacy_retired()


def test_recover_never_unretires_when_the_kept_chain_predates_a_verified_migration(store):
    """rev 2 migrates, rev 3 excludes, rev 4 sets enforce. The object is
    restored to rev 1, rev 3's request record and every verification
    record deleted: rev 4's chain does not verify, so recover keeps rev 1.
    It still carries rev 2's retirement. Mutation: take retirement from the
    kept state or the invalid object only."""
    old = _control(store).read_bytes()
    migration = _change(store, Change(ACTION_MIGRATE), migrate=(None, frozenset({"req_1"})))
    middle = _change(store, Change(ACTION_EXCLUDE, value="req_2"))
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _control(store).write_bytes(old)
    (store.root / AUDIT_PREFIX / audit_name(middle.audit_id, "request")).unlink()
    _unanchor(store)
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.legacy_markers_retired
    assert applied.state.retired_by == migration.audit_id
    assert applied.record["retired_by"]["id"] == migration.audit_id
    _anchor(store)
    reader = _reader(store)
    assert reader.refresh().status == "ok" and reader.legacy_retired()


def _migrated_then_record_deleted(store):
    """rev 2 migrates, rev 3 sets enforce, and the migration's request
    record is deleted. Returns (the migration's path, its bytes)."""
    migration = _change(store, Change(ACTION_MIGRATE), migrate=(None, frozenset({"req_1"})))
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    path = store.root / AUDIT_PREFIX / audit_name(migration.audit_id, "request")
    blob = path.read_bytes()
    path.unlink()
    return path, blob


def _store_bytes(store):
    return _control(store).read_bytes(), {
        p: p.read_bytes() for p in (store.root / AUDIT_PREFIX).rglob("*") if p.is_file()}


def test_recover_refuses_to_unretire_when_the_migration_record_is_deleted(store):
    """Every retired chain walks through the deleted migration, so none
    verifies, and the newest that does is rev 1, not retired. Recover
    writes nothing, and neither does migrate-markers. Mutation: drop the
    retired-request check in _recovered."""
    _migrated_then_record_deleted(store)
    before = _store_bytes(store)
    with pytest.raises(ov.Refused) as exc:
        _change(store, Change(ACTION_RECOVER))
    assert str(exc.value) == ov.REFUSED_RETIREMENT_UNVERIFIED
    with pytest.raises(InvalidState):
        _change(store, Change(ACTION_MIGRATE), migrate=(None, frozenset()))
    assert _store_bytes(store) == before


def test_recover_carries_the_retirement_once_the_migration_record_is_restored(store):
    path, blob = _migrated_then_record_deleted(store)
    path.write_bytes(blob)
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.legacy_markers_retired
    assert applied.state.value(KEY_MODE) == "enforce"


def test_recover_proceeds_when_the_only_retired_request_conflicted(store, monkeypatch):
    """An exclude commits between the migration's read and its object
    write, so the migration's outcome is a signed `conflict`. Recover over
    the broken object keeps the exclude, not retired."""
    real_put = store.put_audit

    def racing(name, body):
        if name.endswith("-request.json"):
            monkeypatch.setattr(store, "put_audit", real_put)
            _change(store, Change(ACTION_EXCLUDE, value="req_2"))
        return real_put(name, body)

    monkeypatch.setattr(store, "put_audit", racing)
    with pytest.raises(ov.StoreConflict):
        _change(store, Change(ACTION_MIGRATE), migrate=(None, frozenset({"req_1"})))
    monkeypatch.undo()
    [retired] = [json.loads(store.get_audit(n)) for n in store.list_audit()
                 if n.endswith("-request.json") and json.loads(store.get_audit(n)).get(
                     ov.FIELD_RETIRED)]
    outcome = json.loads(store.get_audit(audit_name(retired["id"], "outcome")))
    assert outcome["result"] == "conflict"
    _control(store).write_text("{nope")
    applied = _change(store, Change(ACTION_RECOVER))
    assert not applied.state.legacy_markers_retired
    assert applied.state.excluded_requests == frozenset({"req_2"})


def _migration_raced_with_unknown_outcome(store, monkeypatch):
    """An exclude commits at the migration's revision while the migration's
    object write fails with an error other than a conflict, so its outcome
    is `unknown`. The object then fails to parse as a supported version,
    still naming the exclude. Returns the migration's request record."""
    real_put, real_write = store.put_audit, store.write_control

    def racing(name, body):
        if name.endswith("-request.json"):
            monkeypatch.setattr(store, "put_audit", real_put)
            _change(store, Change(ACTION_EXCLUDE, value="req_2"))
            monkeypatch.setattr(store, "write_control", timeout)
        return real_put(name, body)

    def timeout(body, etag):
        raise TimeoutError("no answer")

    monkeypatch.setattr(store, "put_audit", racing)
    with pytest.raises(TimeoutError):
        _change(store, Change(ACTION_MIGRATE), migrate=(None, frozenset({"req_1"})))
    monkeypatch.undo()
    assert store.write_control is not timeout and real_write
    [migration] = [json.loads(store.get_audit(n)) for n in store.list_audit()
                   if n.endswith("-request.json")
                   and json.loads(store.get_audit(n))["action"] == ACTION_MIGRATE]
    outcome = json.loads(store.get_audit(audit_name(migration["id"], "outcome")))
    assert outcome["result"] == "unknown"
    raw = json.loads(_control(store).read_bytes())
    raw["version"] = 99
    _control(store).write_text(json.dumps(raw))
    return migration


def test_recover_refuses_a_retirement_from_a_migration_that_may_not_have_committed(
        store, monkeypatch, caplog):
    """The kept chain is the exclude's, and the migration is off it with
    no signed outcome saying it committed. Recover marked the object
    retired from it and dropped the legacy ids it would have folded in.
    Mutation: drop the `applied` check in _recovered."""
    migration = _migration_raced_with_unknown_outcome(store, monkeypatch)
    before = _store_bytes(store)
    with caplog.at_level(logging.WARNING, "forgd_verdict"), pytest.raises(ov.Refused) as exc:
        _change(store, Change(ACTION_RECOVER))
    assert str(exc.value) == ov.REFUSED_RETIREMENT_UNVERIFIED
    assert any(r.getMessage() == "recover found a migration off the kept chain with no "
               "signed `applied` outcome" and r.fields["migration"] == migration["id"]
               for r in caplog.records)
    assert _store_bytes(store) == before


def _top_siblings_unsettled(store, monkeypatch, winner_outcome=False):
    """rev 1 sets observe. rev 2 is raced: an exclude wins and a set of
    enforce loses, and the loser's `conflict` outcome is lost, as is the
    winner's `applied` one unless `winner_outcome`. The object is restored
    to rev 1 and every verification record deleted, so nothing else names
    either rev 2 record. Returns (winner id, loser id)."""
    from forgd_verdict.store.base import StoreConflict

    _change(store, Change(ACTION_SET, KEY_MODE, "observe"))
    old = _control(store).read_bytes()
    real_put = store.put_audit

    def racing(name, body):
        if name.endswith("-request.json"):
            monkeypatch.setattr(store, "put_audit", real_put)
            _change(store, Change(ACTION_EXCLUDE, value="req_winner"))
        return real_put(name, body)

    monkeypatch.setattr(store, "put_audit", racing)
    with pytest.raises(StoreConflict):
        _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    monkeypatch.undo()
    winner = _head(store).audit_id
    [loser] = [json.loads(store.get_audit(n))["id"] for n in store.list_audit()
               if n.endswith("-request.json")
               and json.loads(store.get_audit(n)).get("new_value") == "enforce"]
    (store.root / AUDIT_PREFIX / audit_name(loser, "outcome")).unlink()
    if not winner_outcome:
        (store.root / AUDIT_PREFIX / audit_name(winner, "outcome")).unlink()
    _anchor(store)
    _control(store).write_bytes(old)
    _unanchor(store)
    return winner, loser


def test_recover_refuses_when_both_top_siblings_verify(store, monkeypatch, caplog):
    """Recover skipped both as siblings and kept rev 1, losing the
    winner's exclude with no sign that it had. Mutation: drop the
    ambiguity refusal in _recoverable."""
    winner, loser = _top_siblings_unsettled(store, monkeypatch)
    before = _store_bytes(store)
    with caplog.at_level(logging.WARNING, "forgd_verdict"), pytest.raises(ov.Refused) as exc:
        _change(store, Change(ACTION_RECOVER))
    assert str(exc.value) == ov.REFUSED_HEAD_AMBIGUOUS
    assert [r.fields["records"] for r in caplog.records if r.getMessage().startswith(
        "recover found more than one")] == [sorted([winner, loser])]
    assert _store_bytes(store) == before


def test_recover_keeps_the_top_sibling_with_a_signed_applied_outcome(store, monkeypatch):
    """Mutation: settle a top race by chain verification alone."""
    _top_siblings_unsettled(store, monkeypatch, winner_outcome=True)
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.excluded_requests == frozenset({"req_winner"})
    assert applied.state.value(KEY_MODE) == "observe"


@pytest.mark.parametrize("winner_outcome", [False, True], ids=["no-outcome", "applied"])
def test_an_invalid_object_naming_a_top_sibling_does_not_settle_the_race(
        store, monkeypatch, winner_outcome):
    """A storage administrator without the signing key writes an invalid
    object at the race's revision naming the loser. Recover adopted the loser's chain.
    Mutation: skip the race check when the invalid object is at the top
    revision."""
    _, loser = _top_siblings_unsettled(store, monkeypatch, winner_outcome)
    top = ov.latest_request_revision(store, KEYS)
    _control(store).write_text(json.dumps({"version": 99, "revision": top, "audit_id": loser}))
    if winner_outcome:
        applied = _change(store, Change(ACTION_RECOVER))
        assert applied.state.excluded_requests == frozenset({"req_winner"})
        assert applied.state.value(KEY_MODE) == "observe"
    else:
        with pytest.raises(ov.Refused) as exc:
            _change(store, Change(ACTION_RECOVER))
        assert str(exc.value) == ov.REFUSED_HEAD_AMBIGUOUS


def test_recover_keeps_the_top_sibling_left_once_the_other_is_deleted(store, monkeypatch):
    """The documented remedy for head_ambiguous."""
    winner, loser = _top_siblings_unsettled(store, monkeypatch)
    (store.root / AUDIT_PREFIX / audit_name(loser, "request")).unlink()
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.excluded_requests == frozenset({"req_winner"})
    assert applied.state.value(KEY_MODE) == "observe"


def test_recover_keeps_the_only_top_sibling_whose_chain_verifies(store, monkeypatch):
    """The loser's record is altered and signed again, so it is signed but
    does not replay to the object it records. Mutation: keep every
    unsettled top sibling as a candidate, not only those whose chain
    verifies."""
    winner, loser = _top_siblings_unsettled(store, monkeypatch)
    path = store.root / AUDIT_PREFIX / audit_name(loser, "request")
    record = json.loads(path.read_bytes())
    body = {k: v for k, v in record.items() if k != sig.SIGNATURE_FIELD}
    path.write_bytes(ov._record_bytes(sig.sign({**body, "new_value": "observe"}, OVERRIDES_KEY)))
    assert not ov._chain_verifies(store, loser, KEYS)
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.excluded_requests == frozenset({"req_winner"})


def _restored_behind_a_live_anchor(store):
    """rev 1 and rev 2 (enforce) are each anchored. The object is restored
    to rev 1 and the records naming rev 2 deleted, so the fresh record
    names rev 1 and rev 2's request is the only thing later."""
    _anchor(store, at=datetime.now(UTC) - timedelta(seconds=120))
    old = _control(store).read_bytes()
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _anchor(store)
    _control(store).write_bytes(old)
    for path in _records(store):
        if json.loads(path.read_text())["head"]["revision"] == 2:
            path.unlink()
    assert lockout.fresh_head(store, KEYS)[1]["revision"] == 1


@pytest.mark.parametrize("change, kwargs", [
    (Change(ACTION_EXCLUDE, value="req_1"), {}),
    (Change(ACTION_SET, KEY_MODE, "observe"), {}),
    (Change(ACTION_INIT), {}),
    (Change(ACTION_MIGRATE), {"migrate": (None, frozenset())}),
], ids=["exclude", "set", "init", "migrate"])
def test_every_change_but_recover_is_refused_behind_a_signed_request(store, change, kwargs):
    """Mutation: drop the latest_request_revision check from apply_change."""
    _restored_behind_a_live_anchor(store)
    before = _control(store).read_bytes()
    with pytest.raises(ov.Refused) as exc:
        _change(store, change, **kwargs)
    assert str(exc.value) == ov.REFUSED_BEHIND_REQUEST
    assert _control(store).read_bytes() == before


def test_recover_behind_a_signed_request_under_a_live_anchor(store):
    """Mutation: refuse a recover over a valid object unless the anchor
    lapsed."""
    _restored_behind_a_live_anchor(store)
    assert ov.cold_refusal(store, _head(store), KEYS) == ov.ERROR_BEHIND_REQUEST
    applied = _change(store, Change(ACTION_RECOVER))
    assert applied.state.value(KEY_MODE) == "enforce"
    _anchor(store)
    snap = _reader(store).refresh()
    assert (snap.status, snap.state.value(KEY_MODE)) == ("ok", "enforce")


class _Crash(BaseException):
    """A process that dies between the request record and the object."""


def test_recover_after_a_crash_between_the_request_and_the_object(store, monkeypatch):
    """The request has no outcome and the object is unchanged: every cold
    reader refuses it. Recover writes the state the request describes.
    Mutation: refuse a recover over a valid object unless the anchor
    lapsed."""
    _anchor(store)
    monkeypatch.setattr(store, "write_control", lambda body, etag: (_ for _ in ()).throw(
        _Crash()))
    with pytest.raises(_Crash):
        _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    monkeypatch.undo()
    [name] = [n for n in store.list_audit() if n.endswith("-request.json")
              and json.loads(store.get_audit(n))["action"] == ACTION_SET]
    assert store.get_audit(name.replace("-request.json", "-outcome.json")) is None
    assert ov.cold_refusal(store, _head(store), KEYS) == ov.ERROR_BEHIND_REQUEST
    intended, _ = ov._walk(store, json.loads(store.get_audit(name)), None, KEYS)
    applied = _change(store, Change(ACTION_RECOVER))
    assert ov.snapshot_of(applied.state) == ov.snapshot_of(intended)
    _anchor(store)
    assert ov.cold_refusal(store, _head(store), KEYS) is None
    assert _reader(store).refresh().state.value(KEY_MODE) == "enforce"


# -- a cold reader needs the exact head ------------------------------------


_HEAD = {"revision": 3, "audit_id": "20260101T000000Z-aaaaaaaaaaaa", "audit_hash": "a" * 64}


def _state(revision, audit_id=_HEAD["audit_id"], audit_hash=_HEAD["audit_hash"]):
    return ov.ControlState(revision=revision, audit_id=audit_id, audit_hash=audit_hash)


@pytest.mark.parametrize("state, anchor, cold, code", [
    (_state(3), _HEAD, True, None),
    (_state(3), _HEAD, False, None),
    (_state(2), _HEAD, True, "object_before_anchor"),
    (_state(2), _HEAD, False, "object_before_anchor"),
    (_state(3, audit_hash="b" * 64), _HEAD, True, "object_before_anchor"),
    (_state(3, audit_id="20260101T000000Z-bbbbbbbbbbbb"), _HEAD, False,
     "object_before_anchor"),
    (_state(4), _HEAD, True, "object_not_anchored"),
    (_state(4), _HEAD, False, None),
    (_state(3), None, True, "head_anchor_missing"),
    (_state(3), None, False, None),
], ids=["cold-same", "warm-same", "cold-older", "warm-older", "cold-other-hash",
        "warm-other-id", "cold-newer", "warm-newer", "cold-none", "warm-none"])
def test_check_anchor(state, anchor, cold, code):
    """Mutations: let a cold reader through on a later revision; compare
    revisions only; refuse a warm reader on a later revision."""
    if code is None:
        ov.check_anchor(state, anchor, cold=cold)
    else:
        with pytest.raises(InvalidState, match=f"^{code}$"):
            ov.check_anchor(state, anchor, cold=cold)


def test_a_restore_after_the_anchor_but_before_the_latest_change_is_refused_cold(store):
    """The anchor names rev 1; rev 2 excludes a request and rev 3 sets
    enforce. The object restored to rev 2 is after the anchor, and a cold
    reader refuses it. Mutation: let a cold reader through on a later
    revision in check_anchor."""
    _anchor(store)
    _change(store, Change(ACTION_EXCLUDE, value="req_1"))
    old = _control(store).read_bytes()
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _control(store).write_bytes(old)
    reader = _reader(store)
    snap = reader.refresh()
    assert (snap.status, snap.error, snap.ready) == ("invalid", "object_not_anchored", False)
    assert readiness(reader)[0] == 503


def test_with_the_latest_anchor_deleted_a_cold_reader_is_not_ready(store):
    """rev 1 and rev 2 are each anchored. With the record naming rev 2
    deleted, the newest fresh record names rev 1, and rev 2 is not its
    head. Mutation: let a cold reader through on a later revision in
    check_anchor."""
    _anchor(store, at=datetime.now(UTC) - timedelta(seconds=120))
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _anchor(store)
    assert _reader(store).refresh().status == "ok"
    latest = [p for p in _records(store)
              if json.loads(p.read_text())["head"]["revision"] == _head(store).revision]
    assert len(latest) == 1
    latest[0].unlink()
    snap = _reader(store).refresh()
    assert (snap.status, snap.error, snap.ready) == ("invalid", "object_not_anchored", False)


def _cli(store, tmp_path, *argv):
    from conftest import OVERRIDES_PUBLIC_TEXT

    from forgd_verdict.cli import main

    policy = tmp_path / "admins.json"
    policy.write_text(json.dumps({"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
                                  "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}))
    return main(["--policy", str(policy), argv[0], "--store", str(store.root), *argv[1:]])


def _shown(store, tmp_path, capsys):
    assert _cli(store, tmp_path, "overrides", "show") == 0
    out = capsys.readouterr()
    return json.loads(out.out)["cold_reader"], out.err


@pytest.mark.usefixtures("control_identity", "signing_env")
def test_overrides_show_says_when_a_cold_reader_refuses_the_object(store, tmp_path, capsys,
                                                                   monkeypatch):
    """Mutations: leave the anchor check out of `overrides show`; check it
    as a warm reader in cold_refusal."""
    monkeypatch.setattr(ov, "provable", lambda s: True)
    _anchor(store)
    assert _shown(store, tmp_path, capsys) == ({"adopts": True, "error": None}, "")
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    shown, err = _shown(store, tmp_path, capsys)
    assert shown == {"adopts": False, "error": "object_not_anchored"}
    assert "a service starting now would refuse this object (object_not_anchored)" in err


@pytest.mark.usefixtures("control_identity", "signing_env")
def test_exclude_list_says_when_a_cold_reader_refuses_the_object(store, tmp_path, capsys,
                                                                 monkeypatch):
    """Mutation: leave the anchor check out of `exclude --list`."""
    monkeypatch.setattr(ov, "provable", lambda s: True)
    _anchor(store)
    assert _cli(store, tmp_path, "exclude", "--list") == 0
    assert "would refuse" not in capsys.readouterr().err
    _rolled_back(store)
    assert _cli(store, tmp_path, "exclude", "--list") == 0
    assert ("a service starting now would refuse this object (object_before_anchor)"
            in capsys.readouterr().err)
