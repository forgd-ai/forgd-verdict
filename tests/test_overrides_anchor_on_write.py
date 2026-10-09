"""Every change writes a signed verification record naming the head it wrote,
so a reader that holds no verified state adopts it without waiting for the
hourly verification. A record that cannot be written leaves the change
applied and is retried.

Each test names the mutation that makes it fail.
"""

from __future__ import annotations

import json
import logging

import pytest
from conftest import DETECTORS, OVERRIDES_KEY, OVERRIDES_PUBLIC, OVERRIDES_PUBLIC_TEXT

from forgd_verdict import lockout
from forgd_verdict import overrides as ov
from forgd_verdict.lockout import LockoutReports
from forgd_verdict.lockout_evidence import verifier
from forgd_verdict.lockout_evidence.verifier import Verifier
from forgd_verdict.models import CONTROL_STATE
from forgd_verdict.overrides import (
    ACTION_EXCLUDE,
    ACTION_INIT,
    ACTION_SET,
    KEY_MODE,
    Change,
    RuntimeOverrides,
    anchor_of,
    apply_change,
    parse_state,
    unanchored_head,
)
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import AUDIT_PREFIX, STATE_PREFIX

ADMIN = {"issuer": "https://idp.example/", "subject": "sub-1", "name": "a.person",
         "via_group": "ops", "verified": True}
KEYS = (OVERRIDES_PUBLIC,)
WRITER = "arn:aws:iam::111111111111:role/forgd-verdict-writer"


class Provable(LocalFileStore):
    """A local store whose lockout counts as provable. With `failing`, no
    verification record can be written."""

    lockout_provable = True
    failing = False

    def put_audit(self, name, body):
        if self.failing and lockout.VERIFY_PREFIX in name:
            raise OSError("the store is unavailable")
        super().put_audit(name, body)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


@pytest.fixture
def store(tmp_path):
    return Provable(tmp_path / "store", instance="t")


def _verifier(store, trusted=None, clock=None, unanchored=True):
    return Verifier(store, identities=(WRITER,), evaluate=lambda s, ids, **_: {WRITER: None},
                    signing_key=OVERRIDES_KEY, verify_keys=KEYS, trusted=trusted,
                    unanchored=(lambda: unanchored_head(store, KEYS)) if unanchored else None,
                    clock=clock)


def _change(store, change, verifier=None):
    return apply_change(store, ADMIN, change, detectors=DETECTORS, signing_key=OVERRIDES_KEY,
                        verify_keys=KEYS,
                        after_write=verifier.after_write if verifier is not None else None)


def _reader(store):
    return RuntimeOverrides(store, "test", baseline={KEY_MODE: "observe"}, verify_keys=KEYS,
                            fleet=LockoutReports(store, ("verdict",), verify_keys=KEYS))


def _head(store):
    return parse_state(store.read_control().body)


def _newest_head(store):
    return lockout.fresh_head(store, KEYS)[1]


def _control(store):
    return store.root / STATE_PREFIX / CONTROL_STATE


# -- a change, then its record ---------------------------------------------


def test_a_change_then_its_record_is_adopted_by_a_cold_reader(store):
    """Mutation: do not call after_write in _write."""
    v = _verifier(store)
    _change(store, Change(ACTION_INIT), v)
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"), v)
    assert _newest_head(store) == anchor_of(_head(store))
    snap = _reader(store).refresh()
    assert (snap.status, snap.ready, snap.state.value(KEY_MODE)) == ("ok", True, "enforce")
    assert v.pending is None


def test_a_checkpoint_is_anchored_before_the_change_after_it(store, monkeypatch):
    """Mutation: do not pass after_write to _checkpoint."""
    monkeypatch.setattr(ov, "CHECKPOINT_EVERY", 1)
    v = _verifier(store)
    _change(store, Change(ACTION_INIT), v)
    _change(store, Change(ACTION_EXCLUDE, value="req_1"), v)
    written = []
    real = v.after_write
    v.after_write = lambda state: written.append(state) or real(state)
    applied = _change(store, Change(ACTION_SET, KEY_MODE, "enforce"), v)
    assert [s.revision for s in written] == [applied.state.revision - 1,
                                             applied.state.revision]
    heads = [json.loads(store.get_audit(n))["head"] for n in store.list_audit()
             if lockout.VERIFY_PREFIX in n]
    assert anchor_of(written[0]) in heads and anchor_of(written[1]) in heads


def test_a_step_after_the_write_that_raises_leaves_the_change_applied(store, caplog):
    """Mutation: let an exception from after_write propagate."""
    _change(store, Change(ACTION_INIT))

    def broken(state):
        raise RuntimeError("boom")

    with caplog.at_level(logging.ERROR, logger="forgd_verdict.overrides"):
        applied = apply_change(store, ADMIN, Change(ACTION_SET, KEY_MODE, "enforce"),
                               detectors=DETECTORS, signing_key=OVERRIDES_KEY,
                               verify_keys=KEYS, after_write=broken)
    assert _head(store) == applied.state
    assert any("step after the write failed" in r.getMessage() for r in caplog.records)


# -- between the write and the record ---------------------------------------


def _unanchored_change(store, caplog):
    """Anchored at init with a warm reader holding it; then enforce, whose
    record cannot be written. Returns (verifier, warm reader)."""
    v = _verifier(store, clock=Clock())
    _change(store, Change(ACTION_INIT), v)
    warm = _reader(store)
    assert warm.refresh().ready
    store.failing = True
    with caplog.at_level(logging.ERROR, logger="forgd_verdict.lockout"):
        _change(store, Change(ACTION_SET, KEY_MODE, "enforce"), v)
    assert any("no lockout verification naming its head was written" in r.getMessage()
               and r.levelno == logging.ERROR for r in caplog.records)
    return v, warm


def test_between_the_write_and_its_record_a_cold_reader_waits_and_a_warm_one_serves(
        store, caplog):
    """Mutation: let a cold reader through on a later revision in
    check_anchor."""
    v, warm = _unanchored_change(store, caplog)
    assert _head(store).value(KEY_MODE) == "enforce", "the change is applied"
    assert v.pending == anchor_of(_head(store))
    snap = _reader(store).refresh()
    assert (snap.status, snap.error, snap.ready) == ("invalid", "object_not_anchored", False)
    snap = warm.refresh()
    assert (snap.status, snap.ready, snap.state.value(KEY_MODE)) == ("ok", True, "enforce")


def test_a_failed_record_is_retried_before_the_hourly_run(store, caplog):
    """Mutations: clear the pending head when the run fails; skip a due
    run in tick."""
    v, _ = _unanchored_change(store, caplog)
    assert v.due() and v.tick(), "retried while the store still fails"
    assert v.pending is not None
    store.failing = False
    assert v.tick()
    assert v.pending is None and not v.due()
    assert not v.tick(), "nothing is due until the hour has passed"
    snap = _reader(store).refresh()
    assert (snap.ready, snap.state.value(KEY_MODE)) == (True, "enforce")


def test_a_restarted_dashboard_writes_the_record_without_adopting_the_head(store, caplog):
    """The dashboard restarts before the retry: its reader holds nothing and
    the pending head is gone. Mutation: drop `unanchored` from Verifier.head."""
    _unanchored_change(store, caplog)
    store.failing = False
    cold = _reader(store)
    assert cold.refresh().state is None
    restarted = _verifier(store, trusted=lambda: ov.trusted_head(cold), clock=Clock())
    assert restarted.due() and restarted.tick()
    assert _newest_head(store) == anchor_of(_head(store))
    assert cold.refresh().state.value(KEY_MODE) == "enforce"


def test_a_restored_unanchored_head_is_not_named_while_a_later_record_exists(store, caplog):
    """rev 2 and rev 3 are both unanchored, and the object is restored to
    rev 2. Mutation: drop the highest_revision check in unanchored_head."""
    v, _ = _unanchored_change(store, caplog)
    old = _control(store).read_bytes()
    _change(store, Change(ACTION_EXCLUDE, value="req_1"), v)
    _control(store).write_bytes(old)
    assert unanchored_head(store, KEYS) is None
    store.failing = False
    restarted = _verifier(store, trusted=lambda: None, clock=Clock())
    assert not restarted.due()
    assert _reader(store).refresh().error == "object_not_anchored"


def test_an_anchored_or_older_head_is_not_unanchored(store):
    """Mutation: compare with >= in unanchored_head."""
    v = _verifier(store)
    _change(store, Change(ACTION_INIT), v)
    assert unanchored_head(store, KEYS) is None


# -- every writer ------------------------------------------------------------


def _policy(tmp_path):
    path = tmp_path / "admins.json"
    path.write_text(json.dumps({"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
                                "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}))
    return path


def _cli(tmp_path, store, *argv):
    from forgd_verdict.cli import main

    command, rest = argv[0], argv[1:]
    return main(["--policy", str(_policy(tmp_path)), command, "--store", str(store.root),
                 *rest])


@pytest.mark.parametrize("before, argv", [
    ((), ("overrides", "init")),
    ((("overrides", "init"),), ("overrides", "set", "server.mode", "enforce")),
    ((("overrides", "init"), ("overrides", "set", "server.mode", "enforce")),
     ("overrides", "clear", "server.mode")),
    ((("overrides", "init"), ("overrides", "set", "server.mode", "enforce")),
     ("overrides", "clear-all")),
    ((("overrides", "init"),), ("overrides", "migrate-markers")),
    ((("overrides", "init"),), ("exclude", "--request-id", "req_1")),
    ((("overrides", "init"), ("exclude", "--request-id", "req_1")), ("exclude", "--clear")),
    ((("overrides", "init"),), ("reset-stats", "--at", "2026-09-01T00:00:00Z")),
    ((("overrides", "init"), ("reset-stats", "--at", "2026-09-01T00:00:00Z")),
     ("reset-stats", "--clear")),
], ids=["init", "set", "clear", "clear-all", "migrate-markers", "exclude", "exclude-clear",
        "reset-stats", "reset-stats-clear"])
@pytest.mark.usefixtures("control_identity", "signing_env")
def test_every_cli_change_names_its_head(tmp_path, store, monkeypatch, before, argv):
    """Mutation: pass no after_write from the CLI's _change."""
    monkeypatch.setattr(lockout, "provable", lambda s: True)
    for step in before:
        assert _cli(tmp_path, store, *step) == 0
    assert _cli(tmp_path, store, *argv) == 0
    assert lockout.anchored_head(store, KEYS) == anchor_of(_head(store))


@pytest.mark.usefixtures("control_identity", "signing_env")
def test_a_cli_recover_names_its_head(tmp_path, store, monkeypatch):
    monkeypatch.setattr(lockout, "provable", lambda s: True)
    assert _cli(tmp_path, store, "overrides", "init") == 0
    _control(store).write_text("{nope")
    assert _cli(tmp_path, store, "overrides", "recover", "--mode", "enforce") == 0
    assert lockout.anchored_head(store, KEYS) == anchor_of(_head(store))


@pytest.mark.usefixtures("control_identity", "signing_env")
def test_the_cli_says_when_the_record_could_not_be_written(tmp_path, store, monkeypatch,
                                                           capsys):
    """Mutation: drop the pending check from the CLI's _anchored."""
    monkeypatch.setattr(lockout, "provable", lambda s: True)
    assert _cli(tmp_path, store, "overrides", "init") == 0
    capsys.readouterr()
    real = LocalFileStore.put_audit

    def failing(self, name, body):
        if lockout.VERIFY_PREFIX in name:
            raise OSError("the store is unavailable")
        real(self, name, body)

    monkeypatch.setattr(LocalFileStore, "put_audit", failing)
    assert _cli(tmp_path, store, "overrides", "set", "server.mode", "enforce") == 0
    assert _head(store).value(KEY_MODE) == "enforce"
    assert "the change is applied, but the lockout verification naming its head could not " \
           "be written" in capsys.readouterr().err


# -- a record that locks out no writer ----------------------------------------


def _count(store):
    return len(list(store.root.rglob(f"{lockout.VERIFY_PREFIX}*.json")))


def test_a_cli_record_with_no_identities_is_rewritten_before_the_hourly_run(store):
    """The CLI, run without FORGD_OVERRIDES_WRITER_IDENTITIES, writes a
    record naming its head that verifies no identity. The dashboard's next
    tick writes a full one. Mutation: ignore whether the newest record
    locks out every writer in due."""
    clock = Clock()
    dashboard = _verifier(store, clock=clock)
    _change(store, Change(ACTION_INIT), dashboard)
    cli = Verifier(store, identities=(), signing_key=OVERRIDES_KEY, verify_keys=KEYS)
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"), cli)
    assert not lockout.fresh_record(store, KEYS)["ok"]
    assert _reader(store).refresh().ready is False
    clock.t = verifier.RETRY_S
    assert dashboard.tick()
    newest = lockout.fresh_record(store, KEYS)
    assert newest["ok"] and newest["head"] == anchor_of(_head(store))
    snap = _reader(store).refresh()
    assert (snap.ready, snap.state.value(KEY_MODE)) == (True, "enforce")


def test_a_dashboard_that_cannot_verify_does_not_rewrite_on_every_tick(store, caplog):
    """Its own record shows a failing identity. Mutations: drop the
    written-since-the-last-run condition in due; stop recording the newest
    id when a run ends."""
    clock = Clock()
    dashboard = Verifier(store, identities=(WRITER,), clock=clock,
                         evaluate=lambda s, ids, **_: {WRITER: "policy_read_failed"},
                         signing_key=OVERRIDES_KEY, verify_keys=KEYS,
                         unanchored=lambda: unanchored_head(store, KEYS))
    with caplog.at_level(logging.ERROR):
        _change(store, Change(ACTION_INIT), dashboard)
    assert any("writer lockout not verified" in r.getMessage() for r in caplog.records)
    written = _count(store)
    for tick in range(1, 4):
        clock.t = tick * verifier.RETRY_S
        assert not dashboard.tick()
    assert _count(store) == written
    cli = Verifier(store, identities=(), signing_key=OVERRIDES_KEY, verify_keys=KEYS)
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"), cli)
    assert dashboard.tick(), "a record written since its last run is rewritten once"
    assert not dashboard.tick()


def test_a_failed_rewrite_of_a_cli_record_is_retried(store):
    """Mutation: record the newest id after a run that raised."""
    clock = Clock()
    dashboard = _verifier(store, clock=clock)
    _change(store, Change(ACTION_INIT), dashboard)
    cli = Verifier(store, identities=(), signing_key=OVERRIDES_KEY, verify_keys=KEYS)
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"), cli)
    store.failing = True
    clock.t = verifier.RETRY_S
    assert dashboard.tick() and not lockout.fresh_record(store, KEYS)["ok"]
    store.failing = False
    clock.t = 2 * verifier.RETRY_S
    assert dashboard.tick() and lockout.fresh_record(store, KEYS)["ok"]


def _replica(store, clock):
    """A dashboard replica whose verification shows a failing identity."""
    return Verifier(store, identities=(WRITER,), clock=clock,
                    evaluate=lambda s, ids, **_: {WRITER: "policy_read_failed"},
                    signing_key=OVERRIDES_KEY, verify_keys=KEYS,
                    unanchored=lambda: unanchored_head(store, KEYS),
                    written_by=lockout.WRITTEN_BY_DASHBOARD)


def test_two_dashboard_replicas_do_not_rewrite_each_others_failing_record(store):
    """Each replica's newest record is the other's, so it was never the
    newest when its own last run ended. Neither runs before the interval.
    A failing record from the CLI, or from a writer that names none, is
    still rewritten. Mutation: drop the written_by condition in due."""
    clock = Clock()
    a, b = _replica(store, clock), _replica(store, clock)
    b.once()
    _change(store, Change(ACTION_INIT), a)
    assert lockout.fresh_record(store, KEYS)["written_by"] == lockout.WRITTEN_BY_DASHBOARD
    written = _count(store)
    assert not b.due()
    for tick in range(1, int(lockout.VERIFY_EVERY_S // verifier.RETRY_S)):
        clock.t = tick * verifier.RETRY_S
        assert not a.tick() and not b.tick()
    assert _count(store) == written
    clock.t = lockout.VERIFY_EVERY_S + verifier.RETRY_S
    assert b.tick()

    for written_by in (lockout.WRITTEN_BY_CLI, None):
        cli = Verifier(store, identities=(), signing_key=OVERRIDES_KEY, verify_keys=KEYS,
                       written_by=written_by)
        cli.once()
        assert lockout.fresh_record(store, KEYS).get("written_by") == written_by
        assert b.due()
        b.once()


@pytest.mark.parametrize("written_by, trusted", [
    ("cli", True), ("Not A Role", False), (7, False)])
def test_a_verification_writer_must_be_a_fixed_code(store, written_by, trusted):
    """Mutation: skip the written_by check in _well_formed."""
    record = lockout.write_verification(store, {WRITER: None}, "s3",
                                        signing_key=OVERRIDES_KEY)
    record = {**record, "written_by": written_by}
    record = lockout.sign_record({k: v for k, v in record.items() if k != "signature"},
                                 OVERRIDES_KEY)
    (store.root / AUDIT_PREFIX / lockout.verification_name(record["id"])).write_bytes(
        (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
    assert (lockout.fresh_record(store, KEYS) is not None) == trusted
