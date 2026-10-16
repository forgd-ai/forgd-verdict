"""How much of the audit history a change, a cold read and a recover read.

A change and a cold read hold a verified head, and a request record at a
later revision was written after that head's record, so they read only the
request records within REQUEST_WINDOW of it. A recover has no head to go
by and reads every request record, once. Each test names the mutation that
makes it fail.
"""

from __future__ import annotations

import collections
import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import OVERRIDES_KEY
from test_overrides_anchor import KEYS, _change, _head

from forgd_verdict import overrides as ov
from forgd_verdict import overrides_signing as sig
from forgd_verdict.overrides import (
    ACTION_INIT,
    ACTION_RECOVER,
    ACTION_SET,
    KEY_MODE,
    Change,
    InvalidState,
    audit_name,
)
from forgd_verdict.store import LocalFileStore

DAY0 = datetime(2026, 1, 1, 12, tzinfo=UTC)


class Counting(LocalFileStore):
    """A local store that counts its audit reads and listings."""

    lockout_provable = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.gets: collections.Counter[str] = collections.Counter()
        self.lists = 0
        self.request_lists = 0

    def get_audit(self, name):
        self.gets[name] += 1
        return super().get_audit(name)

    def list_audit(self, day=None, leaf=""):
        self.lists += 1
        if leaf[:1].isdigit():
            self.request_lists += 1
        return super().list_audit(day, leaf)

    def reset(self):
        self.gets.clear()
        self.lists = self.request_lists = 0

    def requests_read(self):
        return {n: c for n, c in self.gets.items() if n.endswith("-request.json")}


@pytest.fixture
def store(tmp_path):
    return Counting(tmp_path / "store", instance="t")


def _history(store, changes, every=timedelta(hours=12)):
    """`state.init` at DAY0, then `changes` mode changes `every` apart.
    Returns the object's bytes after each change, init's first."""
    _change(store, Change(ACTION_INIT), now=DAY0)
    snapshots = [store.read_control().body]
    for i in range(changes):
        _change(store, Change(ACTION_SET, KEY_MODE, "enforce" if i % 2 == 0 else "observe"),
                now=DAY0 + every * (i + 1))
        snapshots.append(store.read_control().body)
    return snapshots


def _id_time(name_or_id):
    leaf = name_or_id.rsplit("/", 1)[-1]
    return datetime.strptime(leaf[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


def test_a_cold_check_reads_only_the_request_records_near_the_head(store):
    """Sixty days of changes; the check reads the head's day and the one
    before it. Mutation: read every request record in check_requests."""
    _history(store, 120)
    head = _head(store)
    store.reset()
    ov.check_requests(store, head, KEYS)
    read = store.requests_read()
    assert read and len(read) <= 4, sorted(read)
    assert all(_id_time(n) >= _id_time(head.audit_id) - ov.REQUEST_WINDOW for n in read)
    assert store.lists <= 2


def test_an_object_restored_from_weeks_ago_is_still_behind_a_request(store):
    """Every record after the restored head is in the window, however long
    after it. Mutation: end the window at the head's id."""
    snapshots = _history(store, 60)
    store.write_control(snapshots[10], store.read_control().etag)
    restored = _head(store)
    with pytest.raises(InvalidState, match="object_behind_request"):
        ov.check_requests(store, restored, KEYS)
    assert ov.latest_request_revision(store, KEYS, after=restored.audit_id) == 61
    assert ov.cold_refusal(store, restored, KEYS) is not None


def _signed_request(store, audit_id, base_revision):
    record = sig.sign({"version": ov.VERSION, "kind": "request", "id": audit_id,
                       "base_revision": base_revision, "action": ACTION_SET,
                       "key": KEY_MODE, "at": "2026-01-01T00:00:00Z"}, OVERRIDES_KEY)
    store.put_audit(audit_name(audit_id, "request"),
                    (json.dumps(record, sort_keys=True) + "\n").encode())


@pytest.mark.parametrize("before, counted", [
    (timedelta(hours=23, minutes=59, seconds=59), True),
    (timedelta(days=1), True),
    (timedelta(days=1, seconds=1), False)])
def test_the_window_reaches_one_day_before_the_head(store, before, counted):
    """A signed request at a later revision whose id is dated before the
    head's by more than REQUEST_WINDOW is outside what a change or a cold
    read reads; a full scan still counts it. Mutation: shrink or drop the
    window."""
    _history(store, 6)
    head = _head(store)
    stamp = _id_time(head.audit_id) - before
    _signed_request(store, f"{stamp:%Y%m%dT%H%M%SZ}-{'a' * 12}", head.revision)
    bounded = ov.latest_request_revision(store, KEYS, after=head.audit_id)
    assert bounded == (head.revision + 1 if counted else head.revision)
    assert ov.latest_request_revision(store, KEYS) == head.revision + 1


def test_a_change_reads_only_the_request_records_near_the_head(store):
    """Mutation: drop `after` from apply_change's latest_request_revision."""
    _history(store, 120)
    head = _head(store)
    store.reset()
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"), now=DAY0 + timedelta(days=61))
    early = [n for n in store.requests_read()
             if _id_time(n) < _id_time(head.audit_id) - ov.REQUEST_WINDOW]
    # The chain walk reads back to the newest chain start, no further.
    assert len(early) <= ov.CHECKPOINT_EVERY, len(early)
    assert len(store.requests_read()) < 120


def test_latest_request_revision_reads_outcomes_only_at_the_top(store):
    """Mutation: read the outcome of every request record."""
    _history(store, 40)
    store.reset()
    assert ov.latest_request_revision(store, KEYS) == 41
    outcomes = [n for n in store.gets if n.endswith("-outcome.json")]
    assert len(outcomes) <= 1, outcomes


def test_a_recover_reads_each_request_record_once(store):
    """Mutation: let each of recover's helpers read the records itself."""
    _history(store, 200)
    store.write_control(b"{not json", store.read_control().etag)
    days = len(store.audit_days())
    store.reset()
    _change(store, Change(ACTION_RECOVER), now=DAY0 + timedelta(days=101))
    read = store.requests_read()
    assert len(read) >= 200
    assert sum(read.values()) <= 200 + 2 * ov.CHECKPOINT_EVERY, sum(read.values())
    assert store.request_lists <= days, (store.request_lists, days)


@pytest.mark.parametrize("before, refused", [
    (timedelta(days=1), False), (timedelta(days=1, seconds=1), True)])
def test_a_change_dated_more_than_a_day_before_its_head_is_refused(store, before, refused):
    """A writer whose clock is behind, or that took its time before it read
    the head, would write a request no later check reads. Mutation: drop
    the guard in apply_change."""
    _history(store, 6)
    head = _head(store)
    requests = len([n for n in store.list_audit() if n.endswith("-request.json")])
    at = _id_time(head.audit_id) - before
    if refused:
        with pytest.raises(ov.Refused, match=ov.ERROR_CLOCK_BEHIND_HEAD):
            _change(store, Change(ACTION_SET, KEY_MODE, "enforce"), now=at)
        assert len([n for n in store.list_audit() if n.endswith("-request.json")]) == requests
        assert _head(store) == head
    else:
        _change(store, Change(ACTION_SET, KEY_MODE, "enforce"), now=at)
        assert _head(store).revision == head.revision + 1
