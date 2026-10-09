"""A cold reader refuses an object when a signed request record names a
later revision, unless that request has a signed `error` outcome.

The attack is a storage administrator who deletes the newest verification
record and restores the object to the head the surviving record names.
Each test names the mutation that makes it fail.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_overrides_anchor import (
    KEYS,
    Provable,
    _anchor,
    _change,
    _control,
    _head,
    _reader,
    _records,
    _shown,
)

from forgd_verdict import overrides as ov
from forgd_verdict import overrides_signing as sig
from forgd_verdict.dashboard.controls import banners
from forgd_verdict.overrides import (
    ACTION_INIT,
    ACTION_SET,
    KEY_MODE,
    Change,
    anchor_of,
    audit_name,
    readiness,
)
from forgd_verdict.store.base import AUDIT_PREFIX, StoreForbidden


@pytest.fixture
def store(tmp_path):
    store = Provable(tmp_path / "store", instance="t")
    _change(store, Change(ACTION_INIT))
    _anchor(store, at=datetime.now(UTC) - timedelta(seconds=120))
    return store


def _audit(store, audit_id, kind):
    return store.root / AUDIT_PREFIX / audit_name(audit_id, kind)


def _rolled_back(store):
    """rev 2 sets enforce and is anchored. The record naming rev 2 is
    deleted and the object restored to rev 1, the head the surviving
    record names. Returns rev 2's state."""
    old = _control(store).read_bytes()
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    newest = _head(store)
    _anchor(store)
    for path in _records(store):
        if json.loads(path.read_text())["head"]["revision"] == newest.revision:
            path.unlink()
    _control(store).write_bytes(old)
    return newest


def _failed(store, monkeypatch, exc, mode="enforce"):
    """A change setting `mode` whose object write raises `exc`. Returns its
    audit id."""
    before = set(store.list_audit())

    def refuse(*_a, **_k):
        raise exc

    monkeypatch.setattr(store, "write_control", refuse)
    with pytest.raises(type(exc)):
        _change(store, Change(ACTION_SET, KEY_MODE, mode))
    monkeypatch.undo()
    new = [n for n in set(store.list_audit()) - before if n.endswith("-request.json")]
    assert len(new) == 1
    return new[0].rsplit("/", 1)[1].removesuffix("-request.json")


def _cold(store):
    snap = _reader(store).refresh()
    return snap.status, snap.error, snap.ready


def test_a_restore_behind_a_signed_request_is_refused_cold(store, caplog):
    """Mutation: drop check_requests from the reader's cold path."""
    _rolled_back(store)
    reader = _reader(store)
    with caplog.at_level(logging.ERROR):
        snap = reader.refresh()
    assert (snap.status, snap.error, snap.ready) == ("invalid", "object_behind_request", False)
    assert any("a signed change request names a later revision" in r.getMessage()
               for r in caplog.records)
    assert "a signed change request names a later revision than the object" in banners(
        snap, "observe")
    code, body = readiness(reader)
    assert (code, body["reason"]) == (503, "runtime overrides are behind a signed change "
                                           "request")


@pytest.mark.usefixtures("control_identity", "signing_env")
def test_show_says_a_cold_reader_refuses_a_restore_behind_a_request(store, tmp_path, capsys,
                                                                     monkeypatch):
    """Mutation: drop check_requests from cold_refusal."""
    monkeypatch.setattr(ov, "provable", lambda s: True)
    _rolled_back(store)
    shown, err = _shown(store, tmp_path, capsys)
    assert shown == {"adopts": False, "error": "object_behind_request"}
    assert ("refuse this object (object_behind_request): a signed change request names a "
            "later revision" in err)


def test_a_request_with_a_signed_error_outcome_does_not_block(store, monkeypatch):
    """Mutation: stop leaving out a request whose signed outcome is `error`."""
    _failed(store, monkeypatch, StoreForbidden("denied"))
    assert _cold(store) == ("ok", None, True)


@pytest.mark.parametrize("outcome", ["missing", "unknown"])
def test_a_request_with_no_outcome_or_an_unknown_one_blocks(store, monkeypatch, outcome):
    """Mutation: leave out a request whatever its outcome says."""
    if outcome == "missing":
        audit_id = _failed(store, monkeypatch, StoreForbidden("denied"))
        _audit(store, audit_id, "outcome").unlink()
    else:
        _failed(store, monkeypatch, TimeoutError("timed out"))
    assert _cold(store) == ("invalid", "object_behind_request", False)


@pytest.mark.parametrize("signer", ["unsigned", "other key"])
def test_an_error_outcome_that_is_not_signed_by_a_listed_key_blocks(store, monkeypatch,
                                                                    signer):
    """Mutation: skip the signature check on the outcome record."""
    audit_id = _failed(store, monkeypatch, StoreForbidden("denied"))
    path = _audit(store, audit_id, "outcome")
    outcome = json.loads(path.read_text())
    outcome.pop(sig.SIGNATURE_FIELD)
    if signer == "other key":
        outcome = sig.sign(outcome, Ed25519PrivateKey.generate())
    path.write_text(json.dumps(outcome))
    assert _cold(store) == ("invalid", "object_behind_request", False)


def test_an_error_outcome_naming_another_request_blocks(store, monkeypatch):
    """A signed `error` outcome copied beside another request. Mutation:
    skip the request_id check on the outcome record."""
    abandoned = _failed(store, monkeypatch, StoreForbidden("denied"))
    later = _failed(store, monkeypatch, TimeoutError("timed out"))
    _audit(store, later, "outcome").unlink()
    _audit(store, later, "outcome").write_bytes(
        _audit(store, abandoned, "outcome").read_bytes())
    assert _cold(store) == ("invalid", "object_behind_request", False)


def test_an_unsigned_request_does_not_block(store, monkeypatch):
    """Mutation: count a request record whatever its signature."""
    audit_id = _failed(store, monkeypatch, TimeoutError("timed out"))
    path = _audit(store, audit_id, "request")
    record = json.loads(path.read_text())
    record.pop(sig.SIGNATURE_FIELD)
    path.write_text(json.dumps(record))
    assert _cold(store) == ("ok", None, True)


def test_a_warm_reader_is_not_held_by_a_later_request(store, monkeypatch):
    """A warm reader keeps its rules. Mutation: run check_requests for warm
    readers too."""
    reader = _reader(store)
    assert reader.refresh().status == "ok"
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _failed(store, monkeypatch, TimeoutError("timed out"), mode="observe")
    snap = reader.refresh()
    assert (snap.status, snap.ready, snap.state.value(KEY_MODE)) == ("ok", True, "enforce")


def test_unanchored_head_passes_over_a_later_abandoned_request(store, monkeypatch):
    """rev 2 is written and not anchored; a rev-3 request is then refused
    with a signed `error` outcome. Mutation: count it in
    latest_request_revision."""
    _change(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    _failed(store, monkeypatch, StoreForbidden("denied"), mode="observe")
    assert ov.unanchored_head(store, KEYS) == anchor_of(_head(store))
