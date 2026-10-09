"""`min_reader_version`: the lowest release that may apply the object.

Setting `server.mode` raises it to the writer's release (`__version__`,
never `build_id()`). Every other write keeps it while `server.mode` is set,
and it goes with the mode. A reader whose release is lower adopts nothing
new: a warm one keeps its last-known-good, a cold one the baseline, and
either is not ready, in error, and answers `/readyz` with 503.
"""

from __future__ import annotations

import json
import logging

import pytest
from conftest import DETECTORS, OVERRIDES_KEY, OVERRIDES_PUBLIC_TEXT, WHSEC, ASGIClient, make_policy

import forgd_verdict
from forgd_verdict import overrides as ov
from forgd_verdict.models import CONTROL_STATE
from forgd_verdict.overrides import (
    ACTION_CLEAR,
    ACTION_CLEAR_ALL,
    ACTION_EXCLUDE,
    ACTION_INIT,
    ACTION_RECOVER,
    ACTION_RESET,
    ACTION_SET,
    ACTION_UNEXCLUDE,
    ERROR_READER_TOO_OLD,
    FIELD_MIN_READER,
    KEY_MODE,
    Change,
    InvalidState,
    RuntimeOverrides,
    apply_change,
    audit_name,
    parse_state,
    reader_supports,
    readiness,
    release,
)
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import STATE_PREFIX

ADMIN = {"issuer": "https://idp.example/", "subject": "sub-1", "name": "a.person",
         "via_group": "ops", "verified": True}


@pytest.fixture
def store(tmp_path):
    s = LocalFileStore(tmp_path / "store", instance="t")
    apply_change(s, ADMIN, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    return s


def _apply(store, change, writer=None, **kw):
    return apply_change(store, ADMIN, change, detectors=DETECTORS, signing_key=OVERRIDES_KEY, writer_version=writer, **kw)


def _mode(store, value="enforce", writer="1.4.0"):
    return _apply(store, Change(ACTION_SET, KEY_MODE, value), writer)


def _control(store):
    return store.root / STATE_PREFIX / CONTROL_STATE


def _raw(store):
    return json.loads(_control(store).read_bytes())


def _request(store, audit_id):
    return json.loads(store.get_audit(audit_name(audit_id, "request")))


def _reader(store, version, baseline="observe"):
    return RuntimeOverrides(store, "test", baseline={KEY_MODE: baseline}, reader_version=version)


# -- the version -------------------------------------------------------------


@pytest.mark.parametrize("value,parsed", [
    ("0.29.8", (0, 29, 8)), ("10.0.12", (10, 0, 12)), ("0.0.0", (0, 0, 0)),
    ("1.2", None), ("1.2.3.4", None), ("01.2.3", None), ("1.02.3", None), ("v1.2.3", None),
    ("1.2.3+abcdef", None), ("1.2.3-rc1", None), (" 1.2.3", None), ("", None),
    (123, None), (None, None), (["1.2.3"], None),
])
def test_only_a_strict_release_version_parses(value, parsed):
    assert release(value) == parsed


@pytest.mark.parametrize("need,have,ok", [
    (None, "0.0.1", True),
    ("0.29.8", "0.29.8", True),
    ("0.29.8", "0.29.9", True),
    ("0.29.9", "0.29.8", False),
    ("0.29.10", "0.29.9", False),
    ("0.29.9", "0.29.10", True),
    ("0.10.0", "0.9.99", False),
    ("0.9.99", "0.10.0", True),
    ("1.0.0", "0.99.99", False),
    ("10.0.0", "9.99.99", False),
    ("0.29.8", "0.29.8+abc", False),
    ("0.29.8", "dev", False),
])
def test_versions_compare_numerically_per_component(need, have, ok):
    """Mutation: compare the strings, which puts 0.29.10 before 0.29.9."""
    assert reader_supports(need, have) is ok


# -- stamping ------------------------------------------------------------------


def test_setting_the_mode_stamps_the_writers_release_in_the_object_and_the_record(store):
    """Mutation: do not stamp on server.mode."""
    applied = _mode(store, writer="1.4.0")
    assert applied.state.min_reader_version == "1.4.0"
    assert _raw(store)[FIELD_MIN_READER] == "1.4.0"
    assert _request(store, applied.audit_id)[FIELD_MIN_READER] == "1.4.0"
    assert parse_state(_control(store).read_bytes()).min_reader_version == "1.4.0"


def test_the_default_stamp_is_the_release_not_the_build(store, monkeypatch):
    """Mutation: stamp build_id()."""
    monkeypatch.setattr(forgd_verdict, "build_commit", "0123456789abcdef")
    assert "+" in forgd_verdict.build_id()
    applied = _apply(store, Change(ACTION_SET, KEY_MODE, "enforce"))
    assert applied.state.min_reader_version == forgd_verdict.__version__


def test_an_object_without_a_mode_carries_no_field(store):
    """An object from before the field keeps its bytes and its digest."""
    _apply(store, Change(ACTION_EXCLUDE, value="req_1"))
    assert FIELD_MIN_READER not in _raw(store)
    state = parse_state(_control(store).read_bytes())
    assert state.min_reader_version is None and FIELD_MIN_READER not in state.to_json()


def test_unrelated_writes_keep_it_and_clearing_the_mode_removes_it(store):
    """Mutation: drop it on an unrelated write, or keep it after the mode goes."""
    _mode(store, writer="1.4.0")
    for change in (Change(ACTION_EXCLUDE, value="req_1"), Change(ACTION_UNEXCLUDE, value="req_1"),
                   Change(ACTION_RESET, value="2026-09-01T00:00:00Z")):
        applied = _apply(store, change, writer="9.0.0")
        assert applied.state.min_reader_version == "1.4.0", change.action
        assert _request(store, applied.audit_id)[FIELD_MIN_READER] == "1.4.0"
    applied = _apply(store, Change(ACTION_CLEAR, KEY_MODE))
    assert applied.state.min_reader_version is None
    assert FIELD_MIN_READER not in _raw(store)
    assert _request(store, applied.audit_id)[FIELD_MIN_READER] is None
    assert _reader(store, "0.0.1").refresh().status == "ok"


def test_clear_all_removes_it(store):
    _mode(store, writer="1.4.0")
    assert _apply(store, Change(ACTION_CLEAR_ALL)).state.min_reader_version is None
    assert FIELD_MIN_READER not in _raw(store)


def test_setting_the_mode_again_never_lowers_it(store):
    _mode(store, "enforce", writer="1.10.0")
    assert _mode(store, "observe", writer="1.9.0").state.min_reader_version == "1.10.0"
    assert _mode(store, "enforce", writer="1.11.0").state.min_reader_version == "1.11.0"
    assert _reader(store, "1.11.0").refresh().status == "ok"


def test_a_writer_that_is_not_a_release_cannot_set_the_mode(store):
    with pytest.raises(ov.Refused, match="not a release version"):
        _mode(store, writer="1.4.0+abc")
    assert FIELD_MIN_READER not in _raw(store)


def test_recover_keeps_it_and_a_recover_mode_stamps_it(store):
    _mode(store, writer="1.4.0")
    _apply(store, Change(ACTION_EXCLUDE, value="req_1"))
    raw = _raw(store)
    raw["version"] = 99
    _control(store).write_text(json.dumps(raw))
    applied = _apply(store, Change(ACTION_RECOVER), writer="2.0.0")
    assert applied.state.min_reader_version == "1.4.0"
    assert applied.record["new_value"][FIELD_MIN_READER] == "1.4.0"
    assert applied.record[FIELD_MIN_READER] == "1.4.0"
    assert _reader(store, "1.4.0").refresh().status == "ok"

    raw = _raw(store)
    raw["version"] = 99
    _control(store).write_text(json.dumps(raw))
    applied = _apply(store, Change(ACTION_RECOVER), writer="2.0.0", recover_mode="observe")
    assert applied.state.min_reader_version == "2.0.0"
    assert _reader(store, "2.0.0").refresh().status == "ok"


def test_a_checkpoint_carries_it(store):
    _mode(store, writer="1.4.0")
    for i in range(ov.CHECKPOINT_EVERY + 1):
        _apply(store, Change(ACTION_EXCLUDE, value=f"req_{i}"))
    checkpoints = [json.loads(store.get_audit(n)) for n in store.list_audit()
                   if n.endswith("-request.json")
                   and json.loads(store.get_audit(n))["action"] == ov.ACTION_CHECKPOINT]
    assert [c["new_value"][FIELD_MIN_READER] for c in checkpoints] == ["1.4.0"]
    assert [c[FIELD_MIN_READER] for c in checkpoints] == ["1.4.0"]
    snap = _reader(store, "1.4.0").refresh()
    assert snap.status == "ok" and snap.state.min_reader_version == "1.4.0"


# -- tamper checks ---------------------------------------------------------------


@pytest.mark.parametrize("value", ["1.2", "v1.2.3", "1.2.3+abc", "", 5, None, ["1.2.3"]])
def test_a_malformed_value_is_a_fixed_code(store, value):
    _mode(store)
    raw = _raw(store)
    raw[FIELD_MIN_READER] = value
    with pytest.raises(InvalidState) as raised:
        parse_state(json.dumps(raw).encode())
    assert raised.value.code == "min_reader_version_malformed"


def test_a_value_without_a_mode_is_refused(store):
    raw = _raw(store)
    raw[FIELD_MIN_READER] = "1.0.0"
    with pytest.raises(InvalidState, match="^min_reader_version_without_mode$"):
        parse_state(json.dumps(raw).encode())


@pytest.mark.parametrize("value", ["0.0.1", "99.0.0"])
def test_changing_it_on_the_object_alone_is_refused(store, value):
    """Mutation: leave it out of the object's digest."""
    _mode(store, writer="1.4.0")
    raw = _raw(store)
    raw[FIELD_MIN_READER] = value
    _control(store).write_text(json.dumps(raw))
    snap = _reader(store, "100.0.0").refresh()
    assert (snap.status, snap.error) == ("invalid", "head_min_reader_mismatch")


def _forge_head(store, applied, value):
    """The head request record and the object both carrying `value`, and
    consistent with each other, as the control identity could write them."""
    state = ov.replace(applied.state, min_reader_version=value, audit_hash=None)
    record = {**applied.record, FIELD_MIN_READER: value, "state_sha256": ov.state_digest(state)}
    blob = ov._record_bytes(record)
    [path] = store.root.rglob(f"{applied.audit_id}-request.json")
    path.write_bytes(blob)
    raw = {**state.to_json(), "audit_hash": ov._sha256(blob), FIELD_MIN_READER: value}
    _control(store).write_text(json.dumps(raw))


def test_a_link_that_changes_it_other_than_by_setting_the_mode_is_refused(store):
    """An exclusion record and its object both drop the version.

    Mutation: skip the per-record check in _transition."""
    _mode(store, writer="1.4.0")
    _forge_head(store, _apply(store, Change(ACTION_EXCLUDE, value="req_1")), "1.0.0")
    snap = _reader(store, "9.0.0").refresh()
    assert (snap.status, snap.error) == ("invalid", "record_min_reader_mismatch")


@pytest.mark.parametrize("claimed,code", [
    ("1.3.9", "record_min_reader_mismatch"), ("1.4", "min_reader_version_malformed")])
def test_a_mode_record_cannot_lower_it_or_claim_a_malformed_one(store, claimed, code):
    """Mutation: take a mode record's claim without comparing it to its parent's."""
    _mode(store, "enforce", writer="1.4.0")
    _forge_head(store, _mode(store, "observe", writer="1.4.0"), claimed)
    snap = _reader(store, "9.0.0").refresh()
    assert (snap.status, snap.error) == ("invalid", code)


# -- readers -------------------------------------------------------------------


@pytest.mark.parametrize("reader,adopted", [
    ("1.4.0", True), ("1.4.1", True), ("1.10.0", True), ("2.0.0", True),
    ("1.3.99", False), ("0.99.0", False),
])
def test_a_cold_reader_adopts_only_at_or_above_the_version(store, reader, adopted, caplog):
    """Mutation: drop the version check before adopting."""
    _mode(store, writer="1.4.0")
    r = _reader(store, reader)
    with caplog.at_level(logging.ERROR, "forgd_verdict"):
        snap = r.refresh()
    if adopted:
        assert (snap.status, snap.source, snap.ready) == ("ok", "object", True)
        assert r.mode("observe") == "enforce"
        return
    assert (snap.status, snap.source, snap.error) == ("disabled", "baseline", ERROR_READER_TOO_OLD)
    assert not snap.ready and snap.in_error and snap.fields()["in_error"] == 1
    assert r.mode("observe") == "observe"
    assert readiness(r) == (503, {"status": "not_ready",
                                  "reason": "runtime overrides need a newer forgd-verdict release",
                                  "runtime_overrides": "disabled"})
    errors = [rec for rec in caplog.records if rec.levelno == logging.ERROR]
    assert errors and all(rec.fields["error"] == ERROR_READER_TOO_OLD for rec in errors)
    assert not any("1.4.0" in rec.getMessage() + json.dumps(rec.fields) for rec in caplog.records)


def test_a_warm_reader_keeps_its_last_known_good_and_is_not_ready(store):
    """Mutation: adopt, or stay ready, on an object that needs a newer release."""
    _mode(store, "enforce", writer="1.4.0")
    r = _reader(store, "1.5.0")
    assert r.refresh().ready and r.mode("observe") == "enforce"
    _mode(store, "observe", writer="1.6.0")
    snap = r.refresh()
    assert (snap.source, snap.status, snap.error) == ("last_known_good", "disabled",
                                                      ERROR_READER_TOO_OLD)
    assert not snap.ready and snap.in_error
    assert snap.state.value(KEY_MODE) == "enforce" and r.mode("observe") == "enforce"
    assert readiness(r)[0] == 503
    _apply(store, Change(ACTION_CLEAR, KEY_MODE))
    snap = r.refresh()
    assert (snap.status, snap.ready) == ("ok", True) and r.mode("observe") == "observe"


@pytest.mark.usefixtures("control_identity")
def test_the_ingest_refusal_names_the_reason(tmp_path, capsys, monkeypatch):
    from forgd_verdict.cli import main

    monkeypatch.setattr("forgd_verdict.compliance.ingest.run_ingest", lambda *a, **k: {})
    monkeypatch.setattr("forgd_verdict.managed.scanner.run_managed_ingest", lambda *a, **k: {})
    root = tmp_path / "s"
    s = LocalFileStore(root, instance="t")
    apply_change(s, ADMIN, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _mode(s, writer="999.0.0")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "compliance": {"api_key": "sk-ant-admin01-" + "x" * 20},
        "dashboard": {"admins": {"groups": [{"group": "ops"}]}},
        "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}))
    assert main(["--policy", str(policy), "ingest", "--store", str(root)]) == 1
    err = capsys.readouterr().err
    assert "refusing to ingest: the runtime overrides need a newer forgd-verdict release" in err


@pytest.mark.usefixtures("control_identity")
async def test_a_service_below_the_version_answers_readyz_503_and_healthz_200(
        tmp_path, monkeypatch):
    from forgd_verdict.server.app import VerdictServer

    root = tmp_path / "s"
    s = LocalFileStore(root, instance="seed")
    apply_change(s, ADMIN, Change(ACTION_INIT), detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    _mode(s, writer="999.0.0")
    server = VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": None,
                "store": str(root), "store_flush_s": 3600},
        dashboard={"admins": {"groups": [{"group": "ops"}]}},
        overrides={"verify_keys": [OVERRIDES_PUBLIC_TEXT]}))
    try:
        assert server.mode == "observe"
        status, body = await ASGIClient(server).get("/readyz")
        assert (status, body["reason"]) == (
            503, "runtime overrides need a newer forgd-verdict release")
        assert (await ASGIClient(server).get("/healthz"))[0] == 200
        assert server._metrics_body()["runtime_overrides"]["in_error"] == 1
    finally:
        server.close()


def test_the_dashboard_banner_says_why(store):
    from forgd_verdict.dashboard.controls import banners

    _mode(store, writer="999.0.0")
    page = banners(_reader(store, "1.0.0").refresh(), "observe")
    assert "need a newer forgd-verdict release" in page
