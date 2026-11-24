"""A service started with no findings store says so, and counts what it skips."""

from __future__ import annotations

import logging

import pytest
from conftest import make_policy
from test_store import rec

from forgd_verdict.intake.app import Intake
from forgd_verdict.otel.app import Collector
from forgd_verdict.server.app import VerdictServer
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.sink import StoreSink

WARNING = "has no findings store"


def test_a_storeless_sink_counts_every_record_it_skips():
    sink = StoreSink(None)
    sink.submit({"verdict": "allow"})
    assert sink.submit_record(rec()) is True
    assert sink.submit_records([rec(), rec()]) is True
    assert sink.skipped == 4
    assert sink.submit_records([]) is True
    assert sink.skipped == 4
    assert sink.stats()["skipped"] == 4
    assert sink.dropped == 0 and sink.errors == 0


def test_a_sink_with_a_store_skips_nothing(tmp_path):
    sink = StoreSink(LocalFileStore(tmp_path, instance="t"))
    try:
        assert sink.submit_record(rec())
        assert sink.stats()["skipped"] == 0
    finally:
        sink.close()


def _server(policy, store):
    return VerdictServer(policy, logger=logging.getLogger("test.storeless"), store=store)


def _collector(_policy, store):
    return Collector(make_policy(), logger=logging.getLogger("test.storeless"), store=store)


def _intake(_policy, store):
    return Intake(make_policy(), store=store)


# Intake logs through the module logger, the other two through the one passed in.
SERVICES = [
    pytest.param(_server, "test.storeless", "verdict has", "set server.store (", id="server"),
    pytest.param(_collector, "test.storeless", "collector has", "set otel.store, or server.store",
                 id="collector"),
    pytest.param(_intake, "forgd_verdict", "intake has", "set intake.store, or server.store",
                 id="intake"),
]


@pytest.mark.parametrize(("build", "logger", "name", "remediation"), SERVICES)
def test_a_storeless_service_warns_naming_itself_and_its_store_key(
        caplog, policy, build, logger, name, remediation):
    with caplog.at_level(logging.WARNING, logger=logger):
        build(policy, None).close()
    [record] = [r for r in caplog.records if WARNING in r.getMessage()]
    assert record.getMessage().startswith(name)
    assert record.fields["remediation"].startswith(remediation)


@pytest.mark.parametrize(("build", "logger", "name", "remediation"), SERVICES)
def test_a_service_with_a_store_does_not_warn(caplog, policy, tmp_path, build, logger, name,
                                              remediation):
    with caplog.at_level(logging.WARNING, logger=logger):
        build(policy, LocalFileStore(tmp_path / "s", instance="t")).close()
    assert WARNING not in caplog.text


def test_the_server_metrics_show_skipped_records(policy):
    app = _server(policy, None)
    try:
        app.sink.submit_record(rec())
        assert app._metrics_body()["store"]["skipped"] == 1
    finally:
        app.close()


def test_the_collector_stats_show_skipped_records(policy):
    app = _collector(policy, None)
    try:
        app.sink.submit_record(rec())
        assert app.stats()["store"]["skipped"] == 1
    finally:
        app.close()


def test_the_intake_stats_show_skipped_records(policy):
    app = _intake(policy, None)
    try:
        app.sink.submit_record(rec())
        assert app.stats()["store"]["skipped"] == 1
    finally:
        app.close()


async def test_a_storeless_intake_counts_a_scan_as_skipped():
    from test_intake_store_sink import _policy, _scan

    app = Intake(_policy(), store=None)
    try:
        assert (await _scan(app))[0] == 200
        assert app.stats()["store"]["skipped"] == 1
    finally:
        app.close()
