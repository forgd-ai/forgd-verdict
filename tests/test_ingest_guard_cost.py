"""What cleaning an ingest pass's records costs, counted against its reports."""

from __future__ import annotations

import collections
import dataclasses
import logging
from types import SimpleNamespace

from conftest import FAKE_AWS_KEY

import forgd_verdict.compliance.ingest as compliance
import forgd_verdict.managed.scanner as managed
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store.base import VerdictRecord

SALT = "test-salt"
KEY = "sk-ant-api03-" + "x" * 90


def _report(i: int):
    return SimpleNamespace(i=i, action="deny" if i % 4 == 0 else "allow",
                           artifacts_scanned=0, artifacts_failed=0, content_read=True)


def _to_record(source: str):
    def convert(report, salt, owner):
        return VerdictRecord(source=source, session_id=f"s-{report.i}",
                             model=FAKE_AWS_KEY if report.i % 3 == 0 else "claude-x",
                             surface="claude-code", request_id=f"r-{report.i}")
    return convert


class Store:
    def __init__(self) -> None:
        self.verdicts: list[VerdictRecord] = []

    def write_verdicts(self, batch) -> int:
        self.verdicts.extend(batch)
        return len(batch)


def _count_guard(monkeypatch) -> collections.Counter:
    calls: collections.Counter[str] = collections.Counter()
    real = MetadataGuard.matches

    def matches(self, values):
        calls["matches"] += 1
        return real(self, values)

    monkeypatch.setattr(MetadataGuard, "matches", matches)
    return calls


def _untimed(records: list[VerdictRecord]) -> list[VerdictRecord]:
    """`observed_at` is the second each record was built, which differs between
    the run and the expectation built after it."""
    return [dataclasses.replace(r, observed_at="") for r in records]


def _expected(raw: list[VerdictRecord], detectors) -> list[VerdictRecord]:
    guard = MetadataGuard(detectors, SALT, allow_subprocess=True)
    return [guard.record(r) for r in raw]


def _compliance(n: int, monkeypatch, caplog):
    detectors = [T0RegexDetector()]

    class Scanner:
        org_id = "org-a"
        sessions_failed = chats_failed = 0

        def __init__(self, policy, org=None, store=None, detectors=None):
            self.detectors = detectors_

        def scan_sessions(self, **kw):
            return (_report(i) for i in range(n))

        def scan_chats(self, **kw):
            return (_report(n + i) for i in range(n))

        def denials(self, **kw):
            return iter(())

        def commit(self):
            pass

    detectors_ = detectors
    monkeypatch.setattr(compliance, "ComplianceScanner", Scanner)
    monkeypatch.setattr(compliance, "report_to_record", _to_record("compliance"))
    monkeypatch.setattr(compliance, "chat_to_record", _to_record("compliance-chat"))
    store = Store()
    with monkeypatch.context() as m:
        calls = _count_guard(m)
        compliance._ingest_one_org(
            SimpleNamespace(hash_salt=SALT), store, {"id": "org-a", "label": "a"},
            families=["code"], since=None, max_sessions=None, include_denials=False,
            include_chats=True, batch_size=1_000)
    raw = ([_to_record("compliance")(_report(i), SALT, "") for i in range(n)]
           + [_to_record("compliance-chat")(_report(n + i), SALT, "") for i in range(n)])
    return calls["matches"], store.verdicts, _expected(raw, detectors)


def _managed(n: int, monkeypatch):
    detectors = [T0RegexDetector()]

    class Scanner:
        failed = 0

        def __init__(self, policy, ws, store=None, detectors=None):
            self.detectors = detectors_

        def scan(self, **kw):
            return (_report(i) for i in range(n))

        def commit(self):
            pass

    detectors_ = detectors
    monkeypatch.setattr(managed, "ManagedScanner", Scanner)
    monkeypatch.setattr(managed, "report_to_record", _to_record("managed"))
    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": SALT},
        "detectors": {"gitleaks": {"timeout_ms": 60000}},
        "managed_agents": {"workspaces": [{"key": "a", "label": "a", "api_key": KEY}]}}))
    store = Store()
    with monkeypatch.context() as m:
        calls = _count_guard(m)
        summary = managed.run_managed_ingest(policy, store, batch_size=1_000)
    assert summary["workspaces"][0]["ok"], summary
    raw = [_to_record("managed")(_report(i), SALT, "") for i in range(n)]
    return calls["matches"], store.verdicts, _expected(raw, detectors)


def _clean(caplog) -> None:
    logged = "\n".join(f"{r.getMessage()} {getattr(r, 'fields', '')}" for r in caplog.records)
    assert FAKE_AWS_KEY not in logged


def test_compliance_ingest_cleans_its_records_in_a_fixed_number_of_guard_calls(
        monkeypatch, caplog):
    logging.getLogger("forgd_verdict").addHandler(caplog.handler)
    try:
        few, _, _ = _compliance(5, monkeypatch, caplog)
        many, written, expected = _compliance(50, monkeypatch, caplog)
    finally:
        logging.getLogger("forgd_verdict").removeHandler(caplog.handler)
    assert many == few, f"5 reports: {few} guard calls  50 reports: {many}"
    assert _untimed(written) == _untimed(expected)
    assert FAKE_AWS_KEY not in repr(written)
    _clean(caplog)


def test_managed_ingest_cleans_its_records_in_a_fixed_number_of_guard_calls(
        monkeypatch, caplog):
    logging.getLogger("forgd_verdict").addHandler(caplog.handler)
    try:
        few, _, _ = _managed(5, monkeypatch)
        many, written, expected = _managed(50, monkeypatch)
    finally:
        logging.getLogger("forgd_verdict").removeHandler(caplog.handler)
    assert many == few, f"5 reports: {few} guard calls  50 reports: {many}"
    assert _untimed(written) == _untimed(expected)
    assert FAKE_AWS_KEY not in repr(written)
    _clean(caplog)
