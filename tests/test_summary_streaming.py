"""build_summary reads a week of fleet records without holding them all."""

from __future__ import annotations

import tracemalloc

import pytest

from forgd_verdict.store.base import SOURCE_CODE_HOOK, SOURCE_COMPLIANCE_SCAN, VerdictRecord
from forgd_verdict.store.query import build_summary

pytestmark = pytest.mark.serial


def _records(n: int):
    for i in range(n):
        yield VerdictRecord(source=SOURCE_CODE_HOOK, observed_at="2026-10-05T10:00:00Z",
                            session_id=f"s{i % 1000}", surface="claude-code-local",
                            tenant_hash="org_aaaaaaaaaa", device="d000000000001",
                            request_id=f"r{i}")
    for i in range(10):
        yield VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, session_id="same",
                            observed_at=f"2026-10-05T1{i}:00:00Z")


def test_a_summary_over_200k_records_stays_small():
    tracemalloc.start()
    try:
        s = build_summary(_records(200_000), orgs=None)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert s.hook_decisions == 200_000
    assert s.scanned_sessions == 1
    assert peak < 32 * 1024 * 1024
