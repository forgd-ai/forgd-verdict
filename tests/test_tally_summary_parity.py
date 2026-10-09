"""The summary over Code hook records and over the same records tallied
gives the same counts, and the session join reads only OTel partitions.

Records are shaped as the intake keeps them: a shipped record carries no
`cache_hit`, `budget_exceeded`, shadow action or timing
(`test_intake_shipped_hook_form.py`).
"""

from __future__ import annotations

import dataclasses
import pathlib
import random

from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.attribution import session_orgs
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_INFERENCE_HOOK,
    SOURCE_OTEL_COLLECT,
    FindingRow,
    VerdictRecord,
)
from forgd_verdict.store.query import build_summary
from forgd_verdict.store.tally import tallied

A, B = "org_aaaaaaaaaa", "org_bbbbbbbbbb"
COUNTS = ("total_requests", "total_findings", "hook_decisions", "orgs", "per_day",
          "would_deny", "enforced_deny", "cache_hits", "cache_misses", "budget_exceeded",
          "detections", "distinct_values")


def _records(n: int, seed: int = 1):
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        day = f"2026-10-0{1 + i % 5}"
        clean = rnd.random() < 0.9
        out.append(VerdictRecord(
            source=SOURCE_CODE_HOOK, observed_at=f"{day}T{i % 24:02d}:{i % 60:02d}:00Z",
            device=f"d{i % 9:012x}", client="laptops", tenant_hash=A if i % 3 else B,
            session_id=f"00000000-0000-4000-8000-{i % 7:012d}", surface="claude-code-local",
            request_id=f"PreToolUse:{day}:{i}", action="allow" if clean else "deny",
            tiers_dropped=[] if rnd.random() < 0.95 else ["gitleaks"],
            findings=[] if clean else [FindingRow("regex:aws-access-key", "block", "c", "h")],
            findings_count=0 if clean else 1))
    return out


def test_the_summary_over_tally_rows_matches_the_summary_over_records():
    raw = _records(2000)
    folded = tallied(list(raw))
    assert len(folded) < len(raw)
    a = dataclasses.asdict(build_summary(list(raw)))
    b = dataclasses.asdict(build_summary(folded))
    diffs = {k: (a.get(k), b.get(k)) for k in COUNTS if a.get(k) != b.get(k)}
    assert not diffs, diffs


def test_the_join_reads_only_otel_partitions(tmp_path, monkeypatch):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([VerdictRecord(
        source=SOURCE_CODE_HOOK, observed_at="2026-10-05T10:00:00Z", tenant_hash=A,
        request_id=f"r{i}", action="allow", tally=5) for i in range(3000)])
    store.write_verdicts([VerdictRecord(
        source=SOURCE_INFERENCE_HOOK, observed_at="2026-10-05T10:00:00Z", tenant_hash=A,
        request_id="inf", action="allow")])
    store.write_verdicts([VerdictRecord(
        source=SOURCE_OTEL_COLLECT, observed_at="2026-10-05T10:00:00Z", tenant_hash=A,
        session_id="11111111-2222-3333-4444-555555555555", surface="claude-code",
        request_id="o1", action="allow")])
    reads: list[str] = []
    real = pathlib.Path.read_bytes

    def spy(self):
        reads.append(str(self))
        return real(self)

    monkeypatch.setattr(pathlib.Path, "read_bytes", spy)
    joins = session_orgs(store, "2026-10-05T00:00:00Z")
    assert joins == {"11111111-2222-3333-4444-555555555555": A}
    assert reads and all("source=otel_collect" in p for p in reads), reads
