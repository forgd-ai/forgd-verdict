"""A device, client or detector filter finds its rows within a bounded read.

The Event Log read 20,000 records a page, so at fleet volume a filter for
one laptop gave "No events found on this page" and eight pages of Older to
reach its deny, which is the revoke path in deploy/MDM.md. A filtered page
now skips objects and lines that cannot hold the value before parsing them,
and reads only the sources that carry it.
"""

from __future__ import annotations

import random

import pytest

from forgd_verdict.store import LocalFileStore, views
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_INFERENCE_HOOK,
    SOURCE_OTEL_COLLECT,
    FindingRow,
    VerdictRecord,
)
from forgd_verdict.store.views import event_page


def _rec(i: int, day: str, device: str, action="allow", source=SOURCE_CODE_HOOK,
         detector="regex:aws-access-key"):
    findings = [FindingRow(detector, "block", "c", f"h{i}")] if action == "deny" else []
    return VerdictRecord(source=source, observed_at=f"{day}T{i % 24:02d}:00:{i % 60:02d}Z",
                         device=device if source == SOURCE_CODE_HOOK else None,
                         client="laptops" if source == SOURCE_CODE_HOOK else None,
                         tenant_hash="org_aaaaaaaaaa", request_id=f"r{day}-{i}",
                         action=action, findings=findings, findings_count=len(findings))


def _store(tmp_path, n_per_day=300, days=("2026-10-01", "2026-10-02", "2026-10-03")):
    rng = random.Random(7)
    s = LocalFileStore(tmp_path / "s", instance="t")
    for day in days:
        batch = []
        for i in range(n_per_day):
            source = rng.choice([SOURCE_CODE_HOOK, SOURCE_CODE_HOOK, SOURCE_OTEL_COLLECT,
                                 SOURCE_INFERENCE_HOOK])
            device = f"d{rng.randrange(20):012x}"
            action = "deny" if rng.random() < 0.05 else "allow"
            batch.append(_rec(i, day, device, action, source,
                              rng.choice(["regex:aws-access-key", "regex:us-ssn"])))
        for i in range(0, len(batch), 50):
            s.write_verdicts(batch[i:i + 50])
    return s


def _walk(store, **kw):
    """Every row of every page, following `before`."""
    rows, before, pages = [], None, 0
    while True:
        page = event_page(store, None, None, before=before, **kw)
        rows += [r.request_id for r in page.records]
        pages += 1
        if page.before is None:
            return rows, pages
        before = page.before


@pytest.mark.parametrize("kw", [
    {"device": "d000000000003"},
    {"device": "d000000000003", "action": "deny"},
    {"detector": "regex:us-ssn"},
    {"client": "laptops", "detector": "regex:aws-access-key"},
    {"device": "d000000000003", "hide_code_hook_allows": True},
])
def test_a_filtered_walk_finds_exactly_the_rows_an_unfiltered_read_would(tmp_path, kw):
    store = _store(tmp_path)
    expected = [r.request_id for r in sorted(
        (r for r in store.read_verdicts() if views._event_filter(
            None, kw.get("source", "all"), kw.get("action", "all"), kw.get("client", ""),
            kw.get("device", ""), kw.get("detector", ""),
            kw.get("hide_code_hook_allows", False))(r)),
        key=lambda r: views.event_time_key(r.observed_at), reverse=True)]
    got, _ = _walk(store, limit=7, **kw)
    assert sorted(got) == sorted(expected)
    assert len(got) == len(set(got))


def test_a_value_json_would_escape_is_still_found(tmp_path):
    s = LocalFileStore(tmp_path / "s", instance="t")
    s.write_verdicts([_rec(1, "2026-10-01", "d000000000001", "deny",
                           detector='plugin:café"x')])
    page = event_page(s, None, None, detector='plugin:café"x')
    assert [r.request_id for r in page.records] == ["r2026-10-01-1"]


def test_a_device_filter_reads_only_the_intakes_sources(tmp_path, monkeypatch):
    store = _store(tmp_path)
    fetched = []
    real = LocalFileStore._object

    def spy(self, rel):
        fetched.append(rel)
        return real(self, rel)

    monkeypatch.setattr(LocalFileStore, "_object", spy)
    event_page(store, None, None, device="d000000000003")
    assert fetched
    assert all(f"source={SOURCE_CODE_HOOK}" in k for k in fetched)


def test_the_byte_budget_ends_a_page_and_the_next_resumes_without_loss(tmp_path):
    store = _store(tmp_path)
    full, _ = _walk(store, device="d000000000003")
    small, pages = _walk(store, device="d000000000003", byte_budget=4096)
    assert sorted(small) == sorted(full)
    assert pages > 1
