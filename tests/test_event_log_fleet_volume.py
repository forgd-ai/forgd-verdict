"""At fleet volume, one laptop's deny a week back is on the first filtered page."""

from __future__ import annotations

import time

import pytest

from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import SOURCE_CODE_HOOK, FindingRow, VerdictRecord
from forgd_verdict.store.views import EVENT_SCAN_BUDGET, event_page

pytestmark = pytest.mark.serial

DAYS = [f"2026-10-0{d}" for d in range(1, 8)]
PER_DAY = 25_000
TARGET = "d0000000003e7"


def _day(day: str):
    out = []
    for i in range(PER_DAY):
        out.append(VerdictRecord(
            source=SOURCE_CODE_HOOK, observed_at=f"{day}T{8 + i % 10:02d}:{i % 60:02d}:00Z",
            device=f"d{i % 900:012x}", client="laptops", tenant_hash="org_aaaaaaaaaa",
            session_id=f"00000000-0000-4000-8000-{i % 1800:012d}",
            request_id=f"PreToolUse:{day}:{i}", action="allow", tally=3))
    return out


def test_one_devices_deny_a_week_back_is_on_the_first_page(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    for day in DAYS:
        batch = _day(day)
        if day == DAYS[0]:
            batch.append(VerdictRecord(
                source=SOURCE_CODE_HOOK, observed_at=f"{day}T09:30:00Z", device=TARGET,
                client="laptops", tenant_hash="org_aaaaaaaaaa", request_id="the-deny",
                action="deny", findings=[FindingRow("regex:aws-access-key", "block",
                                                    "c", "h")], findings_count=1))
        for i in range(0, len(batch), 500):
            store.write_verdicts(batch[i:i + 500])
    assert len(DAYS) * PER_DAY > EVENT_SCAN_BUDGET
    started = time.perf_counter()
    page = event_page(store, None, None, device=TARGET, hide_code_hook_allows=True)
    elapsed = time.perf_counter() - started
    assert [r.request_id for r in page.records] == ["the-deny"]
    assert elapsed < 10
