"""A shipped record's enum, id and count fields are held to what the hook writes.

A fleet token is shared by every laptop, so each field a shipped record
sets is a field any one of them can set to anything. The guard already
replaces secret-shaped and over-long text; these pin the shape checks
behind it: an action outside allow/deny refuses the record, and every
other field outside its shape is replaced or recomputed.
"""

from __future__ import annotations

import pytest
from test_intake_fleet import org_env  # noqa: F401
from test_intake_writer_fields import _hook_rec, _ship

from forgd_verdict.store.base import FindingRow
from forgd_verdict.store.query import build_summary


async def test_an_action_outside_allow_and_deny_refuses_the_record(tmp_path):
    status, stored = await _ship(tmp_path, _hook_rec(action="maybe"),
                                 _hook_rec(action="deny"))
    assert status == 200
    assert [r.action for r in stored] == ["deny"]


@pytest.mark.parametrize("shadow", ["sometimes", "DENY", "x" * 100, "deny", "allow"])
async def test_a_shadow_action_is_dropped(tmp_path, shadow):
    # The hook enforces its deny and never writes one.
    _, [stored] = await _ship(tmp_path, _hook_rec(action="allow", shadow_action=shadow))
    assert stored.shadow_action is None


@pytest.mark.parametrize("ref", ["fv scan with spaces", "fv_" + "a" * 60, "fv_<b>_x"])
async def test_a_reference_id_outside_anthropics_charset_is_dropped(tmp_path, ref):
    _, [stored] = await _ship(tmp_path, _hook_rec(reference_id=ref))
    assert stored.reference_id is None


async def test_a_hook_reference_id_is_kept(tmp_path):
    ref = "fv_aws-access_01J9Z3Y8W7V6T5S4R3Q2P1N0MK"
    _, [stored] = await _ship(tmp_path, _hook_rec(reference_id=ref))
    assert stored.reference_id == ref


@pytest.mark.parametrize("ns", ["anything I like", "d" + "0" * 40, "../etc"])
async def test_a_salt_namespace_not_in_the_hook_form_is_the_device_default(tmp_path, ns):
    _, [stored] = await _ship(tmp_path, _hook_rec(salt_namespace=ns))
    assert stored.salt_namespace == "corp-laptops:device"


async def test_a_hook_salt_namespace_is_kept_under_the_writer(tmp_path):
    _, [stored] = await _ship(tmp_path, _hook_rec(salt_namespace="d0123456789ab"))
    assert stored.salt_namespace == "corp-laptops:d0123456789ab"


async def test_tiers_dropped_keeps_only_tier_shaped_names_and_is_bounded(tmp_path):
    tiers = ["gitleaks", "unscanned:oversize", "free text here", "a" * 200,
             *[f"t{i}" for i in range(100)]]
    _, [stored] = await _ship(tmp_path, _hook_rec(tiers_dropped=tiers))
    assert stored.tiers_dropped[:2] == ["gitleaks", "unscanned:oversize"]
    assert "free text here" not in stored.tiers_dropped
    assert all(len(t) <= 64 for t in stored.tiers_dropped)
    assert len(stored.tiers_dropped) <= 32


async def test_findings_count_is_the_number_of_findings(tmp_path):
    _, [stored] = await _ship(tmp_path, _hook_rec(findings_count=2**53))
    assert stored.findings_count == len(stored.findings) == 1


async def test_an_inflated_findings_count_cannot_move_the_summary(tmp_path):
    _, stored = await _ship(tmp_path, _hook_rec(findings_count=2**53),
                            _hook_rec(findings_count=-5))
    assert build_summary(stored).total_findings == 2


@pytest.mark.parametrize("field,value", [
    ("body_bytes", 2**53), ("body_bytes", -1), ("messages_total", 2**40),
    ("messages_scanned", -3), ("scan_ms", 1e15), ("total_ms", -1.0),
])
async def test_counts_and_timings_out_of_range_are_dropped(tmp_path, field, value):
    _, [stored] = await _ship(tmp_path, _hook_rec(**{field: value}))
    assert getattr(stored, field) is None


async def test_counts_and_timings_in_range_are_dropped_too(tmp_path):
    # The hook writes none of them.
    _, [stored] = await _ship(tmp_path, _hook_rec(scan_ms=12.5, messages_total=3))
    assert (stored.scan_ms, stored.messages_total) == (None, None)


async def test_a_finding_severity_outside_block_and_warn_is_warn(tmp_path):
    rec = _hook_rec(findings=[FindingRow("regex:aws-access-key", "critical!!", "cmd", "h1")])
    _, [stored] = await _ship(tmp_path, rec)
    assert stored.findings[0].severity == "warn"


@pytest.mark.parametrize("detector", ["not a detector name", "", "x" * 300])
async def test_a_finding_detector_outside_the_name_form_is_replaced(tmp_path, detector):
    rec = _hook_rec(findings=[FindingRow(detector, "block", "cmd", "h1")])
    _, [stored] = await _ship(tmp_path, rec)
    assert stored.findings[0].detector == "unknown"


@pytest.mark.parametrize("tool", ["Bash; rm -rf /", "x" * 300])
async def test_a_finding_tool_name_outside_the_name_form_is_dropped(tmp_path, tool):
    rec = _hook_rec(findings=[FindingRow("regex:aws-access-key", "block", "cmd", "h1", tool)])
    _, [stored] = await _ship(tmp_path, rec)
    assert stored.findings[0].tool_name is None


async def test_a_record_holds_at_most_the_scan_findings_cap(tmp_path):
    from forgd_verdict.core import MAX_SCAN_FINDINGS

    rows = [FindingRow("regex:aws-access-key", "block", f"c{i}", "h1")
            for i in range(MAX_SCAN_FINDINGS + 10)]
    _, [stored] = await _ship(tmp_path, _hook_rec(findings=rows))
    assert len(stored.findings) == stored.findings_count == MAX_SCAN_FINDINGS
