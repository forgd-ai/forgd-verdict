"""A gitleaks scan that stops at `max_bytes` raises `ScanTruncated`."""

from __future__ import annotations

import copy
import shutil

import pytest
from conftest import GITLEAKS_FIXTURES

from forgd_verdict.core import decide, scan
from forgd_verdict.detectors.base import DetectorFailed
from forgd_verdict.detectors.gitleaks import GitleaksDetector, _join
from forgd_verdict.models import UNSCANNED_CAPPED, ScanUnit
from forgd_verdict.policy import DEFAULT_POLICY, Policy

# Multi-MiB inputs through real gitleaks: alone, after the parallel suite.
pytestmark = pytest.mark.serial

PAT = GITLEAKS_FIXTURES["gitlab-pat"]
needs_gitleaks = pytest.mark.skipif(shutil.which("gitleaks") is None, reason="needs gitleaks")


def _units(*texts):
    return [ScanUnit(locator=f"u{i}", tool_name=None, text=t) for i, t in enumerate(texts)]


def _truncated_class():
    from forgd_verdict.detectors.base import ScanTruncated
    return ScanTruncated


class _Reported(GitleaksDetector):
    """A daemon-path detector whose report is a finding on every line given."""

    def __init__(self, lines, **kw):
        super().__init__(daemon="/nonexistent.sock", **kw)
        self._lines = lines
        self.streams: list[str] = []

    def _run(self, stream):
        self.streams.append(stream)
        return [{"StartLine": n, "RuleID": "r", "Secret": "s"} for n in self._lines]


def test_a_hit_after_the_cut_raises_with_its_findings_and_the_scanned_count():
    ScanTruncated = _truncated_class()
    det = _Reported([1], max_bytes=100)
    with pytest.raises(ScanTruncated) as caught:
        det.scan(_units("a" * 40, "b" * 40, "c" * 40, "d" * 40))
    assert issubclass(ScanTruncated, DetectorFailed)
    assert caught.value.scanned == 2
    assert [f.locator for f in caught.value.findings] == ["u2"]
    assert det.streams == ["c" * 40 + "\n" + "d" * 40]


def test_a_cut_with_no_hit_raises_with_no_findings():
    ScanTruncated = _truncated_class()
    with pytest.raises(ScanTruncated) as caught:
        _Reported([], max_bytes=100).scan(_units("a" * 60, "b" * 60))
    assert caught.value.findings == [] and caught.value.scanned == 1


def test_one_oversized_unit_raises_having_scanned_nothing():
    ScanTruncated = _truncated_class()
    det = _Reported([1], max_bytes=10)
    with pytest.raises(ScanTruncated) as caught:
        det.scan(_units("x" * 50))
    assert caught.value.scanned == 0 and caught.value.findings == []
    assert det.streams == []


def test_the_separators_count_toward_max_bytes():
    """Three 10-byte units are 32 bytes once joined with newlines."""
    stream, line_map = _join(_units("a" * 10, "b" * 10, "c" * 10), 30)
    assert len(stream.encode()) <= 30
    assert len(line_map["bounds"]) == 2
    ScanTruncated = _truncated_class()
    with pytest.raises(ScanTruncated) as caught:
        _Reported([], max_bytes=30).scan(_units("a" * 10, "b" * 10, "c" * 10))
    assert caught.value.scanned == 2


def test_a_scan_that_fits_returns_its_findings():
    det = _Reported([2], max_bytes=32)
    assert [f.locator for f in det.scan(_units("a" * 10, "b" * 10, "c" * 10))] == ["u1"]


def test_the_detector_keeps_no_per_scan_state():
    det = _Reported([], max_bytes=100)
    with pytest.raises(DetectorFailed):
        det.scan(_units("a" * 60, "b" * 60))
    assert not hasattr(det, "truncated")


def test_core_scan_keeps_the_scanned_findings_and_records_the_tier_and_the_cap():
    """The three units, their two 80-byte pair seams and the 120-byte seam
    across all three are 405 bytes joined; 330 leaves out the first two
    units, so line 1 is the third."""
    r = scan(_units("a" * 40, "b" * 40, "c" * 40), [_Reported([1], max_bytes=330, severity="block")])
    assert [f.locator for f in r.findings] == ["u2"]
    assert r.detectors_skipped == ["gitleaks", UNSCANNED_CAPPED]
    assert r.detectors_run == []


@needs_gitleaks
def test_a_secret_after_the_cut_still_denies_under_the_default_policy():
    """`on_tier_dropped` defaults to allow, so a truncated tier whose
    findings were dropped would let the request through."""
    det = GitleaksDetector(severity="block", max_bytes=3010, timeout_s=30.0)
    r = scan(_units("x" * 5000, f"token {PAT}"), [det])
    assert {f.detector for f in r.findings} == {"gitleaks:gitlab-pat"}
    assert decide(r.findings, Policy(raw=copy.deepcopy(DEFAULT_POLICY)), dropped=r.detectors_skipped).action == "deny"


@needs_gitleaks
def test_a_prompt_over_max_bytes_with_a_gitleaks_secret_after_the_cut_is_denied():
    """`on_tier_dropped` defaults to allow, so a verdict-path prompt whose
    only match is gitleaks' and sits after the cut is denied only if the
    truncated tier's findings are kept."""
    from forgd_verdict.budget import Budget
    from forgd_verdict.core import scan_frame
    from forgd_verdict.detectors.base import TIER_T0
    from forgd_verdict.detectors.gitleaks import DEFAULT_MAX_BYTES
    from forgd_verdict.extract import MAX_UNIT_BYTES, frame_units

    policy = Policy(raw=copy.deepcopy(DEFAULT_POLICY))
    assert policy.on_tier_dropped == "allow"
    detectors = policy.build_detectors()
    (gl,) = [d for d in detectors if d.name == "gitleaks"]
    assert gl.max_bytes == DEFAULT_MAX_BYTES and not gl.uses_daemon

    def text(t):
        return {"role": "user", "content": [{"type": "text", "text": t}]}

    pad = ("the quick brown fox jumps over the lazy dog " * (MAX_UNIT_BYTES // 44))[:MAX_UNIT_BYTES - 1]
    messages = [*(text(pad) for _ in range(3)), text(f"token {PAT}")]
    assert 3 * len(pad) > DEFAULT_MAX_BYTES
    t0 = [d for d in detectors if d.tier == TIER_T0]
    assert scan(frame_units(messages[-1:], 3), t0).findings == []

    r = scan_frame(messages, frame_units, detectors, Budget(600_000))
    assert "gitleaks" in r.detectors_skipped
    assert {f.detector for f in r.findings} == {"gitleaks:gitlab-pat"}
    assert decide(r.findings, policy, dropped=r.detectors_skipped).action == "deny"
