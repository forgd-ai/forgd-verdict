"""`screen` names detectors that did not run, and words each scan marker."""

from __future__ import annotations

import pytest

from forgd_verdict import core
from forgd_verdict.detectors.base import TIER_T0, DetectorFailed
from forgd_verdict.models import MAX_SCAN_UNITS, Finding
from forgd_verdict.overrides import Refused, screen

VALUE = "synthetic-value-0001"


class _Flood:
    name, tier = "flood", TIER_T0

    def scan(self, units):
        return [Finding("flood:hit", "warn", u.locator, f"h{i}-{k}")
                for i, u in enumerate(units) for k in range(5)]


class _Blind:
    name, tier = "blind", TIER_T0

    def scan(self, units):
        return []


class _Broken:
    name, tier = "broken", TIER_T0

    def scan(self, units):
        raise DetectorFailed("down")


def _refusal(values, detectors) -> str:
    with pytest.raises(Refused) as exc:
        screen(values, detectors)
    return str(exc.value)


def test_a_findings_cap_is_worded_as_one(monkeypatch):
    monkeypatch.setattr(core, "MAX_SCAN_FINDINGS", 2)
    message = _refusal([VALUE], [_Flood()])
    assert "too many findings to review" in message
    assert "findings:capped" not in message
    assert "did not run" not in message
    assert VALUE not in message


def test_a_failed_detector_and_a_marker_are_worded_apart(monkeypatch):
    monkeypatch.setattr(core, "MAX_SCAN_FINDINGS", 2)
    message = _refusal([VALUE], [_Flood(), _Broken()])
    assert "broken did not run" in message
    assert "too many findings to review" in message
    assert "findings:capped" not in message
    assert VALUE not in message


def test_values_over_the_unit_cap_are_worded_as_the_size_limit():
    message = _refusal([f"v{i}" for i in range(MAX_SCAN_UNITS + 1)], [_Blind()])
    assert "over the size limit for scanning" in message
    assert "unscanned:capped" not in message
    assert "did not run" not in message
