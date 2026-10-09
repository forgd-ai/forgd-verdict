"""A credential split across a dict key and the unit beside it.

A seam finding is located at the first unit its match lies in and carries
the others' locators in `seam_others`. When either side is a `#key` unit, that key
holds half of the credential, and its path must be redacted in every
locator the scan reports.
"""

from __future__ import annotations

import json

from conftest import FAKE_AWS_KEY

from forgd_verdict import extract
from forgd_verdict.core import REDACTED, decide, scan
from forgd_verdict.extract import hook_units
from forgd_verdict.policy import load_policy

SALT = "seam-key-test-salt-0123456789"
LEFT, RIGHT = "AKIAQYLPMN5", "HHHFPBCDE"  # gitleaks:allow


def _scan(tool_input):
    policy = load_policy("policy.yaml")
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "mcp__x__y",
                        "tool_input": tool_input})
    result = scan(units, policy.build_detectors(salt=SALT))
    return result, decide(result.findings, policy)


def _assert_no_half(result, verdict):
    assert verdict.action == "deny"
    seams = [f for f in result.findings if f.seam_others]
    assert seams, "the split key was not found on a seam"
    exposed = [
        *(f.locator for f in result.findings),
        *(o for f in seams for o in f.seam_others),
        *(json.dumps(f.to_log()) for f in result.findings),
        *result.truncated,
        verdict.reference_id or "",
        verdict.deny_reason or "",
    ]
    for half in (LEFT, RIGHT):
        for text in exposed:
            assert half not in text, text


def test_a_key_holding_the_first_half_is_redacted():
    result, verdict = _scan({"x": {f"zzzz {LEFT}": f"{RIGHT} tail"}})
    _assert_no_half(result, verdict)
    assert f"tool_input.x.{REDACTED}#key" in {f.locator for f in result.findings}


def test_a_key_holding_the_second_half_is_redacted():
    tail_key = f"{RIGHT} and the rest"
    result, verdict = _scan({"x": {"a": f"zzzz {LEFT}",
                                   tail_key: f"key {FAKE_AWS_KEY}"}})
    _assert_no_half(result, verdict)
    # The finding on the value under that key is located under the redacted path.
    assert f"tool_input.x.{REDACTED}" in {f.locator for f in result.findings}


def test_a_truncated_value_under_a_matched_key_is_logged_redacted(monkeypatch):
    monkeypatch.setattr(extract, "MAX_UNIT_BYTES", 64)
    monkeypatch.setattr(extract, "TAIL_UNIT_BYTES", 16)
    result, verdict = _scan({"x": {f"zzzz {LEFT}": f"{RIGHT} tail " + "y" * 200}})
    assert result.truncated == [f"tool_input.x.{REDACTED}"]
    _assert_no_half(result, verdict)


def test_a_split_beside_the_same_key_whole_is_still_redacted():
    # The value also holds the whole key, so a span-less detector finds the
    # seam's excerpt on the right side alone. t0_regex reports a span that
    # crosses the join.
    result, verdict = _scan({"x": {f"zzzz {LEFT}": f"{RIGHT} x {LEFT}{RIGHT}"}})
    _assert_no_half(result, verdict)
    assert f"tool_input.x.{REDACTED}#key" in {f.locator for f in result.findings}


def test_a_split_into_the_next_key_beside_the_same_key_whole_is_still_redacted():
    tail_key = f"{RIGHT} and the rest"
    result, verdict = _scan({"x": {"a": f"{LEFT}{RIGHT} x zzzz {LEFT}",
                                   tail_key: f"key {FAKE_AWS_KEY}"}})
    _assert_no_half(result, verdict)
    assert f"tool_input.x.{REDACTED}" in {f.locator for f in result.findings}
