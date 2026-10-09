"""A dict key matched by any tier is kept out of every finding's locator.

`extract._strings` scans a key as its own unit, `<path>.<key>#key`, and the
key is also part of the locator of every value beneath it. The locator scrub
probes segments with the tiers below T2 only, so a key only Presidio or T2
recognises reached the store in both places.
"""

from __future__ import annotations

import hashlib

from conftest import FAKE_AWS_KEY

from forgd_verdict.core import REDACTED, scan
from forgd_verdict.extract import frame_units, unknown_frame_units
from forgd_verdict.models import Finding
from forgd_verdict.policy import load_policy

SALT = "key-scrub-test-salt-0123456789"
NAME = "Dr. Jane Q. Customer"


class _FakeNER:
    """A T2 detector that matches NAME, which no cheap tier does."""
    name = "fake_ner"
    tier = 2
    severity = "warn"

    def available(self):
        return True

    def scan(self, units):
        return [
            Finding("presidio:person", self.severity, u.locator,
                    hashlib.sha256(NAME.encode()).hexdigest(), u.tool_name)
            for u in units if NAME in u.text
        ]


def _detectors():
    return [*load_policy("policy.yaml").build_detectors(salt=SALT), _FakeNER()]


def _tool_use(input_):
    return [{"role": "assistant",
             "content": [{"type": "tool_use", "name": "t", "input": input_}]}]


def _locators(units):
    findings = scan(units, _detectors()).findings
    assert findings
    return {f.detector: f.locator for f in findings}, findings


def test_a_matched_key_is_not_in_its_own_locator():
    by_det, findings = _locators(frame_units(_tool_use({NAME: "nothing here"})))
    assert "presidio:person" in by_det
    for f in findings:
        assert NAME not in f.locator
        assert "Customer" not in f.locator


def test_a_matched_key_is_not_in_a_nested_value_locator():
    units = frame_units(_tool_use({NAME: {"x": f"key {FAKE_AWS_KEY}"}}))
    by_det, findings = _locators(units)
    cheap = [f for f in findings if f.detector != "presidio:person"]
    assert cheap, "the AWS key under the matched key was not found"
    for f in findings:
        assert "Customer" not in f.locator
    assert any(f.locator.endswith(f".input.{REDACTED}.x") for f in cheap)


def test_a_matched_frame_key_is_scrubbed():
    units = unknown_frame_units({"type": "other",
                                 NAME: {"x": f"key {FAKE_AWS_KEY}"}})
    _, findings = _locators(units)
    assert any(f.detector != "presidio:person" for f in findings)
    for f in findings:
        assert "Customer" not in f.locator
    assert {f.locator for f in findings} >= {f"frame.{REDACTED}#key",
                                             f"frame.{REDACTED}.x"}


def test_an_unmatched_key_is_left_alone():
    units = frame_units(_tool_use({"an_ordinary_field_name": f"key {FAKE_AWS_KEY}"}))
    _, findings = _locators(units)
    assert any(f.locator.endswith(".input.an_ordinary_field_name") for f in findings)


def test_a_matched_key_inside_a_matched_key():
    units = frame_units(_tool_use({NAME: {f"{NAME} again": f"key {FAKE_AWS_KEY}"}}))
    _, findings = _locators(units)
    for f in findings:
        assert "Customer" not in f.locator, f.locator


def test_a_sibling_key_that_shares_a_prefix_is_left_alone():
    units = frame_units(_tool_use({NAME: "x", f"{NAME}X": f"key {FAKE_AWS_KEY}"}))
    findings = scan(units, [*load_policy("policy.yaml").build_detectors(salt=SALT)]).findings
    assert any(f.locator.endswith(f".input.{NAME}X") for f in findings)
