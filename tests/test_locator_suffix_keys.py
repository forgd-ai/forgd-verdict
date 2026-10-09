"""A sender-chosen key spelled like one of the scan's locator suffixes is
an ordinary unit: its findings stay on it and its secret is never forwarded.

The scan derives units from real ones and names them by suffix: `#key`
for a dict key, `#tail` for the end of an over-limit value, `#b64` for
decoded base64, `#seam<n>` for the text across a join, `#log` for a log
body beside a `body` attribute. Seams were found by locator string, so an
OTel attribute named `prompt#seam0` holding a token was taken for the seam
between `prompt` and `response`: its finding was moved onto those two, they
were masked, and the attribute itself was forwarded with the token in it.

A key holding `#` now appears in locators as a placeholder, and a seam's
locator is never that of a real unit. These plant every suffix as a key on
each adapter's extraction.
"""

from __future__ import annotations

import json

import pytest

from forgd_verdict.budget import Budget
from forgd_verdict.core import scan
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.extract import compliance_units, frame_units, hook_units, locator_key
from forgd_verdict.models import ScanUnit
from forgd_verdict.otel.collect import collect, matched_texts
from forgd_verdict.otel.extract import records_units
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink import redact
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.factory import emitted_ids

# Synthetic: the GitHub token shape with a made-up body.
TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
DIRTY = "x " * 150 + f"see {TOKEN} ok " + "y " * 150
CLEAN = "nothing to see in this value at all"
SIBLING = "promptfield"     # long enough to have a `#key` unit of its own
SUFFIXES = ["#seam0", "#seam1", "#seam2", "#seam0'", "#key", "#b64", "#tail", "#head",
            "#tail#b64", "#log", "#key#tail", "#"]
DETECTORS = [T0RegexDetector()]


def _keys(suffix: str) -> dict[str, str]:
    return {SIBLING: CLEAN, "response": CLEAN, SIBLING + suffix: DIRTY, "zzzz": CLEAN}


def _token_findings(result):
    return [f for f in result.findings if "github" in f.detector]


def _on_the_planted_unit(units, result):
    planted = {u.locator for u in units if TOKEN in u.text}
    assert planted, "the token is in no unit"
    found = _token_findings(result)
    assert found, "the token was not found"
    for f in found:
        assert (f.raw_locator or f.locator) in planted, (f.locator, planted)
        assert set(f.seam_others) <= planted, (f.seam_others, planted)
        assert TOKEN not in f.locator and TOKEN not in json.dumps(f.seam_others)


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_a_key_holding_the_mark_is_a_placeholder(suffix):
    assert locator_key("p", SIBLING + suffix, 4) == "p.<key:4>"
    assert locator_key("p", SIBLING, 4) == f"p.{SIBLING}"


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_otel_attribute_is_masked_and_not_forwarded(suffix):
    record = OtelRecord(kind="log", name="claude_code.user_prompt",
                        attributes=_keys(suffix), resource={"service.name": "claude-code"})
    units = records_units([record])
    result = scan(units, DETECTORS, Budget(60_000))
    _on_the_planted_unit(units, result)
    assert TOKEN in "".join(matched_texts(units, result.findings))
    config = SinkConfig(name="s", endpoint="https://collector.test")
    plan = redact.RedactionPlan.build(config, emitted_ids(DETECTORS))
    (event,) = redact.redact_events([record], redact.index_findings(result.findings), plan,
                                    config, surface="claude-code", org="o",
                                    observed_at="2026-10-07T00:00:00Z", detectors=DETECTORS)
    assert TOKEN not in json.dumps(event.attributes)
    assert event.attributes[SIBLING] == CLEAN
    assert event.attributes["response"] == CLEAN


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_otel_collector_record_holds_no_token(suffix):
    record = OtelRecord(kind="log", name="claude_code.user_prompt",
                        attributes=_keys(suffix), resource={"service.name": "claude-code"})
    out, _ = collect([record], DETECTORS, budget_ms=60_000, salt="suffix-test-salt",
                     org_id="org-a")
    assert out and all(TOKEN not in r.to_json() for r in out)
    assert any(r.findings_count for r in out)


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_otel_record_name_holding_the_mark(suffix):
    record = OtelRecord(kind="log", name="claude_code.user_prompt" + suffix,
                        attributes={"prompt": DIRTY, "response": CLEAN},
                        resource={"service.name": "claude-code"})
    units = records_units([record])
    result = scan(units, DETECTORS, Budget(60_000))
    _on_the_planted_unit(units, result)


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_hook_tool_input_key(suffix):
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": _keys(suffix)})
    _on_the_planted_unit(units, scan(units, DETECTORS, Budget(60_000)))


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_hook_nested_tool_input_key(suffix):
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"env": _keys(suffix)}})
    _on_the_planted_unit(units, scan(units, DETECTORS, Budget(60_000)))


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_inference_tool_use_input_key(suffix):
    units = frame_units([{"role": "assistant", "content": [
        {"type": "tool_use", "id": "toolu_01", "name": "Bash", "input": _keys(suffix)}]}])
    _on_the_planted_unit(units, scan(units, DETECTORS, Budget(60_000)))


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_inference_block_field_key(suffix):
    units = frame_units([{"role": "user", "content": [
        {"type": "text", "text": CLEAN, **_keys(suffix)}]}])
    _on_the_planted_unit(units, scan(units, DETECTORS, Budget(60_000)))


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_compliance_tool_use_input_key(suffix):
    units = compliance_units([{"role": "assistant", "content": [
        {"type": "tool_use", "name": "Bash", "input": json.dumps(_keys(suffix))}]}])
    _on_the_planted_unit(units, scan(units, DETECTORS, Budget(60_000)))


@pytest.mark.parametrize("suffix", ["#seam0", "#seam1", "#seam0'"])
def test_a_real_unit_named_like_a_seam_keeps_its_finding(suffix):
    """Below extraction: units whose locators no extractor would build."""
    units = [ScanUnit("prompt", None, CLEAN), ScanUnit("response", None, CLEAN),
             ScanUnit("prompt" + suffix, None, DIRTY), ScanUnit("zzzz", None, CLEAN)]
    _on_the_planted_unit(units, scan(units, DETECTORS, Budget(60_000)))


def test_seam_locators_are_unique_whatever_the_real_locators():
    from forgd_verdict.core import _seams

    units = [ScanUnit(loc, None, CLEAN) for loc in
             ("a", "a#seam0", "a#seam1", "a#seam0'", "b", "a#seam1#seam2")]
    seams = [seam.locator for seam, _ in _seams(units, ["b#seam3"])]
    taken = {u.locator for u in units} | {"b#seam3"}
    assert len(seams) == len(set(seams)) and not set(seams) & taken
