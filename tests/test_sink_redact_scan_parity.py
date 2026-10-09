"""Redaction masks what the scan found, whichever tier found it.

The metadata guard probes identity values and attribute names with T0 and
daemon-backed T1 only. The scan that produced the findings also runs
subprocess gitleaks, T2 and plugins, and the name scrub runs every tier
below T2. A value or a name any of those matched must not be forwarded.
"""

from __future__ import annotations

import json

import pytest
from conftest import GITLEAKS_FIXTURES

from forgd_verdict.budget import Budget
from forgd_verdict.core import scan
from forgd_verdict.detectors.base import TIER_T1, TIER_T2
from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.models import UNSCANNED_CAPPED, Finding
from forgd_verdict.otel.extract import records_units
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.factory import emitted_ids
from forgd_verdict.sink.redact import RedactionPlan, index_findings, redact_events

SHOPIFY = GITLEAKS_FIXTURES["shopify-access-token"]
MARKER = "zqxplugintokenzqx"


class Marker:
    """Finds MARKER wherever it appears, like a plugin or T2 tier would.
    Not daemon-backed, so the metadata guard never runs it."""

    name = "marker"
    severity = "block"

    def __init__(self, tier: int) -> None:
        self.tier = tier

    def finding_ids(self):
        return ["marker:token"]

    def available(self):
        return True

    def scan(self, units):
        out = []
        for u in units:
            i = u.text.find(MARKER)
            if i >= 0:
                out.append(Finding(detector="marker:token", severity="block",
                                   locator=u.locator, excerpt_hash="h",
                                   start=i, end=i + len(MARKER)))
        return out


@pytest.fixture(scope="module")
def gitleaks():
    det = GitleaksDetector()
    if not det.available():
        pytest.skip("gitleaks is not installed")
    assert not det.uses_daemon
    return det


def _forward(records, detectors):
    result = scan(records_units(records), detectors, Budget(60_000))
    config = SinkConfig(name="s", endpoint="https://collector.test")
    plan = RedactionPlan.build(config, emitted_ids(detectors))
    events = redact_events(records, index_findings(result.findings), plan, config,
                           surface="s", org="o", observed_at="2026-10-06T00:00:00Z",
                           detectors=detectors,
                           skipped=list(result.detectors_skipped))
    return result, events


def _wire(events) -> str:
    return json.dumps([[e.name, e.attributes, e.resource] for e in events])


def test_an_identity_value_only_gitleaks_matches_is_masked(gitleaks):
    records = [OtelRecord(kind="log", name="claude_code.tool_result",
                          attributes={"request_id": SHOPIFY, "tool_name": SHOPIFY,
                                      "tool.output": "plain words only"}),
               OtelRecord(kind="log", name="claude_code.tool_result",
                          attributes={"request_id": SHOPIFY})]
    result, events = _forward(records, [T0RegexDetector(), gitleaks])
    assert any(f.detector == "gitleaks:shopify-access-token" for f in result.findings)
    assert SHOPIFY not in _wire(events)
    for e in events:
        assert e.attributes["request_id"].startswith("[redacted:")
    assert events[0].attributes["tool_name"].startswith("[redacted:")


@pytest.mark.parametrize("tier", [TIER_T1, TIER_T2])
def test_an_identity_value_only_a_plugin_or_t2_tier_matches_is_masked(tier):
    value = f"sess-{MARKER}-01"
    records = [OtelRecord(kind="log", name="claude_code.user_prompt",
                          attributes={"session.id": value, "prompt": "plain words only"})]
    result, events = _forward(records, [T0RegexDetector(), Marker(tier)])
    assert any(f.detector == "marker:token" for f in result.findings)
    assert MARKER not in _wire(events)


@pytest.mark.parametrize("key", [f"note.{SHOPIFY}", f"{SHOPIFY}_id"])
def test_an_attribute_name_only_gitleaks_matches_is_renamed(gitleaks, key):
    """`note.<token>` is a scanned value whose dotted name the scrub flags;
    `<token>_id` is identity-shaped, so only its name is probed."""
    records = [OtelRecord(kind="log", name="claude_code.tool_result",
                          attributes={key: "a perfectly ordinary value",
                                      "tool.output": "plain words only"})]
    _, events = _forward(records, [T0RegexDetector(), gitleaks])
    (event,) = events
    assert SHOPIFY not in _wire(events)
    assert key not in event.attributes
    assert any(k.startswith("[redacted:metadata-name:") for k in event.attributes)


# RFC 9562's UUIDv4 example, as a prompt.id the scan never reads.
PROMPT_ID = "919108f7-52d1-4320-9bac-f847db4148a8"


def _redact_unscanned(detectors, skipped):
    record = OtelRecord(kind="log", name="claude_code.user_prompt",
                        attributes={"session.id": "sess-abcdefgh-01",
                                    "prompt.id": PROMPT_ID})
    config = SinkConfig(name="s", endpoint="https://collector.test")
    plan = RedactionPlan.build(config, emitted_ids(detectors))
    (event,) = redact_events([record], {}, plan, config, surface="s", org="o",
                             observed_at="2026-10-06T00:00:00Z", detectors=detectors,
                             skipped=skipped)
    return event.attributes


@pytest.mark.parametrize("skipped, mask", [
    ([UNSCANNED_CAPPED], "[redacted:unscanned-capped:whole-value]"),
    (["marker"], "[redacted:tier-skipped:marker:whole-value]"),
])
def test_an_identity_value_a_tier_the_guard_lacks_did_not_scan_is_masked(skipped, mask):
    attributes = _redact_unscanned([T0RegexDetector(), Marker(TIER_T2)], skipped)
    assert attributes["session.id"] == mask
    # Never scanned, capped or not.
    assert attributes["prompt.id"] == PROMPT_ID


@pytest.mark.parametrize("detectors, skipped", [
    ([T0RegexDetector()], [UNSCANNED_CAPPED]),
    ([T0RegexDetector(), Marker(TIER_T1)], ["marker"]),
])
def test_an_identity_value_the_guard_cleared_on_every_unscanned_tier_is_kept(detectors,
                                                                            skipped):
    assert _redact_unscanned(detectors, skipped)["session.id"] == "sess-abcdefgh-01"


def test_a_failed_late_tier_leaves_identity_values_it_never_reads():
    from test_sink_late import FakeNER

    from forgd_verdict.sink.late import LateGroup, LateJob, LateRedactor

    config = SinkConfig(name="s", endpoint="https://collector.test")
    t0, ner = T0RegexDetector(), FakeNER(fail=True)
    plan = RedactionPlan.build(config, emitted_ids([t0, ner]))
    offered = []
    late = LateRedactor(plan=plan, config=config, offer=offered.extend,
                        cheap_detectors=[t0], late_detectors=[ner], background=False)
    record = OtelRecord(kind="log", name="claude_code.user_prompt",
                        attributes={"session.id": "sess-abcdefgh-01",
                                    "prompt": "plain words only"})
    late.offer(LateJob([LateGroup([record], [], "s")], "o", "2026-10-06T00:00:00Z"))
    late.drain()
    (event,) = offered
    assert event.attributes["prompt"] == "[redacted:tier-skipped:presidio_pii:whole-value]"
    assert event.attributes["session.id"] == "sess-abcdefgh-01"


class RaisesOnName(T0RegexDetector):
    """The real T0 detector, raising when it is handed the event name."""

    def scan(self, units):
        units = list(units)
        if any(u.locator == "name" for u in units):
            raise RuntimeError("probe failed")
        return super().scan(units)


def test_an_event_name_a_detector_failed_on_is_masked_whole():
    name = "evt.zzsomething-sender-chosen"
    record = OtelRecord(kind="log", name=name, attributes={"prompt": "plain words only"})
    detectors = [RaisesOnName()]
    config = SinkConfig(name="s", endpoint="https://collector.test")
    plan = RedactionPlan.build(config, emitted_ids(detectors))
    (event,) = redact_events([record], {}, plan, config, surface="s", org="o",
                             observed_at="2026-10-06T00:00:00Z", detectors=detectors)
    assert event.name == "[redacted:scan-failed:whole-value]"
    assert event.redactions.get("scan-failed") == 1
