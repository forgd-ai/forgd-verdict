"""The collector does not store an identity value its own scan matched.

The metadata guard that cleans a stored record probes with T0 and
daemon-backed T1. The scan also runs subprocess T1, T2 and plugins over
each identity attribute, and a value it matched must not reach the store
or `/stats` either.
"""

from __future__ import annotations

import pytest
from test_sink_redact_scan_parity import MARKER, Marker

from forgd_verdict.detectors.base import TIER_T1, TIER_T2
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.otel.collect import collect
from forgd_verdict.otel.payload import OtelRecord


@pytest.mark.parametrize("tier", [TIER_T1, TIER_T2])
def test_an_identity_value_only_the_scan_matched_is_not_stored(tier):
    records = [OtelRecord(kind="log", name="mystery.event",
                          attributes={"session.id": f"sess-{MARKER}-01",
                                      "model": f"model-{MARKER}",
                                      "service.name": f"svc-{MARKER}",
                                      "note": "plain words only"})]
    out, unknown = collect(records, [T0RegexDetector(), Marker(tier)], budget_ms=5000,
                           org_id="o", salt="s")
    (record,) = out
    assert any(f.detector == "marker:token" for f in record.findings)
    assert MARKER not in repr(record)
    assert MARKER not in repr(unknown)
    assert record.session_id.startswith("redacted_")
    assert record.model.startswith("redacted_")


def test_each_replacement_is_counted_in_metadata_redacted():
    from forgd_verdict.metadata import MetadataGuard

    detectors = [T0RegexDetector(), Marker(TIER_T2)]
    meta = MetadataGuard(detectors, "s")
    records = [OtelRecord(kind="log", name="mystery.event",
                          attributes={"session.id": f"sess-{MARKER}-01",
                                      "model": f"model-{MARKER}",
                                      "service.name": f"svc-{MARKER}"})]
    collect(records, detectors, budget_ms=5000, org_id="o", salt="s", meta=meta)
    # session_id, model, reported_as, and the unattributed hint for /stats.
    assert meta.redacted == 4
