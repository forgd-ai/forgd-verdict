"""Masking many matches in one value: cost and equivalence.

`_mask_text` replaces every wanted span in one attribute value. Its cost
grows with the length of the value and the number of findings, not with
their product.
"""

from __future__ import annotations

import random
from collections.abc import Sequence

from forgd_verdict import core
from forgd_verdict.core import scan
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.models import Finding
from forgd_verdict.otel.extract import record_units
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.policy import load_policy
from forgd_verdict.sink import redact
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.redact import (
    MASK,
    MASK_WHOLE,
    RedactionPlan,
    _mask_text,
    _still_matches,
    index_findings,
    redact_events,
)

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _reference_mask_text(text: str, findings: Sequence[Finding], plan: RedactionPlan,
                         detectors) -> tuple[str, dict[str, int]]:
    """The implementation before the single join, kept as the spec."""
    counts: dict[str, int] = {}
    wanted = [f for f in findings if plan.wants(f.detector)]
    if not wanted:
        return text, counts

    def whole(f: Finding) -> tuple[str, dict[str, int]]:
        totals = dict(counts)
        for g in wanted:
            totals[g.detector] = totals.get(g.detector, 0) + 1
        return MASK_WHOLE.format(detector=f.detector), totals

    out = text
    masked_ranges: list[tuple[int, int]] = []
    for f in sorted(wanted, key=lambda f: -1 if f.start is None else f.start,
                    reverse=True):
        if f.start is None or f.end is None:
            return whole(f)
        start, end = int(f.start), int(f.end)
        if not (0 <= start < end <= len(text)):
            return whole(f)
        if any(start < b and a < end for a, b in masked_ranges):
            continue
        out = out[:start] + MASK.format(detector=f.detector) + out[end:]
        masked_ranges.append((start, end))
        counts[f.detector] = counts.get(f.detector, 0) + 1
    if _still_matches(out, plan, detectors):
        return whole(wanted[0])
    return out, counts


def _aws_key(i: int) -> str:
    return "AKIA" + "".join(_B32[(i >> (5 * j)) & 31] for j in range(16))


class _Sliced(str):
    """A str that adds the length of every slice taken from it, or from a
    string built from it by slicing or `+`, to `sliced[0]`."""

    def __new__(cls, value: str, sliced: list[int]):
        self = super().__new__(cls, value)
        self.sliced = sliced
        return self

    def __getitem__(self, key):
        part = str.__getitem__(self, key)
        self.sliced[0] += len(part)
        return _Sliced(part, self.sliced)

    def __add__(self, other):
        return _Sliced(str.__add__(self, other), self.sliced)

    def __radd__(self, other):
        return _Sliced(str.__add__(other, self), self.sliced)


def test_many_matches_in_one_value_are_masked_in_linear_time(monkeypatch):
    n = 20_000
    monkeypatch.setattr(core, "MAX_SCAN_FINDINGS", 4 * n)
    detectors = [d for d in load_policy("policy.yaml").build_detectors(salt="s" * 32)
                 if d.tier == 0]
    message = " ".join(_aws_key(i) for i in range(n))
    rec = OtelRecord(kind="span", name="agent.query", attributes={"user.message": message})
    found = index_findings(scan(record_units(rec, 0), detectors).findings)
    cfg = SinkConfig(name="s", endpoint="https://collector.test")
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    rescans: list[int] = []

    def counted(text, plan, detectors):
        rescans.append(len(text))
        return _still_matches(text, plan, detectors)

    monkeypatch.setattr(redact, "_still_matches", counted)
    out = redact_events([rec], found, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=detectors)
    assert out[0].redactions == {"regex:aws-access-key": n}
    assert "AKIA" not in out[0].attributes["user.message"]
    assert len(rescans) == 1, f"{len(rescans)} rescans of one value"

    [spans] = found.values()
    sliced = [0]
    masked, counts = _mask_text(_Sliced(message, sliced), spans, plan, detectors)
    assert counts == {"regex:aws-access-key": n}
    assert sliced[0] <= 2 * len(message), f"sliced {sliced[0]:,} of {len(message):,}"


_DETECTORS = [T0RegexDetector()]
_NAMES = ["regex:aws-access-key", "regex:ssn", "other:thing"]


def _random_case(rng: random.Random) -> tuple[str, list[Finding]]:
    words = ["plain", "text", "x", "AKIAQYLPMN5HGZTHX4UQ", "--", "value"]
    text = " ".join(rng.choice(words) for _ in range(rng.randint(0, 12)))
    findings = []
    for k in range(rng.randint(0, 8)):
        roll = rng.random()
        if roll < 0.05:
            start = end = None
        elif roll < 0.1:
            start, end = rng.randint(-3, len(text) + 3), rng.randint(-3, len(text) + 3)
        else:
            start = rng.randint(0, max(0, len(text) - 1))
            end = rng.randint(start + 1, len(text) + 1) if text else 1
            end = min(end, len(text)) if rng.random() < 0.95 else end
        findings.append(Finding(rng.choice(_NAMES), "block", "loc", f"h{k}",
                                start=start, end=end))
    # A span for each real key, so masking can remove it.
    pos = text.find("AKIA")
    while pos >= 0:
        if rng.random() < 0.8:
            findings.append(Finding("regex:aws-access-key", "block", "loc", f"k{pos}",
                                    start=pos, end=pos + 20))
        pos = text.find("AKIA", pos + 1)
    rng.shuffle(findings)
    return text, findings


def test_mask_text_matches_the_reference():
    rng = random.Random(353)
    plans = [RedactionPlan(frozenset({"regex"})),
             RedactionPlan(frozenset({"regex:aws-access-key", "other:thing"})),
             RedactionPlan(frozenset({"other:thing"}))]
    for _ in range(3000):
        text, findings = _random_case(rng)
        plan = rng.choice(plans)
        assert (_mask_text(text, findings, plan, _DETECTORS)
                == _reference_mask_text(text, findings, plan, _DETECTORS)), (text, findings)
