"""A secret in the last of many records stays out of the store and the sink
when the metadata guard's candidate text is past gitleaks' `max_bytes`.

Production defaults: the real `DEFAULT_MAX_BYTES` and the gitleaks binary on
the daemon path the guard batches with. Assertions are presence and absence
only, so a failure never prints a planted value.
"""

from __future__ import annotations

import random
import shutil
import string

import pytest
from conftest import GITLEAKS_FIXTURES

from forgd_verdict.core import _candidates, _run_candidates, _utf8_len
from forgd_verdict.detectors.gitleaks import DEFAULT_MAX_BYTES, GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.otel.collect import collect
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink import redact
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.factory import emitted_ids
from forgd_verdict.store.base import VerdictRecord

# Multi-MiB inputs through real gitleaks: alone, after the parallel suite.
pytestmark = [pytest.mark.serial,
              pytest.mark.skipif(not shutil.which("gitleaks"), reason="needs gitleaks")]

EARLY = GITLEAKS_FIXTURES["linear-api-key"]
LATE = GITLEAKS_FIXTURES["gitlab-pat"]
PLANTED = (EARLY, LATE)


class _DaemonPath(GitleaksDetector):
    """The binary, batched by the guard as a daemon would be."""

    @property
    def uses_daemon(self) -> bool:
        return True


def _gitleaks() -> _DaemonPath:
    return _DaemonPath(timeout_s=300)


def _pad(rng: random.Random, words: int, cap: int) -> str:
    """Eight-letter words joined by alternating "-" and " "."""
    out = ""
    for i in range(words):
        out += ("-" if i % 2 else " ") * bool(i)
        out += "".join(rng.choice(string.ascii_lowercase) for _ in range(8))
    return out[:cap]


class _Measured(MetadataGuard):
    """Records the most candidate bytes one `matches` call was handed."""

    largest = 0

    def _matches(self, values):
        size = sum(_utf8_len(c) for v in values.values() if isinstance(v, str) and v
                   for c in dict.fromkeys([v, *_candidates(v), *_run_candidates(v)]))
        _Measured.largest = max(_Measured.largest, size)
        return super()._matches(values)


@pytest.fixture(autouse=True)
def _measure(monkeypatch):
    _Measured.largest = 0
    monkeypatch.setattr(redact, "MetadataGuard", _Measured)
    yield
    assert _Measured.largest > DEFAULT_MAX_BYTES


def _raw(blob: str) -> list[int]:
    """Which planted values `blob` holds, by position, never the value."""
    return [i for i, v in enumerate(PLANTED) if v in blob]


def test_the_store_path_replaces_a_secret_in_the_last_record():
    rng = random.Random(2)
    recs = [VerdictRecord(source="otel", request_id=_pad(rng, 14, 126),
                          session_id=_pad(rng, 14, 126), model=_pad(rng, 14, 126),
                          reported_as=_pad(rng, 14, 126)) for _ in range(9000)]
    recs[0].session_id, recs[-1].session_id = EARLY, LATE

    out = _Measured([T0RegexDetector(), _gitleaks()], "salt").records(recs)
    assert _raw(repr(out)) == []
    assert out[1].session_id == recs[1].session_id


def test_collect_stores_no_secret_from_the_last_session():
    rng = random.Random(3)
    recs = [OtelRecord(kind="log", name="claude_code.api_request",
                       attributes={"session.id": _pad(rng, 14, 126),
                                   "model": _pad(rng, 14, 126),
                                   "service.name": _pad(rng, 14, 126)}, resource={})
            for _ in range(9000)]
    recs[0].attributes["session.id"] = EARLY
    recs[-1].attributes["session.id"] = LATE

    meta = _Measured([T0RegexDetector(), _gitleaks()], "salt")
    stored, unknown = collect(recs, [T0RegexDetector()], budget_ms=60_000, salt="salt",
                              org_id="o", meta=meta)
    assert len(stored) == len(recs)
    assert _raw(repr(stored) + repr(unknown)) == []


def test_the_sink_path_masks_a_secret_in_the_last_group():
    rng = random.Random(1)
    recs = [OtelRecord(kind="log", name="claude_code.api_request",
                       attributes={f"k{j}_id": _pad(rng, 10, 96) for j in range(7)}, resource={})
            for _ in range(9000)]
    recs[0].attributes["session.id"] = EARLY
    recs[-1].attributes["session.id"] = LATE

    detectors = [T0RegexDetector(), _gitleaks()]
    cfg = SinkConfig(name="s", endpoint="https://collector.test")
    groups = [redact.RedactGroup(recs[i:i + 50], {}, "s") for i in range(0, len(recs), 50)]
    out = redact.redact_groups(groups, redact.RedactionPlan.build(cfg, emitted_ids(detectors)),
                               cfg, org="o", observed_at="t", detectors=detectors)
    assert len(out) == len(recs)
    assert _raw(repr([e.attributes for e in out])) == []
    assert out[1].attributes["k0_id"] == recs[1].attributes["k0_id"]
