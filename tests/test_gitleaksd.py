"""The gitleaks daemon transport.

Skipped unless `FORGD_GITLEAKSD_BIN` points at a built `sidecar/gitleaksd`.
CI builds it and sets the variable; a laptop without a Go toolchain skips.

The test that matters is transport equality. The two paths run the same rules
over the same bytes and must produce identical findings -- and the first
version did not: the gitleaks library reports `StartLine` 0-based while the
CLI's JSON report is 1-based, so every daemon finding was attributed to the
wrong ScanUnit and then dropped by the line map. The detector returned an
empty list, which is indistinguishable from a clean scan.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from conftest import FAKE_GITHUB_TOKEN, GITLEAKS_FIXTURES, GITLEAKS_STOPWORD_GHP

from forgd_verdict.detectors import GitleaksDetector
from forgd_verdict.detectors.gitleaks import BASELINE_CONFIG, DaemonUnavailable
from forgd_verdict.models import ScanUnit

# NOT conftest's FAKE_AWS_KEY. That is `AKIAIOSFODNN7EXAMPLE`, which
# gitleaks' default rule set allowlists as a documentation key -- T0 flags it
# and T1 correctly does not, which is the tier difference the module docstring
# describes. A gitleaks test needs a key gitleaks will actually report.
GL_AWS_KEY = "AKIAQYLPMN5HGZTHX4UQ"

DAEMON_BIN = os.environ.get("FORGD_GITLEAKSD_BIN")

pytestmark = pytest.mark.skipif(
    not (DAEMON_BIN and Path(DAEMON_BIN).is_file()),
    reason="set FORGD_GITLEAKSD_BIN to a built sidecar/gitleaksd binary",
)


@pytest.fixture(scope="module")
def daemon():
    # Not tmp_path_factory: macOS caps a Unix socket path at 104 bytes.
    d = tempfile.mkdtemp(prefix="gl", dir="/tmp")
    sock = Path(d) / "gl.sock"
    try:
        proc = subprocess.Popen(
            [DAEMON_BIN, "--socket", str(sock), "--config", str(BASELINE_CONFIG)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for _ in range(100):
            if sock.exists():
                break
            time.sleep(0.05)
        else:
            proc.kill()
            out, _ = proc.communicate(timeout=10)
            pytest.fail(f"gitleaksd never created {sock}: {out.strip()}")
        yield str(sock)
        proc.terminate()
        proc.wait(timeout=10)
    finally:
        shutil.rmtree(d, ignore_errors=True)


UNITS = [
    ScanUnit(locator="m[0]", tool_name=None, text="nothing to see here\n"),
    ScanUnit(locator="m[1]", tool_name=None,
             text=f"deploy with {GL_AWS_KEY} and {'filler ' * 50}"),
    ScanUnit(locator="m[2]", tool_name=None, text=f"token {FAKE_GITHUB_TOKEN}"),
]


def _triples(findings):
    return sorted((f.detector, f.locator, f.excerpt_hash) for f in findings)


@pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks not installed")
def test_both_transports_return_identical_findings(daemon):
    """Same rules, same bytes, same answer -- including which ScanUnit each
    finding is attributed to, which is where the line-base bug showed."""
    subprocess_findings = GitleaksDetector("block", "", timeout_s=30.0).scan(UNITS)
    daemon_findings = GitleaksDetector("block", "", daemon=daemon).scan(UNITS)

    assert _triples(subprocess_findings) == _triples(daemon_findings)
    assert subprocess_findings, "the fixture must produce at least one finding"


SPAN_UNITS = [
    ScanUnit(locator="s[0]", tool_name=None, text=f"see {GL_AWS_KEY}"),
    ScanUnit(locator="s[1]", tool_name=None, text=f"xé {GL_AWS_KEY} ok"),
    ScanUnit(locator="s[2]", tool_name=None, text=f"first line\nsé {FAKE_GITHUB_TOKEN}"),
]


@pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks not installed")
def test_both_transports_return_identical_spans(daemon):
    subprocess_findings = GitleaksDetector("block", "", timeout_s=30.0).scan(SPAN_UNITS)
    daemon_findings = GitleaksDetector("block", "", daemon=daemon).scan(SPAN_UNITS)

    def spans(findings):
        return sorted((f.detector, f.locator, f.start, f.end) for f in findings)

    assert spans(subprocess_findings) == spans(daemon_findings)
    assert {f.locator for f in daemon_findings} == {"s[0]", "s[1]", "s[2]"}
    assert all(f.start is not None for f in daemon_findings)


def test_the_daemon_attributes_a_finding_to_the_right_unit(daemon):
    findings = GitleaksDetector("block", "", daemon=daemon).scan(UNITS)
    by_locator = {f.locator for f in findings}
    assert "m[1]" in by_locator
    assert "m[0]" not in by_locator, "the clean unit must not be blamed"


def test_the_daemon_ignores_a_gitleaks_allow_comment(daemon):
    """The scanned content is untrusted and may carry the annotation. The
    subprocess path passes --ignore-gitleaks-allow for the same reason."""
    units = [ScanUnit(locator="m", tool_name=None,
                      text=f"key {GL_AWS_KEY} # gitleaks:allow")]
    assert GitleaksDetector("block", "", daemon=daemon).scan(units)


def test_a_configured_daemon_that_is_down_raises(tmp_path):
    """Never a silent fallback. An empty result reads as a clean scan, so
    a control that fails open does so quietly."""
    det = GitleaksDetector("block", "", daemon=str(tmp_path / "absent.sock"))
    assert det.available() is False
    with pytest.raises(DaemonUnavailable):
        det.scan(UNITS)


def test_a_live_daemon_reports_available(daemon):
    assert GitleaksDetector("block", "", daemon=daemon).available() is True


def test_the_daemon_never_returns_the_secret_in_a_finding(daemon):
    """The privacy invariant holds across the new transport too: the daemon
    hands back the matched value so the hash can be computed, and nothing
    downstream of Finding carries it."""
    findings = GitleaksDetector("block", "", daemon=daemon).scan(UNITS)
    blob = repr(findings)
    assert GL_AWS_KEY not in blob
    assert FAKE_GITHUB_TOKEN not in blob


@pytest.mark.parametrize("rule", sorted(GITLEAKS_FIXTURES))
def test_the_daemon_reports_each_rule_family_under_its_rule_id(daemon, rule):
    """The library build has to catch what the CLI catches, family by
    family, with fixtures T0 does not see (see tests/data/gitleaks-t1.json)."""
    units = [ScanUnit(locator="m", tool_name=None,
                      text=f"the deploy notes had {GITLEAKS_FIXTURES[rule]} pasted into them")]
    found = {f.detector for f in GitleaksDetector("block", "", daemon=daemon).scan(units)}
    assert f"gitleaks:{rule}" in found


def test_the_daemon_drops_a_value_containing_the_alphabet_stopword(daemon):
    """The same default-config stopword the CLI applies."""
    units = [ScanUnit(locator="m", tool_name=None, text=f"token {GITLEAKS_STOPWORD_GHP}")]
    assert GitleaksDetector("block", "", daemon=daemon).scan(units) == []


def test_the_guard_on_the_daemon_matches_v0_45_0_past_max_bytes(daemon, monkeypatch):
    """One export whose identity values hand the guard more than
    `max_bytes` of candidate text in one call, with a gitleaks-only secret
    in the first record and another in the last. Redacted together it must
    give what v0.45.0 gave group by group."""
    import random

    import _redact_v0_45_0 as v045

    from forgd_verdict.core import _candidates, _run_candidates, _utf8_len
    from forgd_verdict.detectors.gitleaks import DEFAULT_MAX_BYTES
    from forgd_verdict.detectors.t0_regex import T0RegexDetector
    from forgd_verdict.metadata import MetadataGuard
    from forgd_verdict.otel.payload import OtelRecord
    from forgd_verdict.sink import redact
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.factory import emitted_ids

    largest = 0

    class Measured(MetadataGuard):
        def _matches(self, values):
            nonlocal largest
            largest = max(largest, sum(
                _utf8_len(c) for v in values.values() if isinstance(v, str) and v
                for c in dict.fromkeys([v, *_candidates(v), *_run_candidates(v)])))
            return super()._matches(values)

    monkeypatch.setattr(redact, "MetadataGuard", Measured)
    monkeypatch.setattr("forgd_verdict.core._SCRUB_BUDGET_S", 60.0)

    class Recorded(GitleaksDetector):
        """Records every exception `scan` raises, so a daemon failure in one
        run cannot pass for a redaction difference."""

        raised: list[str] = []

        def scan(self, units):
            try:
                return super().scan(units)
            except Exception as exc:
                self.raised.append(f"{type(exc).__name__}: {exc}")
                raise

    rng = random.Random(7)

    def pad() -> str:
        return " ".join("".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(8))
                        for _ in range(10))[:96]

    groups = [[OtelRecord(kind="log", name="claude_code.api_request",
                          attributes={f"k{j}_id": pad() for j in range(7)},
                          resource={"service.name": "claude-code"})
               for _ in range(450)] for _ in range(20)]
    early, late = GITLEAKS_FIXTURES["linear-api-key"], GITLEAKS_FIXTURES["gitlab-pat"]
    t0_hits = T0RegexDetector().scan([ScanUnit("x", None, early), ScanUnit("y", None, late)])
    assert t0_hits == []
    groups[0][0].attributes["session.id"] = early
    groups[-1][-1].attributes["session.id"] = late

    gitleaks = Recorded(daemon=daemon, timeout_s=300)
    detectors = [T0RegexDetector(), gitleaks]
    config = SinkConfig(name="s", endpoint="https://collector.test")
    ids = emitted_ids(detectors)
    kw = {"org": "o", "observed_at": "2026-10-05T00:00:00Z", "detectors": detectors}
    old_plan = v045.RedactionPlan.build(config, ids)
    new_plan = redact.RedactionPlan.build(config, ids)
    before = [e for records in groups
              for e in v045.redact_events(records, {}, old_plan, config, surface="s", **kw)]
    after = redact.redact_groups([redact.RedactGroup(records, {}, "s") for records in groups],
                                 new_plan, config, **kw)
    assert largest > DEFAULT_MAX_BYTES
    raw = [i for i, v in enumerate((early, late)) if v in repr(after)]
    assert raw == []
    assert gitleaks.raised == [], f"gitleaks raised during the run: {gitleaks.raised}"
    same = after == before
    assert same
