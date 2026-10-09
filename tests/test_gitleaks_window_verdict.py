"""A gitleaks scan past `max_bytes` on the verdict path and in the collector.

The verdict server runs the shipped `on_tier_dropped: allow` and real
gitleaks. gitleaks keeps the newest units that fit under `max_bytes` and
records UNSCANNED_CAPPED for the earlier ones, so a blocking policy denies
what it did not read. Assertions are presence and absence only, so a
failure never prints a planted value.
"""

from __future__ import annotations

import json
import shutil

import pytest
from conftest import GITLEAKS_T1_ONLY, WHSEC, ASGIClient, frame, make_policy, sign, text_msg

from forgd_verdict.detectors.base import ScanTruncated
from forgd_verdict.detectors.gitleaks import DEFAULT_MAX_BYTES, GitleaksDetector
from forgd_verdict.extract import MAX_UNIT_BYTES
from forgd_verdict.models import UNSCANNED_CAPPED, ScanUnit
from forgd_verdict.otel.collect import collect
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.server.app import VerdictServer
from forgd_verdict.sink import redact
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.factory import emitted_ids

# Multi-MiB inputs through real gitleaks: alone, after the parallel suite.
pytestmark = [pytest.mark.serial,
              pytest.mark.skipif(not shutil.which("gitleaks"), reason="needs gitleaks")]

PAT = GITLEAKS_T1_ONLY["gitlab-pat"]
WORDS = "the quick brown fox jumps over the lazy dog "
# Every unit is under MAX_UNIT_BYTES, and two of them joined fit DEFAULT_MAX_BYTES.
PAD = (WORDS * (MAX_UNIT_BYTES // len(WORDS)))[:MAX_UNIT_BYTES - 1]
# Further from the end of its unit than a seam reaches.
TRAILER = WORDS * 20


def _policy(tmp_path, **detectors):
    return make_policy(
        detectors={"gitleaks": {"enabled": True, "severity": "block", "timeout_ms": 300_000},
                   **detectors},
        server={"mode": "enforce", "secrets": [WHSEC],
                "csv_path": str(tmp_path / "timings.csv"),
                "archive_dir": str(tmp_path / "archive")},
    )


async def _verdict(server: VerdictServer, messages) -> dict:
    raw = json.dumps(frame(messages)).encode()
    status, verdict = await ASGIClient(server).post("/hook", raw, sign(raw))
    assert status == 200
    return verdict


async def test_a_secret_before_the_window_denies_as_over_the_size_limit(tmp_path):
    policy = _policy(tmp_path)
    assert policy.on_tier_dropped == "allow"
    server = VerdictServer(policy)
    (gitleaks,) = [d for d in server.detectors if d.name == "gitleaks"]
    assert gitleaks.max_bytes == DEFAULT_MAX_BYTES and not gitleaks.uses_daemon
    assert 3 * len(PAD) > DEFAULT_MAX_BYTES >= 2 * len(PAD) + 1

    verdict = await _verdict(server, [text_msg(f"token {PAT} {TRAILER}"),
                                      *(text_msg(PAD) for _ in range(3))])
    server.close()

    assert verdict["action"] == "deny"
    assert "over the size limit" in verdict["deny_reason"]
    assert PAT not in json.dumps(verdict)
    assert PAT[-8:] not in verdict["deny_reason"] + verdict.get("reference_id", "")


async def test_a_secret_inside_the_window_denies_as_the_finding(tmp_path):
    server = VerdictServer(_policy(tmp_path))

    verdict = await _verdict(server, [*(text_msg(PAD) for _ in range(3)),
                                      text_msg(f"token {PAT}")])
    server.close()

    assert verdict["action"] == "deny"
    assert "over the size limit" not in verdict["deny_reason"]
    assert "could not be checked" not in verdict["deny_reason"]
    assert PAT not in json.dumps(verdict)


async def test_a_truncated_scan_allows_when_no_detector_blocks(tmp_path):
    policy = _policy(tmp_path, t0_regex={"enabled": True, "severity": "warn"},
                     checksums={"enabled": True, "severity": "warn"},
                     gitleaks={"enabled": True, "severity": "warn"})
    detectors = [d for d in policy.build_detectors(profile="server") if d.name != "gitleaks"]
    gitleaks = GitleaksDetector("warn", max_bytes=400, timeout_s=30.0)
    server = VerdictServer(policy, detectors=[*detectors, gitleaks])

    verdict = await _verdict(server, [text_msg(WORDS * 20), text_msg(f"token {PAT}")])
    server.close()

    assert verdict["action"] == "allow"


def test_a_truncated_group_hands_the_sink_unscanned_capped():
    gitleaks = GitleaksDetector(max_bytes=400, timeout_s=30.0)
    record = OtelRecord(kind="log", name="claude_code.user_prompt",
                        attributes={"prompt.id": "p1", "prompt": WORDS * 20,
                                    "response": f"token {PAT}"},
                        resource={"service.name": "claude-code"})
    handed = []

    def on_group(records, findings, surface, skipped):
        handed.append((records, findings, surface, skipped))

    collect([record], [gitleaks], budget_ms=60_000, org_id="o", on_group=on_group)

    ((records, findings, surface, skipped),) = handed
    assert "gitleaks" in skipped
    assert UNSCANNED_CAPPED in skipped
    config = SinkConfig(name="s", endpoint="https://collector.test")
    events = redact.redact_events(
        records, redact.index_findings(findings),
        redact.RedactionPlan.build(config, emitted_ids([gitleaks])), config,
        surface=surface, org="o", observed_at="2026-10-05T00:00:00Z",
        detectors=[gitleaks], skipped=skipped)
    assert WORDS * 20 not in repr(events)
    assert PAT not in repr(events)


def test_gitleaks_scans_the_newest_units_that_fit():
    other = GITLEAKS_T1_ONLY["linear-api-key"]
    units = [ScanUnit(locator="old", tool_name=None, text=f"token {other}"),
             ScanUnit(locator="mid", tool_name=None, text=WORDS),
             ScanUnit(locator="new", tool_name=None, text=f"token {PAT}")]
    fits = len(units[1].text) + 1 + len(units[2].text)
    gitleaks = GitleaksDetector(max_bytes=fits, timeout_s=30.0)

    with pytest.raises(ScanTruncated) as caught:
        gitleaks.scan(units)

    assert caught.value.scanned == 2
    assert [(f.detector, f.locator) for f in caught.value.findings] == [
        ("gitleaks:gitlab-pat", "new")]
