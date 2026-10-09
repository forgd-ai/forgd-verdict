"""A scrubbed locator segment, run, whole locator, tool name or label
carries no digest of what it replaced.

The markers were `<redacted:` and 12 hex characters of an unsalted sha256,
so a low-entropy value such as an SSN used as a dict key or in a tool name
could be brute-forced back from a finding, a store row or a log line even
with `privacy.hash_salt` set. Every value here is planted with a non-empty
salt in force.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import re

from conftest import FAKE_AWS_KEY, FAKE_SSN, WHSEC, ASGIClient, frame, make_policy, sign

from forgd_verdict.core import _scrub_locator, scan, scrub_plugin_label
from forgd_verdict.extract import MAX_UNIT_BYTES, frame_units, hook_units
from forgd_verdict.models import ScanUnit
from forgd_verdict.plugins import PluginDetector
from forgd_verdict.policy import load_policy

SALT = "scrub-marker-test-salt-0123456789"
SSN_DOTTED = FAKE_SSN.replace("-", ".")
TOOL = f"lookup_{FAKE_SSN}"
HEX_MARKER = re.compile(r"<redacted:[0-9a-f]+>")


def _bare(text: str) -> tuple[str, str]:
    full = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return full, full[:12]


def assert_no_digest(haystack: str, *replaced: str) -> None:
    """No hex marker, and no bare sha256 (full or 12-character) of the
    planted value or of any text a marker replaced."""
    assert not HEX_MARKER.search(haystack), HEX_MARKER.search(haystack).group(0)
    for text in {FAKE_SSN, SSN_DOTTED, *replaced}:
        for d in _bare(text):
            assert d not in haystack, f"bare digest of {text!r} in output"


def _detectors():
    return load_policy("policy.yaml").build_detectors(salt=SALT)


def test_a_matched_segment_and_tool_name_carry_no_digest():
    units = [ScanUnit(f"tool_input.{FAKE_SSN}", TOOL, f"key {FAKE_AWS_KEY}")]
    findings = scan(units, _detectors()).findings
    assert findings
    shown = json.dumps([f.to_log() for f in findings]) + repr(findings)
    assert_no_digest(shown, TOOL)
    assert {f.locator for f in findings} == {"tool_input.<redacted>"}
    assert {f.tool_name for f in findings} == {"<redacted>"}


def test_a_matched_run_of_segments_carries_no_digest():
    """Each of `123`, `45` and `6789` is clean alone; the dotted run matches."""
    loc = f"tool_input.{SSN_DOTTED}.x"
    out = _scrub_locator(loc, _detectors())
    assert_no_digest(out, loc)
    assert out == "tool_input.<redacted>.x"


def test_an_oversized_locator_carries_no_digest():
    loc = "a." * 600 + FAKE_SSN
    out = _scrub_locator(loc, _detectors())
    assert_no_digest(out, loc)
    assert out == "<redacted>"


def test_the_truncated_locator_warning_carries_no_digest(caplog):
    units = frame_units([
        {"role": "user", "content": [
            {"type": "tool_result",
             "content": {FAKE_SSN: "a" * (MAX_UNIT_BYTES * 2)}}]},
    ])
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.core"):
        result = scan(units, _detectors())
    (warned,) = [r for r in caplog.records
                 if r.getMessage().startswith("value over the size limit")]
    shown = repr(warned.fields) + repr(result.truncated) + caplog.text
    assert_no_digest(shown)
    assert result.truncated == ["msg[0].content[0].content.<redacted>"]


def test_a_scrub_a_detector_fails_on_carries_no_digest():
    class _Failing:
        tier = 0
        name = "failing"

        def scan(self, units):
            from forgd_verdict.detectors.base import DetectorFailed
            raise DetectorFailed("failing: boom")

    out = _scrub_locator(f"msg[0].{FAKE_SSN}", [_Failing()])
    assert_no_digest(out)
    assert out == "msg[0].<redacted>"


class _Raises:
    tier = 0
    finding_prefix = "zebra"

    def available(self):
        return True

    def finding_ids(self):
        return ["zebra:stripe"]

    def scan(self, units):
        raise ValueError("boom")


def test_a_plugin_failing_in_the_label_scrub_leaves_no_digest():
    det = PluginDetector("zebra", _Raises(), "block", lambda t: t)
    out = scrub_plugin_label(TOOL, [], [det])
    assert_no_digest(out, TOOL)
    assert out == "<redacted>"


def test_an_unrecognised_attribute_name_on_stats_carries_no_digest():
    from forgd_verdict.otel.extract import unrecognised_keys
    from forgd_verdict.otel.payload import OtelRecord

    name = f"user_{FAKE_SSN}"
    rec = OtelRecord(kind="log", name="evt", attributes={name: "x" * 80}, resource={})
    keys = unrecognised_keys(rec, _detectors())
    assert_no_digest(json.dumps(keys), name)
    assert keys == ["<redacted>"]


def test_hook_units_carry_no_digest():
    payload = {"hook_event_name": "PreToolUse", "tool_name": TOOL,
               "tool_input": {"env": {FAKE_SSN: f"export TOKEN={FAKE_AWS_KEY}"}}}
    findings = scan(hook_units(payload), _detectors()).findings
    assert findings
    assert_no_digest(json.dumps([f.to_log() for f in findings]), TOOL)
    assert all(FAKE_SSN not in f.locator for f in findings)


async def test_the_verdict_server_logs_and_stores_no_digest(tmp_path):
    from forgd_verdict.applog import configure_logging
    from forgd_verdict.server.app import VerdictServer
    from forgd_verdict.store.local import LocalFileStore

    stream = io.StringIO()
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC]},
        privacy={"hash_salt": SALT},
    )
    store = LocalFileStore(tmp_path, instance="t")
    server = VerdictServer(policy, logger=configure_logging("DEBUG", stream=stream),
                           store=store)
    client = ASGIClient(server)
    messages = [{"role": "assistant", "content": [
        {"type": "tool_use", "id": "toolu_01", "name": TOOL,
         "input": {FAKE_SSN: f"key {FAKE_AWS_KEY}", SSN_DOTTED: {"v": FAKE_AWS_KEY}}}]}]
    raw = json.dumps(frame(messages)).encode()
    status, verdict = await client.post("/hook", raw, sign(raw))
    assert status == 200 and verdict["action"] == "deny"
    server.close()

    logs = stream.getvalue()
    rows = "".join(p.read_text(errors="replace") for p in tmp_path.rglob("*") if p.is_file())
    for label, shown in (("verdict", json.dumps(verdict)), ("log", logs), ("store", rows)):
        assert FAKE_SSN not in shown, label
        assert_no_digest(shown, TOOL)
    logged = [json.loads(line) for line in logs.splitlines() if line.strip()]
    findings = next(e["findings"] for e in logged if e.get("findings"))
    assert any("<redacted>" in f["locator"] for f in findings)
    assert "<redacted>" in rows
