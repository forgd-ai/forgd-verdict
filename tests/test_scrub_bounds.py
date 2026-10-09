"""The locator scrub after detection cannot raise, cannot delay the
decision past a hook timeout, and never leaves a locator unscrubbed.

Each scrub call is bounded by the bytes it probes and builds and by the
detector calls it makes, counted rather than timed. The end-to-end tests
also hold the decision to the deadline its caller sets: 10 s for Claude
Code's hook in every shipped config, and the org's 5 s verdict timeout for
the verdict server.
"""

from __future__ import annotations

import json
import math
import shutil
import time
from types import SimpleNamespace

import pytest
from conftest import WHSEC, ASGIClient, frame, make_policy, sign
from test_otel_collector import auth
from test_otel_collector import make_policy as collector_policy
from test_otel_payload import RESOURCE, logs_json

from forgd_verdict import core
from forgd_verdict.core import REDACTED, _scrub_names, decide, scan
from forgd_verdict.detectors.base import TIER_T1, DetectorFailed
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.hook.cli import run
from forgd_verdict.models import ACTION_DENY, Finding, ScanUnit
from forgd_verdict.otel.app import Collector
from forgd_verdict.server.app import VerdictServer
from forgd_verdict.sink import redact
from forgd_verdict.store.local import LocalFileStore

# Bounds on time and memory: run alone, after the parallel suite.
pytestmark = pytest.mark.serial

KEY = "AKIAIOSFODNN7EXAMPLE"  # gitleaks:allow
HOOK_TIMEOUT_S = 10.0
VERDICT_TIMEOUT_S = 5.0
# `scan` scrubs its findings' locators in one call; an export adds the
# `scrub_labels` call over its unrecognised attribute names.
SCRUBS_PER_SCAN = 1
SCRUBS_PER_EXPORT = 2
GITLEAKS = shutil.which("gitleaks")
needs_gitleaks = pytest.mark.skipif(GITLEAKS is None, reason="gitleaks not on PATH")

# 5 digits and 25 kanji: 30 characters, 80 bytes of UTF-8 per segment.
MULTIBYTE = "漢" * 25
ASCII = "a" * 25


# A locator of more than `MAX_LOCATOR_SEGMENTS` segments is redacted whole without
# probing, so each fixture keeps prefix plus key at 32 segments or fewer:
# `tool_input.` is one, `msg[i].content[j].input.` and
# `otel[i].claude_code.user_prompt.` are three.
def dotted_key(k: int, segments: int, filler: str) -> str:
    return ".".join(f"{k:02d}{i:03d}{filler}" for i in range(segments))


def gitleaks_detectors() -> dict:
    return {"gitleaks": {"enabled": True, "severity": "block", "binary": GITLEAKS}}


def tool_event(tool_input: dict) -> dict:
    return {
        "session_id": "abc123",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": tool_input,
        "tool_use_id": "toolu_01ABC",
        "permission_mode": "default",
    }


def keyed_input(keys: int, segments: int, filler: str) -> dict:
    """`echo <key>` plus `keys` dotted keys, each holding the key, so every
    dotted key is a finding locator the scrub probes."""
    return {"command": f"echo {KEY}",
            **{dotted_key(k, segments, filler): KEY for k in range(keys)}}


def hook_denies(code: int, out: str) -> bool:
    return (code == 0 and bool(out)
            and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny")


def utf8(texts) -> int:
    return sum(len(t.encode("utf-8", "replace")) for t in texts)


class ProbeSpy:
    """Records each `core._probe` call: its batch limit and the UTF-8 bytes
    of every detector call it makes, by detector."""

    def __init__(self, monkeypatch):
        self.probes: list[tuple[int, dict[int, list[int]]]] = []
        self._open: dict[int, list[int]] | None = None
        probe, hits = core._probe, core._detector_hits

        def spy_probe(texts, cheap, *args, **kwargs):
            calls: dict[int, list[int]] = {}
            self.probes.append((core._batch_limit(cheap), calls))
            self._open = calls
            try:
                return probe(texts, cheap, *args, **kwargs)
            finally:
                self._open = None

        def spy_hits(det, texts):
            if self._open is not None:
                self._open.setdefault(id(det), []).append(utf8(texts))
            return hits(det, texts)

        monkeypatch.setattr(core, "_probe", spy_probe)
        monkeypatch.setattr(core, "_detector_hits", spy_hits)

    def assert_bounded(self, scrubs: int) -> None:
        """At most `scrubs` scrub calls, each handing every detector at most
        `_SCRUB_BUDGET_BYTES`, in no more batches than that many bytes fill."""
        assert 0 < len(self.probes) <= scrubs, f"{len(self.probes)} scrub calls"
        budget = core._SCRUB_BUDGET_BYTES
        for limit, calls in self.probes:
            for sizes in calls.values():
                assert sum(sizes) <= budget, f"one scrub probed {sum(sizes)} bytes"
                # Two consecutive batches together exceed `limit`.
                assert len(sizes) <= 2 * (budget // limit) + 1, (
                    f"one scrub made {len(sizes)} calls to one detector")


class BuildSpy:
    """Records, for each `_scrub_names` call, the UTF-8 bytes of every list
    `core._candidates` and `core._run_candidates` return during it."""

    def __init__(self, monkeypatch, *importers):
        self.scrubs: list[list[int]] = []
        self._open: list[int] | None = None
        names = core._scrub_names

        def spy_names(*args, **kwargs):
            self._open = []
            self.scrubs.append(self._open)
            try:
                return names(*args, **kwargs)
            finally:
                self._open = None

        def spy_build(real):
            def build(*args, **kwargs):
                out = real(*args, **kwargs)
                if self._open is not None:
                    self._open.append(utf8(out))
                return out
            return build

        for module in (core, *importers):
            monkeypatch.setattr(module, "_scrub_names", spy_names)
        monkeypatch.setattr(core, "_candidates", spy_build(core._candidates))
        monkeypatch.setattr(core, "_run_candidates", spy_build(core._run_candidates))

    def assert_bounded(self) -> None:
        """Each call built at most `_SCRUB_BUILD_FACTOR` budgets before its
        last locator started, and that locator at most a budget plus the
        one list that took it past."""
        budget = core._SCRUB_BUDGET_BYTES
        assert self.scrubs, "no scrub call"
        for sizes in self.scrubs:
            bound = (core._SCRUB_BUILD_FACTOR + 1) * budget + max(sizes, default=0)
            assert sum(sizes) <= bound, f"one scrub built {sum(sizes)} bytes"


class Clock:
    """A stand-in for the `time` module `core` reads: `monotonic()` moves
    only when `advance` is called."""

    def __init__(self, monkeypatch):
        self.now = 0.0
        monkeypatch.setattr(core, "time", SimpleNamespace(monotonic=lambda: self.now))

    def advance(self, seconds: float) -> None:
        self.now += seconds


class ScrubOnly:
    """A built-in-shaped cheap tier that behaves normally on the scan's own
    units and differently on the scrub's, whose locators are bare indexes."""

    name = "fake-scrub"
    tier = TIER_T1
    severity = "block"

    def scan(self, units):
        units = list(units)
        if units and all(u.locator.isdigit() for u in units):
            return self.on_scrub(units)
        return []

    def on_scrub(self, units):
        return []


class FailsOnScrub(ScrubOnly):
    def on_scrub(self, units):
        raise DetectorFailed("saw only part of the input and found nothing")


HIDDEN = "zzhiddenzz0123"


class SeesHidden(ScrubOnly):
    """Matches `HIDDEN` and records the UTF-8 bytes of every scrub call."""

    def __init__(self):
        self.calls: list[int] = []

    def on_scrub(self, units):
        self.calls.append(utf8(u.text for u in units))
        return [Finding(detector=self.name, severity=self.severity, locator=u.locator,
                        excerpt_hash="h") for u in units if HIDDEN in u.text]


# -- 1. multibyte keys: the scrub cannot raise --------------------------


@needs_gitleaks
def test_multibyte_dotted_keys_still_deny_on_the_hook():
    """Probe text batched by characters overflowed gitleaks' 8 MiB of
    UTF-8; its `DetectorFailed` left `scan()` and the hook exited 1."""
    policy = make_policy(detectors=gitleaks_detectors())
    code, out = run(tool_event(keyed_input(40, 29, MULTIBYTE)), policy)
    assert hook_denies(code, out), (code, out[:200])


def test_a_detector_failing_only_in_the_scrub_does_not_raise_out_of_scan():
    units = [ScanUnit(locator="tool_input.command", tool_name="Bash", text=f"echo {KEY}"),
             ScanUnit(locator=f"tool_input.{dotted_key(0, 3, ASCII)}", tool_name="Bash",
                      text=KEY)]
    result = scan(units, [T0RegexDetector(), FailsOnScrub()])
    assert any(f.detector.startswith("regex:aws") for f in result.findings)
    assert decide(result.findings, make_policy()).action == ACTION_DENY


# -- 2. many long dotted keys: the decision is bounded in time -----------


@needs_gitleaks
def test_long_dotted_keys_decide_within_the_bound_on_the_hook(monkeypatch):
    policy = make_policy(detectors=gitleaks_detectors())
    event = tool_event(keyed_input(150, 31, ASCII))
    assert len(json.dumps(event)) > 140_000
    spy = ProbeSpy(monkeypatch)
    start = time.monotonic()
    code, out = run(event, policy)
    elapsed = time.monotonic() - start
    assert hook_denies(code, out), (code, out[:200])
    spy.assert_bounded(scrubs=SCRUBS_PER_SCAN)
    assert elapsed < HOOK_TIMEOUT_S, f"{elapsed:.2f}s"


def server_policy(tmp_path):
    return make_policy(
        detectors=gitleaks_detectors(),
        server={"mode": "enforce", "secrets": [WHSEC],
                "csv_path": str(tmp_path / "timings.csv"),
                "archive_dir": str(tmp_path / "archive")})


def tool_use_frame(keys: int, segments: int, filler: str) -> bytes:
    return json.dumps(frame([
        {"role": "user", "content": [{"type": "text", "text": "run it"}]},
        {"role": "assistant", "content": [{
            "type": "tool_use", "id": "toolu_01", "name": "Bash",
            "input": keyed_input(keys, segments, filler)}]},
        {"role": "user", "content": [{"type": "text", "text": "go on"}]},
    ]), ensure_ascii=False).encode()


@needs_gitleaks
@pytest.mark.parametrize(("keys", "segments", "filler"),
                         [(160, 29, ASCII), (40, 29, MULTIBYTE)],
                         ids=["long-ascii", "multibyte"])
async def test_long_dotted_keys_deny_within_the_bound_on_the_server(
        tmp_path, monkeypatch, keys, segments, filler):
    server = VerdictServer(server_policy(tmp_path))
    raw = tool_use_frame(keys, segments, filler)
    spy = ProbeSpy(monkeypatch)
    try:
        start = time.monotonic()
        status, body = await ASGIClient(server).post("/hook", raw, sign(raw))
        elapsed = time.monotonic() - start
    finally:
        server.close()
    assert status == 200, (status, str(body)[:200])
    assert body["action"] == "deny"
    spy.assert_bounded(scrubs=SCRUBS_PER_SCAN)
    assert elapsed < VERDICT_TIMEOUT_S, f"{elapsed:.2f}s"


# -- 3. the collector: bounded, never a 503 -----------------------------


def export(records: int, keys: int, segments: int, filler: str, value: str) -> bytes:
    return logs_json([{
        "attributes": {
            "event.name": "claude_code.user_prompt",
            "prompt": f"deploy with {KEY}",
            "session.id": f"sess-{r}",
            "prompt.id": f"turn-{r}",
            **{dotted_key(k, segments, filler): value for k in range(keys)},
        },
        "body": "",
    } for r in range(records)], RESOURCE)


def collector_with(tmp_path, monkeypatch, **otel) -> Collector:
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    policy = collector_policy(**otel)
    policy.raw["detectors"]["gitleaks"] = gitleaks_detectors()["gitleaks"]
    return Collector(policy, store=LocalFileStore(tmp_path / "findings", instance="test"))


async def post(collector, body):
    return await ASGIClient(collector).post("/v1/logs", body, auth())


@needs_gitleaks
@pytest.mark.parametrize(("keys", "segments", "filler"),
                         [(160, 29, ASCII), (40, 29, MULTIBYTE)],
                         ids=["long-ascii", "multibyte"])
async def test_an_export_with_findings_is_accepted_within_the_bound(
        tmp_path, monkeypatch, keys, segments, filler):
    collector = collector_with(tmp_path, monkeypatch)
    body = export(1, keys, segments, filler, KEY)
    spy = ProbeSpy(monkeypatch)
    try:
        status, out = await post(collector, body)
    finally:
        collector.close()
    assert status == 200, (status, str(out)[:200])
    spy.assert_bounded(scrubs=SCRUBS_PER_EXPORT)


@needs_gitleaks
async def test_benign_attribute_names_with_a_sink_are_accepted_within_the_bound(
        tmp_path, monkeypatch):
    """With a sink configured, `redact_events` scrubbed the locator of every
    unit, findings or not."""
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    policy = collector_policy()
    policy.raw["detectors"]["gitleaks"] = gitleaks_detectors()["gitleaks"]
    policy.raw["sinks"] = [{"name": "siem", "type": "otlp",
                            "endpoint": "https://collector.test",
                            "redact": ["regex"]}]
    collector = Collector(policy, store=LocalFileStore(tmp_path / "findings", instance="test"))
    body = logs_json([{
        "attributes": {
            "event.name": "claude_code.user_prompt",
            "prompt": "refactor the auth middleware",
            "session.id": "sess-1",
            "prompt.id": "turn-1",
            **{dotted_key(k, 29, ASCII): "an ordinary value" for k in range(160)},
        },
        "body": "",
    }], RESOURCE)
    assert len(body) > 100_000
    probes, built = ProbeSpy(monkeypatch), BuildSpy(monkeypatch, redact)
    try:
        assert collector.forwarders, "no sink configured"
        status, out = await post(collector, body)
    finally:
        collector.close()
    assert status == 200, (status, str(out)[:200])
    # The sink's redaction scrubs every unit's name once more.
    probes.assert_bounded(scrubs=SCRUBS_PER_EXPORT + 1)
    built.assert_bounded()


# -- 4. past the budget, no locator is left unscrubbed -------------------


def test_locators_past_the_scrub_budget_are_redacted_whole_not_passed_raw(monkeypatch):
    """`SeesHidden` alone knows `HIDDEN`, and every locator's candidates are
    over the byte budget. The clock does not move, so only the byte budget
    bounds the probe, and `scan` scrubs once. Whatever the scrub does not reach must come out
    redacted, so `HIDDEN` appears in no locator."""
    Clock(monkeypatch)
    det = SeesHidden()
    units = [ScanUnit(locator=f"tool_input.{dotted_key(k, 30, HIDDEN[:8])}.{HIDDEN}",
                      tool_name="Bash", text=KEY)
             for k in range(50)]
    result = scan(units, [T0RegexDetector(), det])
    assert len(result.findings) >= 50
    assert decide(result.findings, make_policy()).action == ACTION_DENY
    leaked = [f.locator for f in result.findings if HIDDEN in (f.locator or "")]
    assert not leaked, leaked[:3]
    assert sum(det.calls) <= core._SCRUB_BUDGET_BYTES, f"probed {sum(det.calls)} bytes"


class TenthPerCall(ScrubOnly):
    """Matches `HIDDEN`, reads at most 16 KiB per call, and advances `clock`
    0.1 s a call."""

    max_bytes = 16 * 1024
    step = 0.1

    def __init__(self, clock: Clock):
        self.clock = clock
        self.calls = 0

    def on_scrub(self, units):
        self.calls += 1
        self.clock.advance(self.step)
        return [Finding(detector=self.name, severity=self.severity, locator=u.locator,
                        excerpt_hash="h") for u in units if HIDDEN in u.text]


def test_locators_past_the_scrub_deadline_are_redacted_whole_not_passed_raw(monkeypatch):
    det = TenthPerCall(Clock(monkeypatch))
    units = [ScanUnit(locator=f"tool_input.{dotted_key(k, 8, HIDDEN[:8])}.{HIDDEN}",
                      tool_name="Bash", text=KEY)
             for k in range(200)]
    result = scan(units, [T0RegexDetector(), det])
    assert len(result.findings) >= 200
    leaked = [f.locator for f in result.findings if HIDDEN in (f.locator or "")]
    assert not leaked, leaked[:3]
    allowed = math.ceil(core._SCRUB_BUDGET_S / det.step) + 1
    assert det.calls <= allowed, f"{det.calls} detector calls; the deadline allows {allowed}"


class CapsBytes(ScrubOnly):
    """Records the UTF-8 bytes of every scrub call; fails past `max_bytes`."""

    max_bytes = 64 * 1024

    def __init__(self):
        self.calls: list[int] = []

    def on_scrub(self, units):
        n = sum(len(u.text.encode("utf-8")) for u in units)
        self.calls.append(n)
        if n > self.max_bytes:
            raise DetectorFailed("over max_bytes")
        return []


def test_scrub_batches_are_sized_in_utf8_bytes_under_the_detectors_cap():
    det = CapsBytes()
    units = [ScanUnit(locator=f"tool_input.{dotted_key(k, 10, MULTIBYTE)}",
                      tool_name="Bash", text=KEY)
             for k in range(5)]
    result = scan(units, [T0RegexDetector(), det])
    assert len(det.calls) > 1
    assert max(det.calls) <= det.max_bytes
    assert all(f.locator.startswith("tool_input.") for f in result.findings)


# -- building the candidates ---------------------------------------------


def test_candidates_stop_being_built_once_the_byte_budget_is_spent(monkeypatch):
    """2k locators of 29 dotted 29-character segments: each one's candidates
    are larger than what is left of the budget, and were all built before
    any was checked against it. The clock does not move, so only the byte
    budgets bound the build."""
    Clock(monkeypatch)
    built = BuildSpy(monkeypatch)
    locs = [".".join(f"{k:05d}{i:03d}" + "a" * 21 for i in range(29)) for k in range(2000)]
    out, _ = core._scrub_names(locs, [], [T0RegexDetector()])
    assert set(out.values()) <= {REDACTED, *locs}
    built.assert_bounded()


def test_a_locator_over_the_segment_cap_is_redacted_without_being_split(monkeypatch):
    split = []
    real = str.split

    class Watched(str):
        def split(self, *a, **kw):
            split.append(len(self))
            return real(self, *a, **kw)

    loc = Watched(".".join(["a"] * 2_000_000))
    out, _ = _scrub_names([loc], [], [T0RegexDetector()])
    assert out[loc] == REDACTED
    assert split == []


def test_nothing_is_built_past_the_deadline(monkeypatch):
    built = []
    real = core._candidates
    monkeypatch.setattr(core, "_SCRUB_BUDGET_S", 0.0)
    monkeypatch.setattr(core, "_candidates", lambda t, **kw: built.append(t) or real(t, **kw))
    out, tools = _scrub_names([f"tool_input.key_number_{i}" for i in range(50)],
                              ["send_message", "Bash"], [T0RegexDetector()])
    assert set(out.values()) == {REDACTED}
    assert tools == {"send_message": REDACTED, "Bash": "Bash"}
    assert built == []


def test_a_short_tool_name_survives_a_spent_budget(monkeypatch):
    monkeypatch.setattr(core, "_SCRUB_BUDGET_BYTES", 0)
    _, tools = _scrub_names([], ["Bash", "Write", "a_long_tool_name"], [T0RegexDetector()])
    assert tools == {"Bash": "Bash", "Write": "Write", "a_long_tool_name": REDACTED}
