"""What forwarding one OTLP export costs, counted against the turns it holds.

Each export goes through the collector's real `/v1/logs` path with one
sink configured. Every count is taken at 50 and at 500 single-record turns
and the two are compared: a count that grows with the turns is a per-turn
cost.
"""

from __future__ import annotations

import collections
import json
import math
import subprocess
import textwrap
import traceback

import pytest
from conftest import ASGIClient
from test_sink_late import FakeNER

from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.otel.app import Collector
from forgd_verdict.policy import load_policy
from forgd_verdict.sink import factory
from forgd_verdict.sink.fake import FakeSink

ORG = "00000000-0000-0000-0000-000000000001"
TOKEN = "a-token-long-enough-to-be-one"
NAMES = ("alphanote", "betanote", "gammanote")
MAX_EVENTS = 7
SENDERS = {"attributed": "claude_code.user_prompt", "unattributed": "generic.note"}


def _from_redact() -> str | None:
    """The innermost `sink/redact.py` function on the stack, if any."""
    frames = [f.name for f in traceback.extract_stack()
              if f.filename.endswith("sink/redact.py")]
    return frames[-1] if frames else None


class CountingT0(T0RegexDetector):
    """The real T0 detector, recording each text redaction hands it."""

    def __init__(self) -> None:
        super().__init__()
        self.seen: collections.Counter[str] = collections.Counter()

    def scan(self, units):
        units = list(units)
        if _from_redact():
            self.seen.update(u.text for u in units)
        return super().scan(units)

    def name_probes(self) -> int:
        return sum(n for text, n in self.seen.items() if any(k in text for k in NAMES))


class Harness:
    """A collector with one fake sink, counting what each export costs."""

    def __init__(self, tmp_path, monkeypatch, *, late: bool) -> None:
        binary = tmp_path / "gitleaks"
        binary.write_text("#!/bin/sh\nexit 1\n")
        binary.chmod(0o755)
        self.counts: collections.Counter[str] = collections.Counter()

        def run(cmd, *, input=b"", **kw):
            caller = _from_redact()
            if caller is None:
                self.counts["launches_detection"] += 1
            elif caller == "_still_matches":
                self.counts["launches_backstop"] += 1
            else:
                self.counts["launches_redact"] += 1
            return subprocess.CompletedProcess(cmd, 0, stdout=b"[]", stderr=b"")

        monkeypatch.setattr("forgd_verdict.detectors.gitleaks.subprocess.run", run)
        for method in ("matches", "many", "one", "record", "records"):
            self._count(monkeypatch, method)

        real_build = factory.build_forwarders

        def build(*a, **kw):
            assert "background" not in kw
            return real_build(*a, background=False, **kw)

        monkeypatch.setattr(factory, "build_forwarders", build)

        pol = tmp_path / "policy.yaml"
        pol.write_text(textwrap.dedent(f"""
            privacy: {{hash_salt: test-salt}}
            server: {{store: ""}}
            otel:
              orgs:
                - {{name: demo, id: "{ORG}", token: {TOKEN}}}
            sinks:
              - name: siem
                type: otlp
                endpoint: https://collector.test
        """), encoding="utf-8")
        self.t0 = CountingT0()
        gitleaks = GitleaksDetector(binary=str(binary))
        assert gitleaks.available() and not gitleaks.uses_daemon
        self.app = Collector(load_policy(str(pol)), store=None,
                             detectors=[self.t0, gitleaks],
                             late_detectors=[FakeNER()] if late else [])
        (self.fwd,) = self.app.forwarders
        assert (self.fwd.late is not None) == late
        self.sink = FakeSink(max_events=MAX_EVENTS, max_bytes=10_000_000)
        self.fwd.pipeline.sink = self.sink

    def _count(self, monkeypatch, method: str) -> None:
        real = getattr(MetadataGuard, method, None)
        if real is None:
            return
        counts = self.counts

        def counted(guard, *a, **kw):
            counts[f"guard.{method}"] += 1
            if _from_redact():
                counts[f"guard.{method}_redact"] += 1
            return real(guard, *a, **kw)

        monkeypatch.setattr(MetadataGuard, method, counted)

    async def export(self, turns: int, sender: str, first: int = 0) -> int:
        body = json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [
            {"attributes": [
                {"key": "event.name", "value": {"stringValue": SENDERS[sender]}},
                {"key": "prompt.id", "value": {"stringValue": f"turn-{first + i}"}},
                *({"key": k, "value": {"stringValue": f"plain value {first + i}"}}
                  for k in NAMES),
            ]} for i in range(turns)]}]}]}).encode()
        status, _ = await ASGIClient(self.app).post(
            "/v1/logs", body, {"authorization": f"Bearer {TOKEN}",
                               "content-type": "application/json"})
        assert status == 200
        return turns

    def deliver(self) -> int:
        """Drain the late stage, flush the pipeline; events the sink holds."""
        if self.fwd.late is not None:
            self.fwd.late.drain()
        self.fwd.pipeline.flush()
        return len(self.sink.events)

    def snapshot(self) -> dict[str, int]:
        out = dict(self.counts)
        out["name_probes"] = self.t0.name_probes()
        out["sends"] = len(self.sink.batches)
        return out

    def close(self) -> None:
        self.app.close()


async def _cost(tmp_path, monkeypatch, turns: int, *, late: bool, sender: str):
    d = tmp_path / f"t{turns}-{'late' if late else 'inline'}-{sender}"
    d.mkdir()
    with monkeypatch.context() as m:
        h = Harness(d, m, late=late)
        try:
            await h.export(turns, sender)
            assert h.deliver() == turns
            return h.snapshot()
        finally:
            h.close()


VARIANTS = [pytest.param(late, sender, id=f"{'late' if late else 'inline'}-{sender}")
            for late in (False, True) for sender in SENDERS]


# The counts stop growing at core._SCRUB_BUDGET_S, which a starved worker reaches.
pytestmark = pytest.mark.serial

@pytest.fixture(scope="module")
def _memo():
    return {}


@pytest.fixture
def cost(tmp_path, monkeypatch, _memo):
    async def get(late: bool, sender: str):
        key = (late, sender)
        if key not in _memo:
            _memo[key] = (await _cost(tmp_path, monkeypatch, 50, late=late, sender=sender),
                          await _cost(tmp_path, monkeypatch, 500, late=late, sender=sender))
        return _memo[key]
    return get


def _flat(few: dict, many: dict, key: str) -> None:
    assert many.get(key, 0) == few.get(key, 0), (
        f"{key}: 50 turns {few.get(key, 0)}  500 turns {many.get(key, 0)}")


@pytest.mark.parametrize("late, sender", VARIANTS)
async def test_name_probes_do_not_grow_with_the_turns(cost, late, sender):
    few, many = await cost(late, sender)
    assert few["name_probes"] > 0
    _flat(few, many, "name_probes")


@pytest.mark.parametrize("late, sender", VARIANTS)
async def test_redaction_launches_gitleaks_a_fixed_number_of_times_per_export(
        cost, late, sender):
    few, many = await cost(late, sender)
    assert few.get("launches_redact", 0) > 0
    _flat(few, many, "launches_redact")


@pytest.mark.parametrize("late, sender", VARIANTS)
async def test_the_metadata_guard_is_called_a_fixed_number_of_times_per_export(
        cost, late, sender):
    few, many = await cost(late, sender)
    _flat(few, many, "guard.matches")


@pytest.mark.parametrize("late, sender", VARIANTS)
async def test_verdicts_are_cleaned_in_a_fixed_number_of_calls(cost, late, sender):
    few, many = await cost(late, sender)
    calls = {k: v.get("guard.record", 0) + v.get("guard.records", 0)
             for k, v in (("few", few), ("many", many))}
    assert calls["few"] > 0
    assert calls["many"] == calls["few"], calls


@pytest.mark.parametrize("late, sender", VARIANTS)
async def test_reported_as_hints_are_cleaned_in_a_fixed_number_of_calls(
        cost, late, sender):
    few, many = await cost(late, sender)
    assert few.get("guard.many", 0) > 0
    _flat(few, many, "guard.many")


@pytest.mark.parametrize("late", [False, True], ids=["inline", "late"])
async def test_unattributed_hints_are_cleaned_in_a_fixed_number_of_calls(cost, late):
    few, many = await cost(late, "unattributed")
    attributed, _ = await cost(late, "attributed")
    assert attributed.get("guard.one", 0) == 0
    _flat(few, many, "guard.one")


@pytest.mark.parametrize("late, sender", VARIANTS)
async def test_one_export_is_sent_in_as_few_batches_as_the_sink_allows(
        cost, late, sender):
    few, many = await cost(late, sender)
    assert few["sends"] == math.ceil(50 / MAX_EVENTS)
    assert many["sends"] == math.ceil(500 / MAX_EVENTS)


@pytest.mark.parametrize("late", [False, True], ids=["inline", "late"])
async def test_a_second_export_probes_its_names_again(tmp_path, monkeypatch, late):
    h = Harness(tmp_path, monkeypatch, late=late)
    try:
        await h.export(20, "attributed")
        h.deliver()
        first = h.t0.name_probes()
        await h.export(20, "attributed", first=20)
        h.deliver()
        second = h.t0.name_probes() - first
    finally:
        h.close()
    assert first > 0
    assert second == first, f"first export {first}  second export {second}"


@pytest.mark.parametrize("late", [False, True], ids=["inline", "late"])
async def test_exports_queued_between_flushes_are_sent_together(tmp_path, monkeypatch,
                                                                late):
    h = Harness(tmp_path, monkeypatch, late=late)
    try:
        for i in range(30):
            await h.export(1, "attributed", first=i)
        assert h.deliver() == 30
        sends = len(h.sink.batches)
    finally:
        h.close()
    assert sends == math.ceil(30 / MAX_EVENTS)
