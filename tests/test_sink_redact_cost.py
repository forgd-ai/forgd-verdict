"""What one `redact_events` call costs, counted against the batch size."""

from __future__ import annotations

import collections
import subprocess
import traceback

import pytest
from conftest import FAKE_AWS_KEY

from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.otel.extract import record_units_by_key
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.redact import (
    RedactGroup,
    RedactionContext,
    RedactionPlan,
    index_findings,
    redact_events,
    redact_groups,
)

NAMES = ("alphanote", "betanote", "gammanote")


class CountingT0(T0RegexDetector):
    """The real T0 detector, recording the text of every unit it is handed."""

    def __init__(self) -> None:
        super().__init__()
        self.seen: collections.Counter[str] = collections.Counter()

    def scan(self, units):
        units = list(units)
        self.seen.update(u.text for u in units)
        return super().scan(units)


def _redact(records, detectors):
    cfg = SinkConfig(name="s", endpoint="https://collector.test")
    found = []
    for index, record in enumerate(records):
        units = [u for _, u in record_units_by_key(record, index)]
        found.extend(T0RegexDetector().scan(units))
    plan = RedactionPlan.build(cfg, [d.name for d in detectors])
    return redact_events(records, index_findings(found), plan, cfg,
                         surface="s", org="o", observed_at="2026-10-05T00:00:00Z",
                         detectors=detectors)


def _name_probes(n: int) -> dict[str, int]:
    det = CountingT0()
    records = [OtelRecord(kind="log", name="evt",
                          attributes={k: f"plain value {k} {i}" for k in NAMES})
               for i in range(n)]
    out = _redact(records, [det])
    assert len(out) == n
    return {k: det.seen[k] for k in NAMES}


def test_each_attribute_name_is_probed_a_number_of_times_independent_of_the_batch():
    few, many = _name_probes(5), _name_probes(50)
    assert all(few.values()), few
    assert many == few, f"N=5: {few}  N=50: {many}"


def _gitleaks_runs(records, tmp_path, monkeypatch) -> list[tuple[str, bytes]]:
    """Redact `records` with T0 and a subprocess gitleaks whose launches are
    faked, and return each launch as (redact.py caller, stdin)."""
    binary = tmp_path / "gitleaks"
    binary.write_text("#!/bin/sh\nexit 1\n")
    binary.chmod(0o755)
    calls = []

    def run(cmd, *, input=b"", **kw):
        callers = [f.name for f in traceback.extract_stack()
                   if f.filename.endswith(("sink/redact.py", "forgd_verdict/core.py"))]
        calls.append((callers[-1] if callers else "?", input))
        return subprocess.CompletedProcess(cmd, 0, stdout=b"[]", stderr=b"")

    monkeypatch.setattr("forgd_verdict.detectors.gitleaks.subprocess.run", run)
    gitleaks = GitleaksDetector(binary=str(binary))
    assert gitleaks.available() and not gitleaks.uses_daemon
    _redact(records, [T0RegexDetector(), gitleaks])
    return calls


def _name_launches(n: int, tmp_path, monkeypatch) -> int:
    tmp_path = tmp_path / f"n{n}"
    tmp_path.mkdir()
    records = [OtelRecord(kind="log", name=f"evt{i % 3}",
                          attributes={"note": f"nothing to see here {i}"})
               for i in range(n)]
    calls = _gitleaks_runs(records, tmp_path, monkeypatch)
    assert not [c for c, _ in calls if c == "_still_matches"]
    return len(calls)


def test_gitleaks_launches_grow_with_distinct_event_names_not_records(tmp_path,
                                                                      monkeypatch):
    few = _name_launches(5, tmp_path, monkeypatch)
    many = _name_launches(50, tmp_path, monkeypatch)
    # One name scrub, one attribute-name guard probe and one event-name scan
    # per distinct event name.
    assert few == many == 1 + 1 + 3, f"N=5: {few} launches  N=50: {many} launches"


def test_the_backstop_scans_each_masked_value_on_its_own(tmp_path, monkeypatch):
    k = 7
    records = [OtelRecord(kind="log", name="evt",
                          attributes={"user.message": f"deploy with {FAKE_AWS_KEY} now {i}"})
               for i in range(k)]
    calls = _gitleaks_runs(records, tmp_path, monkeypatch)
    backstop = [stdin for c, stdin in calls if c == "_still_matches"]
    assert len(backstop) == k
    for stdin in backstop:
        assert stdin.count(b"[redacted:regex:") == 1
        assert FAKE_AWS_KEY.encode() not in stdin


class FailsOnNameBatches(T0RegexDetector):
    """The real T0 detector, raising when one scan holds two or more of
    `names`."""

    def __init__(self, names) -> None:
        super().__init__()
        self.names = set(names)

    def scan(self, units):
        units = list(units)
        if len(self.names & {u.text for u in units}) > 1:
            raise RuntimeError("probe failed")
        return super().scan(units)


def test_a_failed_name_probe_masks_the_value_under_the_name():
    record = OtelRecord(kind="log", name="evt",
                        attributes={"alphanote": "plain value here", "betanote": "tiny"})
    (event,) = _redact([record], [FailsOnNameBatches(record.attributes)])
    assert event.attributes["[redacted:metadata-name:0]"] == (
        "[redacted:metadata-name:whole-value]")
    assert "alphanote" not in event.attributes
    assert event.redactions["metadata-name-value"] == 1


def _groups(n: int):
    """`n` one-record groups whose identity value under `user.email` is
    the fake key in every third group."""
    groups = []
    for i in range(n):
        record = OtelRecord(kind="log", name="evt", attributes={
            **{k: f"plain value number {i}" for k in NAMES},
            "user.email": FAKE_AWS_KEY if i % 3 == 0 else f"u{i}@example.com"})
        units = [u for _, u in record_units_by_key(record, 0)]
        groups.append(RedactGroup([record], index_findings(T0RegexDetector().scan(units)),
                                  "s"))
    return groups


def _redact_groups(groups, detectors, context=None):
    cfg = SinkConfig(name="s", endpoint="https://collector.test")
    plan = RedactionPlan.build(cfg, [d.name for d in detectors])
    if context is not None:
        context = context(detectors, plan)
    return redact_groups(groups, plan, cfg, org="o", observed_at="2026-10-05T00:00:00Z",
                         detectors=detectors, context=context)


def _group_cost(n: int, monkeypatch) -> tuple[dict[str, int], int]:
    det = CountingT0()
    calls = collections.Counter()
    real = MetadataGuard.matches

    def matches(self, values):
        calls["matches"] += 1
        return real(self, values)

    monkeypatch.setattr(MetadataGuard, "matches", matches)
    out = _redact_groups(_groups(n), [det])
    assert len(out) == n
    return {k: det.seen[k] for k in NAMES}, calls["matches"]


def test_one_call_over_many_groups_probes_names_and_identity_values_once(monkeypatch):
    few_names, few_guard = _group_cost(5, monkeypatch)
    many_names, many_guard = _group_cost(50, monkeypatch)
    assert all(few_names.values()), few_names
    assert many_names == few_names, f"N=5: {few_names}  N=50: {many_names}"
    assert many_guard == few_guard, f"guard calls N=5: {few_guard}  N=50: {many_guard}"


def test_gitleaks_launches_do_not_grow_with_the_groups(tmp_path, monkeypatch):
    def launches(n):
        d = tmp_path / f"g{n}"
        d.mkdir()
        binary = d / "gitleaks"
        binary.write_text("#!/bin/sh\nexit 1\n")
        binary.chmod(0o755)
        calls = []

        def run(cmd, *, input=b"", **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout=b"[]", stderr=b"")

        monkeypatch.setattr("forgd_verdict.detectors.gitleaks.subprocess.run", run)
        records = [OtelRecord(kind="log", name=f"evt{i % 3}",
                              attributes={"note": f"nothing to see here {i}"})
                   for i in range(n)]
        groups = [RedactGroup([r], {}, "s") for r in records]
        _redact_groups(groups, [T0RegexDetector(), GitleaksDetector(binary=str(binary))])
        return len(calls)

    # One name scrub per group bringing a name not seen before, one event-name
    # scan per distinct event name, and one attribute-name guard probe.
    assert launches(5) == launches(50) == 3 + 3 + 1


def test_redacting_groups_together_matches_redacting_each_alone():
    groups = _groups(9)
    together = _redact_groups(groups, [T0RegexDetector()])
    alone = [e for g in groups for e in _redact_groups([g], [T0RegexDetector()])]
    assert together == alone
    masked = [e for e in together if "metadata" in e.redactions]
    assert len(masked) == 3
    assert all(FAKE_AWS_KEY not in repr(e) for e in together)


def test_a_context_is_reused_across_calls_and_refuses_another_plan():
    detectors = [CountingT0()]
    cfg = SinkConfig(name="s", endpoint="https://collector.test")
    plan = RedactionPlan.build(cfg, [d.name for d in detectors])
    ctx = RedactionContext(detectors, plan)
    after = []
    for g in _groups(4):
        redact_groups([g], plan, cfg, org="o", observed_at="t", detectors=detectors,
                      context=ctx)
        after.append({k: detectors[0].seen[k] for k in NAMES})
    assert all(after[0].values()) and after[-1] == after[0], after
    other = RedactionPlan.build(cfg, [d.name for d in detectors])
    with pytest.raises(ValueError):
        redact_groups([], other, cfg, org="o", observed_at="t", detectors=detectors,
                      context=ctx)


def test_each_group_has_its_own_name_scrub_budget(monkeypatch):
    """Sixty groups of distinct record names together pass one scrub
    budget's bytes; each alone fits, and no clean value is masked. The
    deadline is lifted so only the byte budget applies."""
    monkeypatch.setattr("forgd_verdict.core._SCRUB_BUDGET_S", 60.0)
    groups = [RedactGroup([OtelRecord(kind="log", name=f"claude_code.tool_result.g{g}r{i}",
                                      attributes={f"tool.input.field{j}": "harmless prose"
                                                  for j in range(4)})
                           for i in range(25)], {}, "s")
              for g in range(60)]
    out = _redact_groups(groups, [T0RegexDetector()])
    assert len(out) == 60 * 25
    assert sum(e.redactions.get("metadata-name-value", 0) for e in out) == 0


def test_a_name_past_one_groups_scrub_budget_is_probed_again_in_the_next(monkeypatch):
    """The first group passes the byte budget with the deadline lifted."""
    monkeypatch.setattr("forgd_verdict.core._SCRUB_BUDGET_S", 60.0)

    def record(name):
        return OtelRecord(kind="log", name=name, attributes={
            f"tool.input.field{j}": "harmless prose" for j in range(4)})

    last = "claude_code.tool_result.last"
    first = RedactGroup([*(record(f"claude_code.tool_result.r{i}") for i in range(1500)),
                         record(last)], {}, "s")
    second = RedactGroup([record(last)], {}, "s")
    out = _redact_groups([first, second], [T0RegexDetector()])
    assert out[1500].redactions.get("metadata-name-value", 0) == 4
    assert out[-1].redactions.get("metadata-name-value", 0) == 0
