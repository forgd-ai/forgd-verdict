"""The metadata guard hands each detector at most an eighth under its
`max_bytes` of candidate text per call, so no value is past the cut."""

from __future__ import annotations

import pytest

from forgd_verdict.detectors.base import TIER_T0, DetectorFailed
from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.metadata import MetadataGuard

MARK = "plantedmarkervalue"


def _pad(i: int) -> str:
    return f"pad{i:06d}" + "q" * 100


class _Gitleaks(GitleaksDetector):
    """gitleaks' own `scan` and `_join`, with a report of every line that
    holds MARK; `daemon` picks the guard's batched or subprocess path."""

    def __init__(self, daemon: bool, **kw):
        super().__init__(daemon="/nonexistent.sock" if daemon else None, **kw)
        self.streams: list[int] = []

    def available(self):
        return True

    def _run(self, stream):
        self.streams.append(len(stream.encode()))
        return [{"StartLine": n, "RuleID": "planted", "Secret": "x"}
                for n, line in enumerate(stream.split("\n"), 1) if MARK in line]


def _values(n: int) -> dict[str, str]:
    values = {f"k{i}": _pad(i) for i in range(n)}
    values["k1"] = f"a{MARK}"
    values[f"k{n - 1}"] = f"z{MARK}"
    return values


@pytest.mark.parametrize("daemon", [True, False], ids=["daemon", "subprocess"])
def test_values_past_max_bytes_are_all_probed(daemon):
    det = _Gitleaks(daemon, max_bytes=4096)
    guard = MetadataGuard([det], allow_subprocess=True)
    values = _values(400)
    assert sum(len(v) for v in values.values()) > 4096 * 5
    assert guard.matches(values) == {"k1", "k399"}
    assert len(det.streams) > 1
    assert max(det.streams) <= 4096 - 4096 // 8


def test_clean_past_max_bytes_replaces_the_last_value():
    det = _Gitleaks(True, max_bytes=4096)
    out = MetadataGuard([det], "salt").clean(_values(400))
    leaked = MARK in repr(out)
    assert not leaked
    assert out["k2"] == _pad(2)


class _FailsOn:
    """A T0 detector that raises on any batch holding `bad`."""

    name = "fails"
    tier = TIER_T0
    max_bytes = 4096

    def __init__(self, bad: str):
        self.bad = bad

    def scan(self, units):
        units = list(units)
        if any(self.bad in u.text for u in units):
            raise DetectorFailed("nope")
        return []


def test_a_failed_batch_marks_only_that_batch():
    values = _values(400)
    hits = MetadataGuard([_FailsOn(_pad(398))]).matches(values)
    assert "k398" in hits and "k0" not in hits


def test_a_2_mib_written_batch_launches_subprocess_gitleaks_once(tmp_path, monkeypatch):
    import subprocess

    from forgd_verdict.core import _candidates, _run_candidates, _utf8_len
    from forgd_verdict.store.base import VerdictRecord

    binary = tmp_path / "gitleaks"
    binary.write_text("#!/bin/sh\nexit 1\n")
    binary.chmod(0o755)
    launches = []

    def run(cmd, *, input=b"", **kw):
        launches.append(len(input))
        return subprocess.CompletedProcess(cmd, 0, stdout=b"[]", stderr=b"")

    monkeypatch.setattr("forgd_verdict.detectors.gitleaks.subprocess.run", run)
    records = [VerdictRecord(source="otel", request_id=f"req {i:06d} " + "w" * 100,
                             session_id=f"sess {i:06d} " + "v" * 100, model=f"model-{i % 7}")
               for i in range(5000)]
    text = sum(_utf8_len(c) for r in records for v in (r.request_id, r.session_id, r.model)
               for c in dict.fromkeys([v, *_candidates(v), *_run_candidates(v)]))
    assert 2 * 2**20 <= text < GitleaksDetector().max_bytes * 7 // 8
    guard = MetadataGuard([GitleaksDetector(binary=str(binary))], allow_subprocess=True)
    assert len(guard.records(records)) == 5000
    assert len(launches) == 1
