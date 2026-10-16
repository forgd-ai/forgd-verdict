"""The serial pass is split across runners by `--shard` (tests/shard.py).
A test that falls between shards is never run and nothing fails, so these
check that the shards cover every test once and that ci.yml runs them all."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from shard import DURATIONS, load_durations, parse_shard, plan, shard_of

ROOT = Path(__file__).resolve().parents[1]


def _groups(nodeids, durations, count):
    groups = plan(durations, count)
    return [shard_of(n, groups, count) for n in nodeids]


def test_shard_takes_i_of_n():
    assert parse_shard("2/4") == (2, 4)
    for bad in ("0/4", "5/4", "4", "a/b", "1/0"):
        with pytest.raises(ValueError):
            parse_shard(bad)


def test_every_test_is_in_exactly_one_shard():
    durations = {f"t::{i}": float(i % 7) for i in range(50)}
    nodeids = [*durations, "t::unrecorded-a", "t::unrecorded-b"]
    for count in (1, 3, 4):
        assigned = _groups(nodeids, durations, count)
        assert all(1 <= g <= count for g in assigned)
        assert len(assigned) == len(nodeids)


def test_a_tests_shard_depends_only_on_its_node_id_and_the_file():
    """Not on what else was collected, so a runner that collects one extra
    or one fewer test still agrees with the others about the rest."""
    durations = {f"t::{i}": float(i) for i in range(20)}
    groups = plan(durations, 4)
    assert ([shard_of(n, groups, 4) for n in ("t::3", "t::new")]
            == [shard_of(n, plan(dict(durations), 4), 4) for n in ("t::3", "t::new")])


def test_the_shards_are_balanced_by_recorded_time():
    durations = {f"t::{i}": float(i) for i in range(1, 41)}
    groups = plan(durations, 4)
    loads = [sum(s for n, s in durations.items() if groups[n] == g) for g in (1, 2, 3, 4)]
    assert max(loads) - min(loads) <= max(durations.values()), loads


def test_the_shards_of_a_real_selection_cover_it_once():
    """Through the conftest hook, as CI runs it."""
    def collect(*extra):
        out = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
             "tests/test_ci_schedule.py", *extra],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        return [line for line in out.splitlines() if "::" in line]

    everything = collect()
    shards = [collect("--shard", f"{i}/3") for i in (1, 2, 3)]
    assert sorted(n for s in shards for n in s) == sorted(everything)
    assert len(everything) > 3


def _parts() -> list[str]:
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    return ci["jobs"]["suite"]["strategy"]["matrix"]["part"]


def test_ci_runs_the_parallel_pass_and_every_serial_shard():
    parts = _parts()
    assert parts[0] == "parallel"
    shards = [parse_shard(re.fullmatch(r"serial (\d+/\d+)", p).group(1)) for p in parts[1:]]
    [count] = {n for _, n in shards}
    assert sorted(i for i, _ in shards) == list(range(1, count + 1))


def test_ci_gates_the_required_check_names_on_every_part():
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    gate = ci["jobs"]["test"]
    assert gate["name"] == "test (py${{ matrix.python }})"
    assert gate["needs"] == "suite"
    assert gate["if"].startswith("always()")
    assert gate["strategy"]["matrix"]["python"] == ci["jobs"]["suite"]["strategy"]["matrix"]["python"]


def test_the_recorded_durations_name_tests_that_exist():
    durations = load_durations()
    assert durations, DURATIONS
    files = {n.split("::", 1)[0] for n in durations}
    assert not [f for f in files if not (ROOT / f).is_file()]
