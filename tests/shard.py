"""Splitting a test run across runners by recorded duration.

`--shard I/N` keeps the I-th of N groups. The tests named in
`tests/durations.json` are grouped longest first, each into the group with
the least recorded time so far, which depends on that file alone. A test
the file does not name goes to the group a CRC-32 of its node id picks.
Either way a test's group depends only on its node id and the file, so
runners that collect the same node ids run each test exactly once between
them.

`--record-durations PATH` writes each test's setup, call and teardown time,
which is how `tests/durations.json` is made.
"""

from __future__ import annotations

import json
import zlib
from pathlib import Path

DURATIONS = Path(__file__).with_name("durations.json")


def parse_shard(value: str) -> tuple[int, int]:
    """`"I/N"` as `(I, N)`, with 1 <= I <= N."""
    index, _, count = value.partition("/")
    try:
        i, n = int(index), int(count)
    except ValueError:
        raise ValueError(f"--shard takes I/N, not {value!r}") from None
    if not 1 <= i <= n:
        raise ValueError(f"--shard {value}: I must be between 1 and N")
    return i, n


def load_durations(path: Path = DURATIONS) -> dict[str, float]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def plan(durations: dict[str, float], count: int) -> dict[str, int]:
    """The 1-based group of each test in `durations`, of `count`."""
    loads = [0.0] * count
    groups: dict[str, int] = {}
    for nodeid, seconds in sorted(durations.items(), key=lambda kv: (-kv[1], kv[0])):
        group = loads.index(min(loads))
        loads[group] += seconds
        groups[nodeid] = group + 1
    return groups


def shard_of(nodeid: str, groups: dict[str, int], count: int) -> int:
    """The 1-based group `nodeid` runs in: from `plan`, or for a test it
    does not name, from a CRC-32 of the node id."""
    return groups.get(nodeid) or zlib.crc32(nodeid.encode("utf-8")) % count + 1
