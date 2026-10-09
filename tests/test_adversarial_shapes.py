"""Adversarial payload shapes: time and memory stay linear in the payload.

Each shape is run through the three paths that scan sender JSON: the
hook's `evaluate`, `scan_frame` with the server profile, and the
collector's decode, scan and `redact_events`. Memory is the tracemalloc
peak of one run; time is measured without the tracer, which slows
allocation-heavy code several times over. Each payload is built once and
shared by the cases that use it.

At `SMALL` a case has absolute bounds: under `WALL_BOUND_S`, and a peak
under `MEMORY_FACTOR` times the payload's JSON size or
`MEMORY_FLOOR_BYTES`, whichever is larger.

At a path's body limit a case is run at a quarter of the limit and at the
limit, and fails when time or peak grows by more than `GROWTH_BOUND`
times the growth in payload size: 8 for a fourfold payload, against 4 for
linear cost and 16 for quadratic. Peak is one traced run per size. Time
is process CPU time with the garbage collector off, the fastest of the
runs at each size: quarter, limit, quarter. A case over the bound is
timed at both sizes `RETRY_ROUNDS` more times before it fails. `CEILING_S`
and `CEILING_BYTES` stop any run there, and a traced run at the limit
fails over `LIMIT_PEAK_BYTES`, which bounds what is linear in the payload
but costs far more than it. A shape in `FLAT_PEAK` has no
traced run on the hook and server paths: its peak is set by
MAX_SCAN_UNITS, not by the payload, and the `SMALL` case bounds it.

A watchdog thread interrupts a run past its limit, so a super-linear case
fails in seconds instead of taking the machine into swap. An untraced run
is stopped when the process's peak RSS rises `CEILING_BYTES` past where
it started.

Gitleaks is disabled: its cost is a subprocess and is the same for every
shape of the same size, and it is not on every machine that runs this.
"""

from __future__ import annotations

import _thread
import base64
import contextlib
import gc
import json
import resource
import sys
import threading
import time
import tracemalloc
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import pytest

from forgd_verdict.budget import Budget
from forgd_verdict.core import MAX_SCAN_UNITS, scan, scan_frame
from forgd_verdict.extract import MAX_UNIT_BYTES, MIN_KEY_CHARS, frame_units
from forgd_verdict.hook import cli as hook_cli
from forgd_verdict.otel.payload import decode
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge, load_policy
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.redact import RedactionPlan, index_findings, redact_events

# Bounds on time and memory: run alone, after the parallel suite.
pytestmark = pytest.mark.serial

WALL_BOUND_S = 3.0
MEMORY_FACTOR = 10
# Every unit costs an object and a locator however short its text, so a
# payload of short values costs more than 10x its size until extraction
# stops at MAX_SCAN_UNITS. 1 KiB a unit covers a locator at its cap.
MEMORY_FLOOR_BYTES = MAX_SCAN_UNITS * 1024
ABORT_FACTOR = 2
# The traced run's time limit, there only to stop it.
TRACED_ABORT_S = 10 * WALL_BOUND_S
TIME_RUNS = 2

GROWTH_BOUND = 2
TIME_ORDER = ("quarter", "limit", "quarter")
RETRY_ROUNDS = 3
CEILING_S = 60.0
CEILING_BYTES = 2 * 2**30
# Below these, a quarter-size run is too quick or too small for a ratio
# against it to mean anything.
TIME_FLOOR_S = 0.05
PEAK_FLOOR_BYTES = 4 * 2**20
LIMIT_PEAK_BYTES = 256 * 2**20

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_SALT = "s" * 32
_NO_GITLEAKS = {"detectors": {"gitleaks": {"enabled": False}}}

_POLICY_FILE = Path(__file__).resolve().parents[1] / "policy.yaml"
_POLICY = Policy(raw=_deep_merge(load_policy(_POLICY_FILE).raw, _NO_GITLEAKS))
_HOOK_POLICY = Policy(raw=_deep_merge(load_policy(_POLICY_FILE, for_hook=True).raw,
                                      _NO_GITLEAKS))

# The hook reads stdin with no limit of its own; a hook configured with
# `scan_endpoint` sends the same payload to the server, so the server's
# limit is the hook's too.
SERVER_LIMIT = int(_POLICY.server.get("max_body_bytes",
                                      DEFAULT_POLICY["server"]["max_body_bytes"]))
HOOK_LIMIT = SERVER_LIMIT
COLLECTOR_LIMIT = int(_POLICY.raw["otel"].get("max_body_bytes", 8 * 1024 * 1024))
SMALL = 256 * 1024


def aws_key(i: int) -> str:
    """A string the AWS access key rule matches. Not a real key."""
    return "AKIA" + "".join(_B32[(i >> (5 * j)) & 31] for j in range(16))


# --- shapes ---------------------------------------------------------------
#
# Each takes a target size in bytes and returns a dict of roughly that JSON
# size. The size check below keeps them honest.


def long_key(n: int) -> dict:
    return {"k" * (n - 8): "v"}


def many_keys(n: int) -> dict:
    count = n // (MIN_KEY_CHARS + 12)
    return {f"key{i:0{MIN_KEY_CHARS}d}": "v" for i in range(count)}


def dotted_segments(n: int) -> dict:
    return {".".join(["a"] * (n // 2)): "v"}


def deep_nesting(n: int, depth: int = 400) -> dict:
    # Under json's recursion limit, which the server's own parse shares.
    pad = "x" * max(1, n // depth - 40)
    node: dict = {"leaf": aws_key(0)}
    for i in range(depth):
        node = {f"level_{i:06d}": node, "pad": pad}
    return node


def long_key_many_children(n: int) -> dict:
    children = n // 32
    return {"k" * (n // 2): {str(i): "v" for i in range(children)}}


def wide_list(n: int) -> dict:
    return {"items": ["value"] * (n // 9)}


def base64_runs(n: int) -> dict:
    run = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODkrLw" * 2
    return {"blob": " ".join([run] * (n // (2 * len(run) + 2))),
            "many": [run] * (n // (2 * len(run) + 8))}


def wrapped_base64(n: int) -> dict:
    line = base64.b64encode(f"key={aws_key(3)} in a wrapped line of text".encode()).decode()
    # JSON writes each newline as two bytes.
    return {"blob": "\n".join([line] * (n // (2 * len(line) + 4))),
            "lines": [line] * (n // (2 * len(line) + 8))}


def dotted_key_over_akia(n: int) -> dict:
    return {".".join(["a"] * (n // 2)): {aws_key(1): aws_key(2)}}


def dotted_keys_29x29(n: int) -> dict:
    seg = 29
    key_bytes = seg * (seg + 1)
    count = n // (key_bytes + 26)
    return {".".join(f"{k:05d}{i:03d}" + "a" * (seg - 8) for i in range(seg)): aws_key(k)
            for k in range(count)}


def dotted_key_many_akia_children(n: int) -> dict:
    children = n // 64
    return {".".join(["a"] * (n // 8)): {aws_key(i): aws_key(i + 1)
                                        for i in range(children)}}


def long_keys_in_wide_list(n: int) -> dict:
    count = 64
    each = n // count
    return {"items": [{"k" * (each // 2): {str(i): "v" for i in range(each // 32)}}
                      for _ in range(count)]}


def many_nested_dotted_keys(n: int) -> dict:
    count = n // 512
    return {f"outer_{k:08d}": {".".join(["b"] * 200): {aws_key(k): "v" * 64}}
            for k in range(count)}


def nested_base64_runs(n: int) -> dict:
    # A value of MAX_UNIT_BYTES, scanned whole, for each 16 MiB, of the
    # shortest runs that decode to text, under a nested key path, after a
    # list that extraction stops reading at MAX_SCAN_UNITS.
    run = base64.b64encode(b"plain text 18 byte").decode()
    each = min(n, MAX_UNIT_BYTES) - 1024
    value = " ".join([run] * (each // (len(run) + 1)))
    count = max(1, n // (4 * MAX_UNIT_BYTES))
    node: dict = {f"v{j}": value for j in range(count)}
    for i in range(4):
        node = {f"{'k' * 110}{i}": node}
    filler = n - count * len(value) - 2048
    return {"filler": ["value"] * max(0, filler // 9), "runs": node}


SHAPES: dict[str, Callable[[int], dict]] = {
    "long_key": long_key,
    "many_keys": many_keys,
    "dotted_segments": dotted_segments,
    "deep_nesting": deep_nesting,
    "long_key_many_children": long_key_many_children,
    "wide_list": wide_list,
    "base64_runs": base64_runs,
    "wrapped_base64": wrapped_base64,
    "dotted_key_over_akia": dotted_key_over_akia,
    "dotted_keys_29x29": dotted_keys_29x29,
    "dotted_key_many_akia_children": dotted_key_many_akia_children,
    "long_keys_in_wide_list": long_keys_in_wide_list,
    "many_nested_dotted_keys": many_nested_dotted_keys,
    "nested_base64_runs": nested_base64_runs,
}


# --- entry points ---------------------------------------------------------


def run_hook(shape: dict) -> None:
    event = {
        "session_id": "abc123",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": shape,
        "tool_use_id": "toolu_01ABC",
        "permission_mode": "default",
    }
    hook_cli.evaluate(event, _HOOK_POLICY)


_SERVER_DETECTORS = _POLICY.build_detectors(profile="server", salt=_SALT)


def run_server(shape: dict) -> None:
    messages = [{"role": "assistant", "content": [
        {"type": "tool_use", "id": "toolu_01", "name": "Bash", "input": shape}]}]
    scan_frame(messages, frame_units, _SERVER_DETECTORS, Budget(_POLICY.budget_ms))


_COLLECTOR_DETECTORS = _POLICY.build_detectors(profile="collector", salt=_SALT)
_SINK = SinkConfig(name="s", endpoint="https://collector.test")
_PLAN = RedactionPlan.build(_SINK, [d.name for d in _COLLECTOR_DETECTORS])


def _any_value(value) -> dict:
    if isinstance(value, dict):
        return {"kvlistValue": {"values": [{"key": k, "value": _any_value(v)}
                                           for k, v in value.items()]}}
    if isinstance(value, list):
        return {"arrayValue": {"values": [_any_value(v) for v in value]}}
    return {"stringValue": str(value)}


def collector_body(shape: dict) -> bytes:
    attrs = [{"key": "event.name", "value": {"stringValue": "claude_code.tool_result"}}]
    attrs += [{"key": k, "value": _any_value(v)} for k, v in shape.items()]
    return json.dumps({"resourceLogs": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "claude-code"}}]},
        "scopeLogs": [{"logRecords": [{"attributes": attrs,
                                       "body": {"stringValue": ""}}]}],
    }]}).encode()


def run_collector(body: bytes) -> None:
    from forgd_verdict.otel.extract import records_units

    records = decode(body, "application/json", "logs")
    result = scan(records_units(records), _COLLECTOR_DETECTORS, Budget(_POLICY.budget_ms))
    redact_events(records, index_findings(result.findings), _PLAN, _SINK,
                  surface="s", org="o", observed_at="t",
                  detectors=_COLLECTOR_DETECTORS, skipped=result.detectors_skipped)


# --- measurement ----------------------------------------------------------


@dataclass
class Measured:
    seconds: float
    peak_bytes: int
    # "time", "memory" or "rss" when the watchdog stopped the run, else "".
    aborted: str
    # Process CPU time of the run.
    cpu_seconds: float = 0.0


def _peak_rss() -> int:
    """This process's peak RSS in bytes; Linux reports kilobytes."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024


def measure(fn: Callable[[], None], max_seconds: float,
            max_bytes: int | None, gc_off: bool = False) -> Measured:
    """Runs `fn`, under tracemalloc when `max_bytes` is given, and with the
    garbage collector disabled when `gc_off`. The watchdog interrupts it
    past `max_seconds` of process CPU time or a memory limit; the interrupt
    arrives as KeyboardInterrupt in this thread."""
    traced = max_bytes is not None
    done = threading.Event()
    tripped: list[str] = []
    rss_from = _peak_rss()

    def watch() -> None:
        while not done.wait(0.01):
            if time.process_time() - cpu_start > max_seconds:
                tripped.append("time")
            elif traced and tracemalloc.get_traced_memory()[1] > max_bytes:
                tripped.append("memory")
            elif not traced and _peak_rss() - rss_from > CEILING_BYTES:
                tripped.append("rss")
            else:
                continue
            _thread.interrupt_main()
            return

    if traced:
        tracemalloc.start()
    collecting = gc.isenabled()
    if gc_off:
        gc.disable()
    start = time.perf_counter()
    cpu_start = time.process_time()
    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    peak = 0
    try:
        try:
            fn()
        finally:
            done.set()
            cpu = time.process_time() - cpu_start
            elapsed = time.perf_counter() - start
            if collecting:
                gc.enable()
            if traced:
                peak = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
            watcher.join()
    except KeyboardInterrupt:
        if not tripped:
            raise
    else:
        if tripped:
            # The interrupt raced the end of `fn` and is still pending.
            with contextlib.suppress(KeyboardInterrupt):
                time.sleep(0.05)
    return Measured(elapsed, peak, tripped[0] if tripped else "", cpu)


def _payload_bytes(shape: dict) -> int:
    return len(json.dumps(shape).encode())


# Payloads of one shape, by (kind, size). The cases are ordered by shape,
# and the cache is emptied when the shape changes, so a 64 MiB payload is
# never held alongside another shape's.
_BUILT: dict[str, dict[tuple[str, int], object]] = {}


def _cached(name: str, kind: str, size: int, make: Callable[[], object]):
    if name not in _BUILT:
        _BUILT.clear()
        _BUILT[name] = {}
    built = _BUILT[name]
    if (kind, size) not in built:
        built[(kind, size)] = make()
    return built[(kind, size)]


def _make_shape(name: str, size: int) -> tuple[dict, int]:
    shape = SHAPES[name](size)
    payload = _payload_bytes(shape)
    assert payload <= size * 1.1, f"{name} built {payload} bytes for {size}"
    return shape, payload


# OTLP JSON wraps each level of a shape in about four levels of its own,
# so the collector gets shallower nesting: py3.11's json stops near 1000
# levels, where the decode refuses the body instead of scanning it.
COLLECTOR_SHAPES: dict[str, Callable[[int], dict]] = {
    "deep_nesting": lambda n: deep_nesting(n, depth=200),
}


def _make_body(name: str, size: int) -> bytes:
    make = COLLECTOR_SHAPES.get(name, SHAPES[name])
    body = collector_body(make(size) if name in COLLECTOR_SHAPES else _shape(name, size)[0])
    if len(body) > size:
        # The OTLP encoding is larger than the shape; fit it to the limit.
        body = collector_body(make(int(size * size / len(body) * 0.95)))
    assert len(body) <= size, f"{name} encoded to {len(body)} bytes for {size}"
    return body


def _shape(name: str, size: int) -> tuple[dict, int]:
    return _cached(name, "shape", size, lambda: _make_shape(name, size))


def _body(name: str, size: int) -> bytes:
    return _cached(name, "body", size, lambda: _make_body(name, size))


def build(path: str, name: str, size: int) -> tuple[Callable[[], None], int]:
    """The run for one case and its payload's size in bytes."""
    if path == "collector":
        body = _body(name, size)
        return (lambda: run_collector(body)), len(body)
    shape, payload = _shape(name, size)
    run = run_hook if path == "hook" else run_server
    return (lambda: run(shape)), payload


def fastest(fn: Callable[[], None], max_seconds: float) -> Measured:
    runs = [measure(fn, max_seconds, None) for _ in range(TIME_RUNS)]
    return min(runs, key=lambda m: (bool(m.aborted), m.seconds))


def _stopped(m: Measured) -> str:
    return f", stopped on {m.aborted}" if m.aborted else ""


# Cases that fail on known findings, by case id. Each fix removes the ones
# it turns green.
XFAIL: dict[str, str] = {}


def _case(path: str, name: str, size: int):
    case_id = f"{path}-{name}-{size // 1024}k"
    marks = ([pytest.mark.xfail(strict=True, reason=XFAIL[case_id])]
             if case_id in XFAIL else [])
    return pytest.param(path, name, size, id=case_id, marks=marks)


_LIMITS = (("hook", HOOK_LIMIT), ("server", SERVER_LIMIT), ("collector", COLLECTOR_LIMIT))

# Shapes whose peak on the hook and server paths is the same at a quarter
# of the limit and at the limit, because extraction stops at MAX_SCAN_UNITS.
FLAT_PEAK = frozenset({
    "many_keys", "long_key_many_children", "wide_list", "base64_runs", "wrapped_base64",
    "dotted_keys_29x29", "dotted_key_many_akia_children", "long_keys_in_wide_list",
    "many_nested_dotted_keys",
})


@pytest.mark.parametrize(("path", "name", "size"),
                         [_case(path, name, SMALL) for name in SHAPES for path, _ in _LIMITS])
def test_shape_is_within_bounds(path, name, size, tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_VERDICT_SPOOL", str(tmp_path / "spool"))
    fn, payload = build(path, name, size)
    mem_bound = max(MEMORY_FACTOR * payload, MEMORY_FLOOR_BYTES)
    where = f"{path} {name} {payload / 1024:.0f} KiB"

    mem = measure(fn, TRACED_ABORT_S, ABORT_FACTOR * mem_bound)
    detail = (f"{where}: {mem.peak_bytes / 2**20:.1f} MiB peak "
              f"(bound {mem_bound / 2**20:.1f} MiB){_stopped(mem)}")
    print(detail)
    assert not mem.aborted and mem.peak_bytes < mem_bound, detail

    wall = fastest(fn, ABORT_FACTOR * WALL_BOUND_S)
    detail = f"{where}: {wall.seconds:.2f}s (bound {WALL_BOUND_S}s){_stopped(wall)}"
    print(detail)
    assert not wall.aborted and wall.seconds < WALL_BOUND_S, detail


def _cpu_times(runs: dict[str, tuple[Callable[[], None], str]], order: Iterable[str],
               best: dict[str, float]) -> None:
    """Times the runs in `order` and keeps the lowest CPU time of each in
    `best`."""
    for label in order:
        fn, where = runs[label]
        m = measure(fn, CEILING_S, None, gc_off=True)
        assert not m.aborted, f"{where}: {m.seconds:.2f}s{_stopped(m)}"
        best[label] = min(best.get(label, m.cpu_seconds), m.cpu_seconds)


@pytest.mark.parametrize(("path", "name", "size"),
                         [_case(path, name, limit) for name in SHAPES for path, limit in _LIMITS])
def test_shape_grows_linearly(path, name, size, tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_VERDICT_SPOOL", str(tmp_path / "spool"))
    payloads, peaks, runs = {}, {}, {}
    for label, at in (("quarter", size // 4), ("limit", size)):
        fn, payload = build(path, name, at)
        where = f"{path} {name} {payload / 1024:.0f} KiB"
        peak = 0
        if path == "collector" or name not in FLAT_PEAK:
            cap = LIMIT_PEAK_BYTES if label == "limit" else CEILING_BYTES
            mem = measure(fn, CEILING_S, cap)
            assert not mem.aborted, (f"{where}: {mem.peak_bytes / 2**20:.1f} MiB "
                                     f"(bound {cap / 2**20:.0f} MiB){_stopped(mem)}")
            peak = mem.peak_bytes
        payloads[label], peaks[label], runs[label] = payload, peak, (fn, where)
    q_payload, l_payload = payloads["quarter"], payloads["limit"]
    q_peak, l_peak = peaks["quarter"], peaks["limit"]
    allowed = GROWTH_BOUND * l_payload / q_payload
    best: dict[str, float] = {}
    _cpu_times(runs, TIME_ORDER, best)
    if best["limit"] / max(best["quarter"], TIME_FLOOR_S) > allowed:
        _cpu_times(runs, ("limit", "quarter") * RETRY_ROUNDS, best)
    del runs
    q_s, l_s = best["quarter"], best["limit"]
    time_growth = l_s / max(q_s, TIME_FLOOR_S)
    peak_growth = l_peak / max(q_peak, PEAK_FLOOR_BYTES)
    peaks_text = (f"{q_peak / 2**20:.1f} -> {l_peak / 2**20:.1f} MiB (x{peak_growth:.1f})"
                  if l_peak else "peak not traced")
    detail = (f"{path} {name}: {q_payload / 1024:.0f} -> {l_payload / 1024:.0f} KiB, "
              f"{q_s:.2f} -> {l_s:.2f}s CPU (x{time_growth:.1f}), {peaks_text}, "
              f"allowed x{allowed:.1f}")
    print(detail)
    assert time_growth <= allowed and peak_growth <= allowed, detail
