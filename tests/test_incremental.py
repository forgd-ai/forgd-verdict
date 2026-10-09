"""Incremental session scanning.

The property that matters: per-frame scan work is flat as a cumulative
transcript grows, and no correctness is traded for it.
"""

from __future__ import annotations

import json

from conftest import FAKE_AWS_KEY, WHSEC, ASGIClient, frame, make_policy, sign, text_msg

from forgd_verdict.budget import Budget
from forgd_verdict.cache import (
    InMemoryLRUCache,
    SessionState,
    head_digest,
    message_shape,
    resume_point,
)
from forgd_verdict.core import scan_frame
from forgd_verdict.extract import frame_units
from forgd_verdict.server.app import VerdictServer

TURNS = 50
FILLER = "lorem ipsum dolor sit amet consectetur adipiscing elit " * 200  # ~11 KB/turn


def _detectors():
    return make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}}
    ).build_detectors()


def _cumulative(n: int, secret_at: int | None = None) -> list[dict]:
    messages = []
    for i in range(n):
        text = f"turn {i} {FILLER}"
        if secret_at is not None and i == secret_at:
            text += f" key={FAKE_AWS_KEY}"
        messages.append(text_msg(text, role="user" if i % 2 == 0 else "assistant"))
    return messages


class _Counting:
    """Wraps a detector and records the units each scan is given."""

    def __init__(self, inner):
        self.inner = inner
        self.name = inner.name
        self.calls: list[int] = []

    def __getattr__(self, attr):
        return getattr(self.inner, attr)

    def scan(self, units):
        units = list(units)
        self.calls.append(len(units))
        return self.inner.scan(units)


def _units_seen(messages, cache=None, key=None) -> int:
    """Units the detectors are handed for one frame, summed over detectors."""
    counters = [_Counting(d) for d in _detectors()]
    scan_frame(messages, frame_units, counters, Budget(5000), cache, key)
    return sum(sum(c.calls) for c in counters)


def test_per_frame_scan_work_is_flat_after_the_first_frame():
    cache = InMemoryLRUCache()
    detectors = _detectors()
    counters = [_Counting(d) for d in detectors]
    key = ("tenant", "session-flat")
    units_per_frame = []
    for n in range(1, TURNS + 1):
        messages = _cumulative(n)
        before = [len(c.calls) for c in counters]
        scan_frame(messages, frame_units, counters, Budget(5000), cache, key)
        units_per_frame.append(sum(sum(c.calls[b:]) for c, b in zip(counters, before, strict=True)))

    # 1. The final frame hands the detectors what an uncached two-message
    #    transcript would: the last scanned message, for the seam, and the
    #    new one.
    assert units_per_frame[-1] == _units_seen(_cumulative(2)), units_per_frame
    # 2. Flat, exactly: every frame after the first costs the same, however
    #    long the transcript is.
    assert len(set(units_per_frame[1:])) == 1, units_per_frame
    # 3. Far below a full rescan of the same transcript.
    full_rescan = _units_seen(_cumulative(TURNS))
    assert units_per_frame[-1] * 10 < full_rescan, (units_per_frame[-1], full_rescan)


def test_naive_rescan_would_be_quadratic():
    """Control: with no cache, each frame hands the detectors every message
    and every seam between two of them, 2n - 1 units per detector, so a
    session of n frames costs n**2 per detector."""
    n_detectors = len(_detectors())
    for n in (5, 50):
        assert _units_seen(_cumulative(n)) == n_detectors * (2 * n - 1)
    total = sum(_units_seen(_cumulative(n)) for n in range(1, TURNS + 1))
    assert total == n_detectors * TURNS**2


def test_findings_from_earlier_turns_persist_across_frames():
    """A secret in turn 1 must still deny at turn 30."""
    cache = InMemoryLRUCache()
    detectors = _detectors()
    key = ("tenant", "session-sticky")
    result = None
    for n in range(1, 31):
        result = scan_frame(
            _cumulative(n, secret_at=0), frame_units, detectors, Budget(5000), cache, key
        )
    assert result is not None
    assert any(f.detector == "regex:aws-access-key" for f in result.findings)
    assert result.cache_hit and result.messages_scanned == 1


def test_shrunk_transcript_forces_full_rescan():
    cache = InMemoryLRUCache()
    detectors = _detectors()
    key = ("tenant", "session-shrink")
    scan_frame(_cumulative(20), frame_units, detectors, Budget(5000), cache, key)
    result = scan_frame(
        _cumulative(5, secret_at=0), frame_units, detectors, Budget(5000), cache, key
    )
    assert not result.cache_hit
    assert result.messages_scanned == 5
    assert any(f.detector == "regex:aws-access-key" for f in result.findings)


def test_null_session_id_is_never_cached_and_always_correct():
    cache = InMemoryLRUCache()
    detectors = _detectors()
    key = ("tenant", None)
    for _ in range(3):
        result = scan_frame(
            _cumulative(4, secret_at=3), frame_units, detectors, Budget(5000), cache, key
        )
        assert not result.cache_hit
        assert result.messages_scanned == 4
        assert any(f.detector == "regex:aws-access-key" for f in result.findings)
    assert cache.stats()["sessions"] == 0


def test_shifted_prefix_forces_full_rescan():
    """A turn whose every block is excluded is omitted entirely, so message
    indices are not guaranteed stable. A count-only high-water mark would
    silently skip the shifted message."""
    cache = InMemoryLRUCache()
    detectors = _detectors()
    key = ("tenant", "session-shift")
    base = _cumulative(10)
    scan_frame(base, frame_units, detectors, Budget(5000), cache, key)

    # Same length, but an earlier turn was dropped and a new one carrying a
    # secret took its place at the end.
    shifted = base[:3] + base[4:] + [text_msg(f"late {FAKE_AWS_KEY}")]
    result = scan_frame(shifted, frame_units, detectors, Budget(5000), cache, key)
    assert not result.cache_hit, "shape change must invalidate the prefix"
    assert any(f.detector == "regex:aws-access-key" for f in result.findings)


def test_head_change_invalidates():
    messages = _cumulative(5)
    state = SessionState(
        scanned_messages=5,
        shapes=[message_shape(m) for m in messages],
        head=head_digest(messages),
    )
    assert resume_point(state, messages) == 5
    changed = [text_msg("different opening"), *messages[1:]]
    assert resume_point(state, changed) == 0


def test_different_tenants_do_not_share_a_session_id():
    cache = InMemoryLRUCache()
    detectors = _detectors()
    messages = _cumulative(4, secret_at=0)
    scan_frame(messages, frame_units, detectors, Budget(5000), cache, ("t1", "same-id"))
    result = scan_frame(
        messages, frame_units, detectors, Budget(5000), cache, ("t2", "same-id")
    )
    assert not result.cache_hit


async def test_server_reports_cache_hits_across_frames(tmp_path):
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": str(tmp_path / "t.csv")},
    )
    server = VerdictServer(policy)
    client = ASGIClient(server)
    try:
        for n in range(1, 6):
            raw = json.dumps(frame(_cumulative(n), session_id="sess-1")).encode()
            status, _ = await client.post("/hook", raw, sign(raw, webhook_id=f"req_{n}"))
            assert status == 200
    finally:
        server.close()
    rows = (tmp_path / "t.csv").read_text().splitlines()
    assert rows[0].startswith("ts,request_id")
    # First frame is a miss; the rest hit and scan one new message each.
    assert rows[1].split(",")[8] == "0"
    for row in rows[2:]:
        cells = row.split(",")
        assert cells[8] == "1", "expected a cache hit"
        assert cells[7] == "1", "expected exactly one new message scanned"


def test_complete_scan_over_budget_is_still_cached():
    """A large frame can run past budget_ms with every detector having run.
    Refusing to cache that would force a full rescan on every later frame --
    the exact quadratic behaviour the cache exists to prevent. Only an
    *incomplete* scan (detectors skipped) must not be cached."""
    cache = InMemoryLRUCache()
    detectors = _detectors()  # T0 only: nothing is budget-gated
    key = ("tenant", "session-slow")
    result = scan_frame(_cumulative(20), frame_units, detectors, Budget(0), cache, key)
    assert result.budget_exceeded, "expected the zero budget to be flagged"
    assert not result.detectors_skipped, "T0 is never skipped"
    assert cache.stats()["sessions"] == 1, "a complete scan must be cached"


def test_incomplete_scan_is_not_cached():
    """A frame that skipped a T2 detector must not advance the high-water
    mark, or the unscanned gap is permanent for the session."""

    class SkippableT2:
        name, tier, severity = "fake_t2", 2, "block"

        def available(self):
            return True

        def scan(self, units):
            return []

    cache = InMemoryLRUCache()
    key = ("tenant", "session-skipped")
    result = scan_frame(
        _cumulative(5), frame_units, [*_detectors(), SkippableT2()],
        Budget(0), cache, key,
    )
    assert result.detectors_skipped == ["fake_t2"]
    assert cache.stats()["sessions"] == 0


# -- a same-length in-place edit -----------------------------------------


def _m(text):
    return {"role": "user", "content": [{"type": "text", "text": text}]}


def test_an_in_place_same_length_edit_forces_a_rescan():
    """`message_shape` recorded lengths only, and a length does not change
    under an in-place edit. Two frames of one session with an
    already-scanned message rewritten at identical length, transcript
    growing, resumed past it and never rescanned it:

        frame1  "note XXXXXXXXXXXXXXXXXXXX end"   allow
        frame2  "note AKIAIOSFODNN7EXAMPLE end"   cache_hit, scanned 1, allow

    The shrinking case (claude.ai edit-and-resubmit) was already covered
    by `len(messages) < n`. This is the growing one.
    """
    before = [_m("turn zero"), _m("note XXXXXXXXXXXXXXXXXXXX end"), _m("turn two")]
    after = [_m("turn zero"), _m("note AKIAIOSFODNN7EXAMPLE end"),
             _m("turn two"), _m("a new turn")]
    assert len(before[1]["content"][0]["text"]) == len(after[1]["content"][0]["text"])

    state = SessionState(scanned_messages=3,
                         shapes=[message_shape(m) for m in before],
                         head=head_digest(before))
    assert resume_point(state, after) == 0


def test_a_dict_input_held_at_a_constant_size_forces_a_rescan():
    """`json.dumps(sort_keys=True)` sizing is a total, so the value AND
    the key set can both change while the size does not."""
    a = {"role": "assistant", "content": [
        {"type": "tool_use", "input": {"aa": "hello there", "b": "XXXXXXXXXXXXXXXXXXXX"}}]}
    b = {"role": "assistant", "content": [
        {"type": "tool_use", "input": {"a": "hello there", "bb": "AKIAIOSFODNN7EXAMPLE"}}]}
    assert message_shape(a) != message_shape(b)


def test_an_untouched_prefix_still_resumes():
    """The cache has to keep working. Digesting the prefix costs about a
    millisecond per megabyte against the hundreds of milliseconds of
    detector work it skips."""
    before = [_m("turn zero"), _m("turn one"), _m("turn two")]
    state = SessionState(scanned_messages=3,
                         shapes=[message_shape(m) for m in before],
                         head=head_digest(before))
    assert resume_point(state, [*before, _m("turn three")]) == 3


def test_a_shared_session_id_across_orgs_no_longer_resumes_wrongly():
    """Closed by the content digest rather than by the namespace.

    With `tenant_id` absent the cache key collapses to `session_id`
    alone. It ranks low because one deployment serves one customer, so
    cross-org segregation is a preference rather than a boundary -- its
    value was as an amplifier for a same-length in-place edit.

    With shapes carrying a digest, a second org's session with the same
    id has different content and gets a full rescan. A collision now
    requires an identical transcript prefix, at which point resuming is
    correct.
    """
    org_a = [_m("org A private planning"), _m("more from A")]
    org_b = [_m("org B has AKIAIOSFODNN7EXAMPLE"), _m("more from B")]
    state = SessionState(scanned_messages=2,
                         shapes=[message_shape(m) for m in org_a],
                         head=head_digest(org_a))
    assert resume_point(state, [*org_b, _m("a third")]) == 0


def test_an_edit_to_any_scanned_field_forces_a_rescan():
    """The digest covered `text`, `content` and `input` only, while
    extraction also scans fields such as `caption`."""
    before = [{"role": "user", "content": [{"type": "text", "text": "hi", "caption": "a photo"}]},
              _m("turn one")]
    after = [{"role": "user", "content": [{"type": "text", "text": "hi",
                                           "caption": f"key {FAKE_AWS_KEY}"}]},
             _m("turn one"), _m("a new turn")]
    assert message_shape(before[0]) != message_shape(after[0])
    cache = InMemoryLRUCache()
    key = ("org", "s1")
    scan_frame(before, frame_units, _detectors(), Budget(1000), cache, key)
    result = scan_frame(after, frame_units, _detectors(), Budget(1000), cache, key)
    assert result.findings, "the edited caption was not rescanned"


def test_a_secret_split_across_the_cache_boundary_is_found():
    """The resumed scan extracted only the new messages, so the seam
    between the last cached unit and the first new one was never joined."""
    head, tail = FAKE_AWS_KEY[:10], FAKE_AWS_KEY[10:]
    first = [_m("turn zero"), _m(f"the key is {head}")]
    second = [*first, _m(f"{tail} and more")]
    cache = InMemoryLRUCache()
    key = ("org", "s2")
    assert not scan_frame(first, frame_units, _detectors(), Budget(1000), cache, key).findings
    result = scan_frame(second, frame_units, _detectors(), Budget(1000), cache, key)
    assert result.cache_hit
    assert result.findings, "the split key was not joined across the boundary"
    full = scan_frame(second, frame_units, _detectors(), Budget(1000))
    assert full.findings


def test_an_edit_to_a_bare_string_block_forces_a_rescan():
    """Every non-dict block had the same fingerprint, and extraction scans
    a bare string block."""
    before = {"role": "user", "content": ["a plain note"]}
    after = {"role": "user", "content": [f"key {FAKE_AWS_KEY}"]}
    assert message_shape(before) != message_shape(after)
    cache = InMemoryLRUCache()
    key = ("org", "s3")
    scan_frame([before, _m("turn one")], frame_units, _detectors(), Budget(1000), cache, key)
    result = scan_frame([after, _m("turn one"), _m("new")], frame_units, _detectors(),
                        Budget(1000), cache, key)
    assert result.findings


def test_the_boundary_seam_walks_past_a_trailing_empty_message():
    """Backing up one message is not enough when that message yields no
    unit: the last unit then belongs to an earlier message."""
    head, tail = FAKE_AWS_KEY[:10], FAKE_AWS_KEY[10:]
    empty = {"role": "assistant", "content": []}
    first = [_m("turn zero"), _m(f"the key is {head}"), empty]
    second = [*first, _m(f"{tail} and more")]
    cache = InMemoryLRUCache()
    key = ("org", "s4")
    assert not scan_frame(first, frame_units, _detectors(), Budget(1000), cache, key).findings
    result = scan_frame(second, frame_units, _detectors(), Budget(1000), cache, key)
    assert result.cache_hit
    assert result.findings
