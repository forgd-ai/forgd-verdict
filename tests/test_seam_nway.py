"""A secret split across three or more adjacent units is found on a seam,
and every unit a match lies in is masked, and no other.

Runs of short units are cut into windows that join as many of them as
fit, so a split into many short pieces is inside one window.
"""

from __future__ import annotations

import json

import pytest
from conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, make_policy

from forgd_verdict import core
from forgd_verdict.budget import Budget
from forgd_verdict.core import SEAM_CHARS, decide, scan, scan_frame
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.extract import frame_units, hook_units
from forgd_verdict.models import Finding, ScanUnit
from forgd_verdict.otel.extract import records_units
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink import redact
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.factory import emitted_ids

STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
SECRETS = (FAKE_GITHUB_TOKEN, FAKE_AWS_KEY, STRIPE)


def _pieces(secret: str, n: int) -> list[str]:
    step = -(-len(secret) // n)
    return [secret[i:i + step] for i in range(0, len(secret), step)]


def _blocks(parts: list[str]) -> list[dict]:
    return [{"role": "user", "content": [{"type": "text", "text": p} for p in parts]}]


def _t0_verdict(parts: list[str]):
    policy = make_policy(server={"mode": "enforce"}).for_profile("server")
    result = scan_frame(_blocks(parts), frame_units, [T0RegexDetector()], Budget(20_000))
    return result, decide(result.findings, policy, dropped=result.detectors_skipped)


@pytest.mark.parametrize("secret", SECRETS)
@pytest.mark.parametrize("n", [2, 3, 4, 6])
def test_a_secret_split_across_n_text_blocks_denies(secret, n):
    parts = _pieces(secret, n)
    parts[0] = "see " + parts[0]
    parts[-1] += " ok"
    result, verdict = _t0_verdict(parts)
    assert verdict.action == "deny", (n, [f.detector for f in result.findings])


@pytest.mark.parametrize("n", [3, 5, 10, 20])
def test_a_secret_split_into_one_character_blocks_denies(n):
    secret = FAKE_GITHUB_TOKEN
    head, rest = secret[:len(secret) - n + 1], secret[len(secret) - n + 1:]
    _, verdict = _t0_verdict(["see " + head, *rest])
    assert verdict.action == "deny"


def test_a_secret_split_across_three_tool_input_fields_denies():
    a, b, c = _pieces(FAKE_AWS_KEY, 3)
    policy = make_policy().for_profile("hook")
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "mcp__x__y",
                        "tool_input": {"p": f"x {a}", "q": b, "r": f"{c} y"}})
    result = scan(units, [T0RegexDetector()])
    assert decide(result.findings, policy).action == "deny"


def test_a_secret_split_across_three_keys_keeps_every_piece_off_locators():
    a, b, c = _pieces(FAKE_AWS_KEY, 3)
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "mcp__x__y",
                        "tool_input": {"x": {f"zz {a}": b, f"{c} zz": "tail"}}})
    result = scan(units, [T0RegexDetector()])
    assert result.findings
    exposed = [*(f.locator for f in result.findings),
               *(o for f in result.findings for o in f.seam_others),
               json.dumps([f.to_log() for f in result.findings])]
    for piece in (a, b, c):
        for text in exposed:
            assert piece not in text, text


def test_a_split_across_a_cached_boundary_is_found_on_the_next_frame():
    """Two pieces were in frames already scanned, one message each."""
    from forgd_verdict.cache import InMemoryLRUCache

    a, b, c = _pieces(FAKE_GITHUB_TOKEN, 3)
    cache = InMemoryLRUCache()
    key = ("tenant", "session")
    dets = [T0RegexDetector()]
    msgs = [{"role": "user", "content": "hello there " + "w " * 300},
            {"role": "user", "content": f"see {a}"}]
    assert not scan_frame(msgs, frame_units, dets, Budget(20_000), cache, key).findings
    msgs.append({"role": "assistant", "content": b})
    assert not scan_frame(msgs, frame_units, dets, Budget(20_000), cache, key).findings
    msgs.append({"role": "user", "content": f"{c} ok"})
    result = scan_frame(msgs, frame_units, dets, Budget(20_000), cache, key)
    assert result.cache_hit
    assert any(f.detector == "regex:github-token" for f in result.findings)


# --- attribution: which units a seam finding counts on ---------------------


def _units(*texts: str) -> list[ScanUnit]:
    return [ScanUnit(locator=f"u{i}", tool_name=None, text=t) for i, t in enumerate(texts)]


def _on(findings, detector="regex:github-token"):
    return {(f.locator, *sorted(f.seam_others)) for f in findings if f.detector == detector}


def test_a_three_way_finding_counts_on_the_three_units_it_spans_only():
    a, b, c = _pieces(FAKE_GITHUB_TOKEN, 3)
    result = scan(_units("clean words before", f"see {a}", b, f"{c} ok", "clean words after"),
                  [T0RegexDetector()])
    assert _on(result.findings) == {("u1", "u2", "u3")}


def test_a_secret_wholly_in_one_short_unit_is_one_finding_on_that_unit():
    result = scan(_units("clean words before", f"see {FAKE_GITHUB_TOKEN} ok", "after"),
                  [T0RegexDetector()])
    assert _on(result.findings) == {("u1",)}


class _SpanlessOnSeams:
    """Reports one span-less finding on every unit holding `marker`."""

    name = "spanless"
    tier = 0

    def __init__(self, marker: str):
        self.marker = marker

    def scan(self, units):
        return [Finding(detector="spanless:x", severity="block", locator=u.locator,
                        excerpt_hash="0" * 64) for u in units if self.marker in u.text]


def test_a_span_less_seam_finding_counts_on_every_unit_of_its_window():
    result = scan(_units("ab", "MA", "RK", "cd", "ef"), [_SpanlessOnSeams("MARK")])
    hit = {loc for f in result.findings for loc in (f.locator, *f.seam_others)}
    assert hit == {"u0", "u1", "u2", "u3", "u4"}


def test_a_seam_never_joins_a_head_to_its_tail():
    head = ScanUnit(locator="v", tool_name=None, text="x " + FAKE_GITHUB_TOKEN[:20],
                    truncated=True)
    tail = ScanUnit(locator="v#tail", tool_name=None, text=FAKE_GITHUB_TOKEN[20:] + " y",
                    truncated=True, tail=True)
    assert core._seams([head, tail]) == []


# --- cost ------------------------------------------------------------------


def _seam_text(units) -> int:
    return sum(len(seam.text) for seam, _ in core._seams(units))


@pytest.mark.parametrize("width", [1, 3, 10, 100, 300, 600, 5000])
def test_seam_text_is_linear_in_the_text_it_joins(width):
    """At most four characters of seam per character joined, and each
    window at most 4 * SEAM_CHARS."""
    units = _units(*["ab" * (width // 2) + "c" * (width % 2)] * 400)
    joined = sum(min(len(u.text), 2 * SEAM_CHARS) for u in units)
    assert _seam_text(units) <= 4 * joined
    assert all(len(seam.text) <= 4 * SEAM_CHARS for seam, _ in core._seams(units))


def test_seam_parts_are_linear_in_the_units_joined():
    """With one-character units every window lists one part per character."""
    units = _units(*["x"] * 5000)
    parts = sum(len(p) for _, p in core._seams(units))
    assert parts <= 4 * len(units)


def test_two_long_units_get_the_one_window_they_always_had():
    left, right = "L" * 2000, "R" * 2000
    ((seam, parts),) = core._seams(_units(left, right))
    assert seam.text == "L" * SEAM_CHARS + "R" * SEAM_CHARS
    assert [p[0] for p in parts] == ["u0", "u1"]


# --- what adapter 5 forwards -----------------------------------------------


def _content(**values) -> OtelRecord:
    return OtelRecord(kind="log", name="claude_code.api_request", attributes=values,
                      resource={"service.name": "claude-code"})


def _forwarded(record: OtelRecord):
    detectors = [T0RegexDetector()]
    result = scan(records_units([record]), detectors, Budget(60_000))
    config = SinkConfig(name="s", endpoint="https://collector.test")
    plan = redact.RedactionPlan.build(config, emitted_ids(detectors))
    (event,) = redact.redact_events([record], redact.index_findings(result.findings), plan,
                                    config, surface="claude-code", org="o",
                                    observed_at="2026-10-06T00:00:00Z", detectors=detectors)
    return event.attributes


def test_a_three_way_split_masks_each_piece_and_leaves_clean_neighbours():
    a, b, c = _pieces(FAKE_GITHUB_TOKEN, 3)
    clean = "plain words only here"
    out = _forwarded(_content(user_system_prompt=clean, prompt=f"see {a}", response=b,
                              tool_parameters=f"{c} ok", error=clean))
    dumped = json.dumps(out)
    for piece in (a, b, c):
        assert piece not in dumped, out
    assert out["user_system_prompt"] == clean
    assert out["error"] == clean


def test_a_four_way_split_beside_a_whole_copy_masks_every_piece():
    a, b, c, d = _pieces(STRIPE, 4)
    out = _forwarded(_content(prompt=f"x {a}", response=b,
                              tool_parameters=c, error=f"{d} and {STRIPE}"))
    dumped = json.dumps(out)
    for piece in (a, b, c, d):
        assert piece not in dumped, out


def test_a_two_way_split_after_a_unit_ending_in_a_word_character_is_masked():
    """The pair's own window starts at the first piece, so the word before
    it does not glue onto the match."""
    pan = "4539578763621486"
    out = _forwarded(_content(user_system_prompt="say please", prompt=pan[:8],
                              response=f"{pan[8:]} {pan}"))
    assert pan[:8] not in json.dumps(out), out


def test_a_three_way_split_between_word_characters_denies():
    a, b, c = _pieces(FAKE_AWS_KEY, 3)
    _, verdict = _t0_verdict(["please", a, b, c, "thanks"])
    assert verdict.action == "deny"


def test_a_secret_in_one_character_units_is_one_finding():
    """The windows that overlap it all report it, and they merge into one."""
    units = _units("see ", *FAKE_GITHUB_TOKEN, " ok")
    result = scan(units, [T0RegexDetector()])
    (finding,) = [f for f in result.findings if f.detector == "regex:github-token"]
    assert {finding.locator, *finding.seam_others} == {
        f"u{i}" for i in range(1, len(FAKE_GITHUB_TOKEN) + 1)}


def test_a_seam_whose_text_folding_changed_counts_on_every_part(monkeypatch):
    """No offset in a refolded window maps to a part, so a spanned finding
    counts on all of them."""
    from forgd_verdict import normalize

    a, b, c = _pieces(FAKE_GITHUB_TOKEN, 3)
    real = normalize.fold
    monkeypatch.setattr(normalize, "fold", lambda t: (
        (t.replace(a + b, a + b[1:]), True) if a + b in t else real(t)))
    units = _units("clean " * 3, f"see {a}", b, f"{c} ok", "tail")
    seams = core._seams(units)
    refolded = {seam.locator: parts for seam, parts in seams
                if all(s == e for _, s, e in parts)}
    assert refolded
    found = [Finding(detector="d", severity="block", locator=loc, excerpt_hash="0" * 64,
                     start=0, end=3) for loc in refolded]
    for f, parts in zip(core._on_seams(found, refolded), refolded.values(), strict=True):
        assert [f.locator, *f.seam_others] == [loc for loc, _, _ in parts]


class _ForgedOthers:
    name = "forged"
    tier = 0

    def scan(self, units):
        return [Finding(detector="forged:x", severity="block", locator=u.locator,
                        excerpt_hash="0" * 64, seam_others=("elsewhere",))
                for u in units if "MARK" in u.text]


def test_a_detector_cannot_set_seam_others_off_a_seam():
    result = scan(_units("a MARK b"), [_ForgedOthers()])
    assert [f.seam_others for f in result.findings] == [()]
