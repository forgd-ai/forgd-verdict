"""`dedupe_findings` keeps one finding per (detector, locator, excerpt), and
merges a repeat into the first: it counts on every unit either lists in
`seam_others`, and has no span when either has none."""

from __future__ import annotations

from forgd_verdict.models import Finding, dedupe_findings

LEFT = "otel[0].claude_code.api_request.prompt"
RIGHT = "otel[0].claude_code.api_request.response"
THIRD = "otel[0].claude_code.api_request.error"


def _finding(excerpt_hash="h", **kw) -> Finding:
    return Finding(detector="regex:github-token", severity="block", locator=LEFT,
                   excerpt_hash=excerpt_hash, **kw)


def test_a_repeated_finding_is_kept_once():
    assert dedupe_findings([_finding(start=2, end=9), _finding(start=2, end=9)]) == [
        _finding(start=2, end=9)]


def test_a_seam_finding_after_one_on_its_value_alone_is_merged_without_a_span():
    alone = _finding(start=2, end=9)
    seam = _finding(seam_others=(RIGHT,))
    (merged,) = dedupe_findings([alone, seam])
    assert merged.seam_others == (RIGHT,)
    assert (merged.start, merged.end) == (None, None)


def test_a_finding_on_its_value_alone_after_its_seam_finding_keeps_no_span():
    seam = _finding(seam_others=(RIGHT,))
    alone = _finding(start=2, end=9)
    (merged,) = dedupe_findings([seam, alone])
    assert merged.seam_others == (RIGHT,)
    assert (merged.start, merged.end) == (None, None)


def test_a_span_less_repeat_drops_the_span():
    """The span-less one may be another occurrence the span does not cover."""
    (merged,) = dedupe_findings([_finding(start=2, end=9), _finding()])
    assert (merged.start, merged.end) == (None, None)


def test_two_seam_findings_merge_the_units_they_count_on():
    first = _finding(seam_others=(RIGHT,))
    second = _finding(seam_others=(THIRD, RIGHT))
    (merged,) = dedupe_findings([first, second])
    assert merged.seam_others == (RIGHT, THIRD)


def test_findings_with_different_keys_are_both_kept():
    other = Finding(detector="regex:github-token", severity="block", locator=RIGHT,
                    excerpt_hash="h")
    assert len(dedupe_findings([_finding(), other, _finding(excerpt_hash="g")])) == 3
