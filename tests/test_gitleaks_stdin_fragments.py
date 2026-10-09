"""The gitleaks subprocess reads its stream in fragments; the stream opening
like a binary file or a token on a fragment cut must still be found."""

from __future__ import annotations

import shutil

import pytest

from forgd_verdict.budget import Budget
from forgd_verdict.core import scan
from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.models import ScanUnit

pytestmark = pytest.mark.skipif(not shutil.which("gitleaks"),
                                reason="gitleaks binary not installed")

T = "shpat_" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"


@pytest.mark.parametrize("first", ["%PDF-1.7 notes", "{\\rtf1 notes", "PK\x03\x04 notes"])
def test_a_stream_that_opens_like_a_binary_file_is_still_scanned(first):
    # gitleaks sources.File.fileFragments runs filetype.Match on the first
    # chunk and skips the whole input when its MIME type is application/*.
    units = [ScanUnit(locator="u0", tool_name=None, text=first),
             ScanUnit(locator="u1", tool_name=None, text=f"see {T}")]
    result = scan(units, [T0RegexDetector(), GitleaksDetector()], Budget(60_000))
    assert result.findings, "no finding: gitleaks skipped the stream as a binary file"


def test_a_token_at_a_fragment_cut_is_found():
    # The stdin source reads ~100 kB (pipe-dependent) plus at most 25 kB until
    # a blank line, then cuts mid-line; a match straddling the cut is in
    # neither fragment. Nondeterministic, so several runs.
    fill = "lorem ipsum dolor sit amet consectetur " * 60
    units = [ScanUnit(locator=f"v{i}", tool_name=None,
                      text=fill[:(i * 37) % 1500] + T + fill[:2000 - (i * 37) % 1500])
             for i in range(300)]
    missed = set()
    for _ in range(6):
        result = scan(units, [T0RegexDetector(), GitleaksDetector()], Budget(600_000))
        hit = {f.raw_locator or f.locator for f in result.findings}
        hit |= {o for f in result.findings for o in f.seam_others}
        missed |= {u.locator for u in units if u.locator not in hit}
    assert not missed, missed


def test_spans_past_the_first_window_are_exact():
    fill = "lorem ipsum dolor sit amet consectetur\n" * 50
    units = [ScanUnit(locator=f"v{i}", tool_name=None,
                      text=fill[:(i * 53) % 1900] + "x=" + T + "\n" + fill)
             for i in range(60)]
    findings = GitleaksDetector().scan(units)
    by_unit = {u.locator: u for u in units}
    spanned = [f for f in findings if f.start is not None]
    assert {f.locator for f in spanned} == set(by_unit)
    for f in spanned:
        text = by_unit[f.locator].text
        assert text[f.start:f.end] == T, (f.locator, text[f.start:f.end])


def test_a_multibyte_stream_keeps_spans_on_characters():
    units = [ScanUnit(locator=f"v{i}", tool_name=None,
                      text="é漢" * (i * 997 % 9000) + " " + T + " ü")
             for i in range(12)]
    findings = GitleaksDetector().scan(units)
    by_unit = {u.locator: u for u in units}
    assert {f.locator for f in findings} == set(by_unit)
    for f in findings:
        if f.start is not None:
            assert by_unit[f.locator].text[f.start:f.end] == T
