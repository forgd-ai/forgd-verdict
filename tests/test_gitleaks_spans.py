"""Gitleaks findings carry the match's character offsets in their unit,
mapped from the report's UTF-8 byte columns, or no span when the columns
do not locate the match."""

from __future__ import annotations

import shutil

import pytest

from forgd_verdict.detectors.gitleaks import GitleaksDetector, _span
from forgd_verdict.models import ScanUnit
from forgd_verdict.store.base import FindingRow

T = "shpat_" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"

needs_gitleaks = pytest.mark.skipif(not shutil.which("gitleaks"),
                                    reason="gitleaks binary not installed")


def _spans(*texts: str) -> dict[str, tuple[int | None, int | None]]:
    gl = GitleaksDetector()
    assert gl.available() and not gl.uses_daemon
    units = [ScanUnit(locator=f"u{i}", tool_name=None, text=t) for i, t in enumerate(texts)]
    return {f.locator: (f.start, f.end) for f in gl.scan(units)}


@needs_gitleaks
def test_a_match_on_the_first_line_of_the_stream():
    assert _spans(f"see {T}") == {"u0": (4, 4 + len(T))}


@needs_gitleaks
def test_a_match_on_a_later_line_after_a_non_ascii_prefix():
    text = f"xé {T} ok"
    spans = _spans("nothing here", text)
    assert spans == {"u1": (3, 3 + len(T))}
    assert text[3:3 + len(T)] == T


@needs_gitleaks
def test_a_match_on_a_later_line_of_its_own_unit():
    text = f"first line\nsé {T}"
    start, end = _spans("nothing here", text)["u1"]
    assert text[start:end] == T


@needs_gitleaks
def test_matches_in_three_units_each_get_their_own_span():
    texts = [f"see {T}", f"xé {T} ok", T]
    spans = _spans(*texts)
    assert {k: texts[int(k[1:])][s:e] for k, (s, e) in spans.items()} == {
        "u0": T, "u1": T, "u2": T}


def _item(**kw):
    return {"StartLine": 2, "EndLine": 2, "StartColumn": 6, "EndColumn": 43,
            "Match": T, **kw}


def test_the_columns_of_a_later_line_map_to_characters():
    assert _span(_item(), f"xé {T} ok", 0) == (3, 3 + len(T))


@pytest.mark.parametrize("item", [
    _item(StartColumn=7),
    _item(EndLine=3),
    _item(Match=T[:-1]),
    {k: v for k, v in _item().items() if k != "StartColumn"},
    _item(EndColumn="x"),
    _item(EndColumn=400),
])
def test_columns_that_do_not_locate_the_match_give_no_span(item):
    assert _span(item, f"xé {T} ok", 0) == (None, None)


@needs_gitleaks
def test_a_span_reaches_neither_a_log_line_nor_a_stored_finding():
    gl = GitleaksDetector()
    (finding,) = gl.scan([ScanUnit(locator="u0", tool_name=None, text=f"see {T}")])
    assert finding.start is not None
    fields = {"detector", "severity", "locator", "excerpt_hash", "tool_name"}
    assert set(finding.to_log()) == fields
    row = FindingRow.from_finding(finding)
    assert not hasattr(row, "start") and not hasattr(row, "end")
