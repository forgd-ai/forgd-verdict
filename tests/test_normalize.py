"""Unicode folding before detection.

The finding this closes: one invisible codepoint inside a credential
defeated the regex tier, the checksum tier, the entropy tier and gitleaks
simultaneously, in every adapter and every enforcing mode, with no
configuration involved. The payload renders identically to the person
reading the transcript and to the model consuming it.
"""

from __future__ import annotations

from forgd_verdict.core import scan
from forgd_verdict.extract import hook_units
from forgd_verdict.models import ScanUnit
from forgd_verdict.normalize import fold
from forgd_verdict.policy import load_policy

KEY = "AKIAIOSFODNN7EXAMPLE"

# Every row gets past the whole default detector set without folding.
EVASIONS = {
    "zero-width space": "AKIA​IOSFODNN7EXAMPLE",
    "zero-width joiner": "AKIA‍IOSFODNN7EXAMPLE",
    "zero-width non-joiner": "AKIA‌IOSFODNN7EXAMPLE",
    "soft hyphen": "AKIA­IOSFODNN7EXAMPLE",
    "right-to-left mark": "AKIA‏IOSFODNN7EXAMPLE",
    "word joiner": "AKIA⁠IOSFODNN7EXAMPLE",
    "byte order mark": "AKIA﻿IOSFODNN7EXAMPLE",
    "cyrillic A": "АKIAIOSFODNN7EXAMPLE",
    "fullwidth AK": "ＡＫIAIOSFODNN7EXAMPLE",
    "combining acute": "AKIA" + chr(0x0301) + "IOSFODNN7EXAMPLE",
    "variation selector": "AKIA" + chr(0xFE0F) + "IOSFODNN7EXAMPLE",
    "mongolian vowel separator": "AKIA" + chr(0x180E) + "IOSFODNN7EXAMPLE",
    "tag character": "AKIA" + chr(0xE0041) + "IOSFODNN7EXAMPLE",
}


def _policy():
    return load_policy("policy.yaml")


def test_every_evasion_folds_back_to_the_key():
    for name, text in EVASIONS.items():
        folded, changed = fold(text)
        assert folded == KEY, f"{name}: {folded!r}"
        assert changed, name


def test_the_shipped_detectors_deny_every_evasion():
    """The property that matters, through the real policy and real units."""
    policy = _policy()
    detectors = policy.build_detectors()
    for name, text in EVASIONS.items():
        units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                            "tool_input": {"command": text}})
        result = scan(units, detectors)
        assert result.findings, f"{name} was not detected"


def test_folding_happens_in_the_constructor_so_no_adapter_can_forget():
    """Deliberately not in `extract._add`.

    Several adapters build units, through several different functions, and
    another adapter is a plausible next change. Folding per call site is one
    omission away from a surface that is silently unprotected.
    """
    unit = ScanUnit(locator="x", tool_name=None, text="AKIA​IOSFODNN7EXAMPLE")
    assert unit.text == KEY
    assert unit.folded


def test_a_folded_unit_yields_no_span():
    """Offsets into the folded string are not offsets into the original.

    `sink/redact.py` reads a missing span as "contains a match, position
    unknown" and replaces the whole value -- which is right. A span kept
    here would censor the wrong characters and leave part of the secret
    visible, which is the one outcome adapter 5 exists to prevent.
    """
    policy = _policy()
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": "x AKIA​IOSFODNN7EXAMPLE y"}})
    findings = scan(units, policy.build_detectors()).findings
    assert findings
    assert all(f.start is None and f.end is None for f in findings)


def test_an_unfolded_unit_keeps_its_span():
    """The common case must not lose adapter 5's ability to mask a range."""
    policy = _policy()
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": f"x {KEY} y"}})
    findings = scan(units, policy.build_detectors()).findings
    assert findings
    assert any(f.start is not None and f.end is not None for f in findings)


def test_ascii_is_returned_unchanged_and_not_copied():
    """The fast path. This runs inside a 5,000 ms end-to-end budget."""
    text = "a perfectly ordinary prompt with no funny business " * 200
    folded, changed = fold(text)
    assert folded is text and not changed


def test_folding_ascii_text_is_not_measurably_expensive():
    """ASCII is checked with one `isascii` scan, never walked per character."""

    touched: list[str] = []

    class NoWalk(str):
        def __iter__(self):
            touched.append("iterated")
            return super().__iter__()

        def __getitem__(self, key):
            touched.append("indexed")
            return super().__getitem__(key)

    body = NoWalk("lorem ipsum dolor sit amet " * 4000)  # ~108 KB, ASCII
    folded, changed = fold(body)
    assert folded is body and not changed
    assert touched == []


def test_legitimate_non_ascii_prose_survives():
    """Folding must not mangle text that is simply not English."""
    # Precomposed accents survive: NFKC leaves them as one character
    # and they are category Ll, not Mn.
    for text in ("naïve café résumé", "日本語のテキスト", "emoji 🎉 stays"):
        folded, _ = fold(text)
        assert folded == text, folded


def test_combining_marks_are_deleted_too():
    """Not obvious, and probing is what settled it.

    A combining mark is not invisible the way a ZWSP is, so the first
    version of this module kept category Mn. Dropped between two
    characters of a credential it renders as a barely-perceptible tick
    and breaks the pattern exactly as well -- both of these scored zero
    against the full detector set:

        AKIA<U+0301>IOSFODNN7EXAMPLE
        AKIA<U+FE0F>IOSFODNN7EXAMPLE

    The cost is that the folded view loses accents, and the folded view
    is only ever scanned and digested -- never shown, stored or sent.
    """
    folded, changed = fold("e" + chr(0x0301) + "clair")
    assert folded == "eclair" and changed
