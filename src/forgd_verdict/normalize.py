"""Fold a string to the form a detector should see.

Every tier -- the regexes, the checksums, the entropy scan and gitleaks --
matches literal characters. A credential with one invisible codepoint in it
therefore matches nothing, while rendering identically to the human reading
the transcript and to the model consuming it:

    AKIAIOSFODNN7EXAMPLE            1 finding, denied
    AKIA<U+200B>IOSFODNN7EXAMPLE    0 findings, allowed

That is not a gap in one pattern. `\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b` cannot
match across a zero-width space, and no rewriting of the pattern set fixes
it, because the same character defeats the checksum tier and gitleaks too.
It has to be removed before any of them run.

Three transformations, and each earns its place against a probe that got a
secret past the whole default detector set:

**Format characters and combining marks are deleted.** Category `Cf` --
zero-width space, zero-width joiner and non-joiner, soft hyphen, the
directional marks, the word joiner, a BOM anywhere in the middle, the
Mongolian vowel separator, the tag characters. And category `Mn`, which
is the one that is not obvious: a combining acute or a variation selector
is not invisible in the way a ZWSP is, but dropped between two characters
of a credential it renders as a barely-perceptible mark and breaks the
same patterns. `AKIA<U+0301>IOSFODNN7EXAMPLE` and `AKIA<U+FE0F>IOSF...`
both scored zero against the full detector set.

Deleting `Mn` costs the folded view its accents, so `café` is scanned as
`cafe` and hashes as `cafe`. That is acceptable because the folded string
is only ever fed to detectors and digested -- it is never shown to
anyone, never stored, and never sent anywhere. It does mean scripts where
a combining mark is not decoration, such as Arabic harakat or Devanagari
matras, are scanned without them.

**Single-character compatibility forms are folded.** NFKC maps fullwidth
`Ａ` to `A`. Applied per character and only where the result is still
one character, so a ligature or a circled digit that would expand is left
alone -- see the length note below.

**A small set of homoglyphs is folded to Latin.** NFKC does not touch
these: Cyrillic `А` and Latin `A` are different letters that are not
compatibility-equivalent, and no amount of normalisation joins them. The
table is deliberately short -- the letters whose Latin lookalike is exact
in the fonts a transcript is read in -- because every entry is also a way
to make legitimate Cyrillic or Greek text look like something else.

## Why this is not configurable

`CLAUDE.md`: detection behaviour is not environment-tunable, and a default
that is only safe because we know about it is a bug. An operator who could
switch folding off would be switching off every tier at once for anyone who
knows one character.

## Length

Folding shortens text whenever it deletes a format character, so an offset
into the folded string is not an offset into the original. `core.scan`
handles that by dropping the span on any finding from a unit that changed,
which makes adapter 5 redact the whole value rather than a range it cannot
place. That is the existing safe path for "we know this contains a match
and cannot say where" -- see `sink/redact.py`.
"""

from __future__ import annotations

import unicodedata

# Latin lookalikes that NFKC leaves alone because they are genuinely
# different letters. Uppercase Cyrillic and Greek first, then the lowercase
# forms that are unambiguous. Kept short on purpose: a wrong entry mangles
# real text in those scripts, and the payoff is only for the letters that
# appear in credential alphabets.
# Cf is the invisible-by-design set. Mn is combining marks and the
# variation selectors -- see the module docstring for why they belong here
# despite being visible.
_DELETE = frozenset({"Cf", "Mn"})

_HOMOGLYPHS = {
    # Cyrillic -> Latin
    "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "У": "Y", "Х": "X",
    "І": "I", "Ј": "J", "Ѕ": "S",
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s",
    # Greek -> Latin
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X", "ο": "o",
}


def fold(text: str) -> tuple[str, bool]:
    """Return (folded, changed).

    `changed` is what the caller needs in order to know the offsets it is
    about to receive are not offsets into `text`.

    ASCII short-circuits. None of the three transformations can apply to a
    character below U+0080, and the overwhelming majority of scanned text
    is ASCII -- this runs on the verdict path inside a 5,000 ms end-to-end
    budget, so the common case must cost one scan and no allocation.
    """
    if text.isascii():
        return text, False

    out: list[str] = []
    for ch in text:
        if ch.isascii():
            out.append(ch)
            continue
        mapped = _HOMOGLYPHS.get(ch)
        if mapped is not None:
            out.append(mapped)
            continue
        if unicodedata.category(ch) in _DELETE:
            # Deleted, not replaced. A space would leave `AKIA IOSF...`,
            # which matches the pattern no better than the ZWSP did.
            continue
        folded = unicodedata.normalize("NFKC", ch)
        # Only a 1:1 compatibility mapping. An expansion would be a second
        # way to shift offsets for no detection benefit that the deletion
        # above does not already provide.
        out.append(folded if len(folded) == 1 else ch)

    result = "".join(out)
    return result, result != text
