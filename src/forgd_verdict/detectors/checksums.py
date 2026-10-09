"""T0c: checksum-validated identifiers.

Breadth without guesswork. Every identifier here carries a mathematical
check digit, so a match is near-certain rather than probable: a random
sixteen-digit number passes Luhn one time in ten, an IBAN passes mod-97 one
time in ninety-seven, and an NHS number passes mod-11 one time in eleven.
Combined with a format constraint that is already selective, the false
positive rate is low enough to justify `block`.

This is the honest answer to "it is only regex". The pattern locates a
candidate; arithmetic decides. Adding a detector here is adding a validated
identifier, not another hopeful expression.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import NamedTuple

from ..models import Finding, ScanUnit, digest
from .base import TIER_T0, label


class Check(NamedTuple):
    id: str
    pattern: re.Pattern[str]
    validate: Callable[[str], bool]
    description: str


def _digits(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


def luhn(value: str) -> bool:
    digits = _digits(value)
    if not digits:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_mod97(value: str) -> bool:
    """ISO 13616: move the first four characters to the end, letters to
    digits (A=10), then the whole thing mod 97 must equal 1."""
    compact = re.sub(r"[\s-]", "", value).upper()
    if not (15 <= len(compact) <= 34) or not compact[:2].isalpha():
        return False
    rotated = compact[4:] + compact[:4]
    converted = ""
    for ch in rotated:
        if ch.isdigit():
            converted += ch
        elif ch.isalpha():
            converted += str(ord(ch) - 55)
        else:
            return False
    try:
        return int(converted) % 97 == 1
    except ValueError:
        return False


def aba_routing(value: str) -> bool:
    """ABA/FedWire: weighted 3-7-1 sum mod 10 must be zero."""
    d = _digits(value)
    if len(d) != 9:
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    total = sum(int(c) * w for c, w in zip(d, weights, strict=True))
    # 0000 is a reserved prefix, and an all-zero routing number is a
    # placeholder rather than a bank.
    return total % 10 == 0 and set(d) != {"0"}


def nhs_number(value: str) -> bool:
    """UK NHS number: mod-11 with weights 10..2; remainder 10 is invalid."""
    d = _digits(value)
    if len(d) != 10 or len(set(d)) == 1:
        return False
    total = sum(int(c) * (10 - i) for i, c in enumerate(d[:9]))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    return check != 10 and check == int(d[9])


def canadian_sin(value: str) -> bool:
    d = _digits(value)
    return len(d) == 9 and len(set(d)) > 1 and luhn(d)


def imei(value: str) -> bool:
    d = _digits(value)
    return len(d) == 15 and len(set(d)) > 1 and luhn(d)


_SIN_LABEL = label("sin", r"s\.i\.n\.?", "social insurance")

CHECKS: tuple[Check, ...] = (
    Check(
        "iban",
        # Country code, check digits, then the BBAN. Optional spacing as
        # people paste it from a bank statement. Not inside a run of letters
        # and digits; `_` either side is a separator.
        re.compile(r"[A-Z](?<![^\W_][A-Z])[A-Z][0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}"
                   r"(?:[ ]?[A-Z0-9]{1,3})?(?![^\W_])"),
        iban_mod97,
        "an international bank account number",
    ),
    Check(
        "aba-routing",
        re.compile(rf"(?i){label('routing', 'aba', 'rtn')}"
                   r"[^0-9\n]{0,16}([0-9]{9})(?!\d)"),
        aba_routing,
        "a bank routing number",
    ),
    Check(
        "nhs-number",
        # Label-gated, and this one is load-bearing. Ungated, the pattern is
        # "any ten-digit number" and mod-11 passes about one in eleven by
        # chance, so a deck full of figures yields matches with no mention of
        # the NHS anywhere. An arithmetic check is a filter, not an identity
        # proof.
        re.compile(
            rf"(?i){label('nhs')}[^0-9\n]{{0,16}}"
            r"([0-9]{3}[ -]?[0-9]{3}[ -]?[0-9]{4})(?!\d)"
        ),
        nhs_number,
        "a UK NHS number",
    ),
    Check(
        "canadian-sin",
        re.compile(rf"(?i){_SIN_LABEL}"
                   r"[^0-9\n]{0,16}([0-9]{3}[ -]?[0-9]{3}[ -]?[0-9]{3})(?!\d)"),
        canadian_sin,
        "a Canadian Social Insurance Number",
    ),
    Check(
        "imei",
        re.compile(rf"(?i){label('imei[12]?')}[^0-9\n]{{0,16}}([0-9]{{15}})(?!\d)"),
        imei,
        "a device IMEI",
    ),
)

# No pattern above matches fewer characters than this.
SHORTEST_MATCH = 12

DESCRIPTIONS = {f"checksum:{c.id}": c.description for c in CHECKS}


class ChecksumDetector:
    """Identifiers where arithmetic, not a pattern, makes the decision."""

    name = "checksum"
    tier = TIER_T0

    def __init__(self, severity: str = "block", salt: str = "",
                 enabled: set[str] | None = None):
        self.severity = severity
        self._salt = salt
        self._checks = tuple(c for c in CHECKS if enabled is None or c.id in enabled)

    def available(self) -> bool:
        return True

    def matches(self, units: Iterable[ScanUnit]):
        """Yield `(detector_name, matched_value)` for spot checking.

        The same walk `scan` does, minus the Finding. Exists because a
        Finding carries a hash and no offset, so a caller wanting to judge
        precision would otherwise have to guess which substring produced
        which hash -- and guessing silently returned nothing for every
        value the detector had normalised, which is most of them.
        """
        for unit in units:
            if len(unit.text or "") < SHORTEST_MATCH:
                continue
            for check in self._checks:
                for match in check.pattern.finditer(unit.text):
                    value = match.group(match.lastindex or 0)
                    if check.validate(value):
                        yield f"checksum:{check.id}", value

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        findings: list[Finding] = []
        for unit in units:
            if len(unit.text or "") < SHORTEST_MATCH:
                continue
            for check in self._checks:
                for match in check.pattern.finditer(unit.text):
                    value = match.group(match.lastindex or 0)
                    if not check.validate(value):
                        continue
                    findings.append(
                        Finding(
                            detector=f"checksum:{check.id}",
                            severity=self.severity,
                            locator=unit.locator,
                            excerpt_hash=digest(value, self._salt),
                            tool_name=unit.tool_name,
                        )
                    )
        return findings
