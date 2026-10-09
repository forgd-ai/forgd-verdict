"""Detector protocol.

A detector turns ScanUnits into Findings. It must never return, log, or raise
matched text. Tier is advisory metadata used by the budget: T2 detectors are
the ones dropped first when a frame runs out of scan budget.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from ..models import Finding, ScanUnit


class DetectorFailed(RuntimeError):
    """A detector could not run. NOT the same as finding nothing.

    An empty result is indistinguishable from a clean scan, which is how a
    dead tier hides -- `DaemonUnavailable` already says this, and the
    subprocess path it sits beside was returning `[]` instead.

    Caught by `core.scan`, which records the detector as SKIPPED rather
    than run. Deliberately not fatal: on the verdict path a non-200 is a
    webhook failure rather than a deny, so a transient timeout must not
    take the request down -- it must be visible.
    """


class ScanTruncated(DetectorFailed):
    """A scan read only its last `scanned` units; `findings` are what
    those units produced. Every unit before them was not scanned."""

    def __init__(self, message: str, findings: list | None = None, scanned: int = 0):
        super().__init__(message)
        self.findings = list(findings or [])
        self.scanned = scanned


TIER_T0 = 0
TIER_T1 = 1
TIER_T2 = 2

# Boundaries for a label inside an `(?i)` pattern. No letter or digit, in
# any script (`[^\W_]`), may precede the label, except at a camelCase hump (`bankRouting`);
# underscores and punctuation are boundaries. `(?-i:...)` makes a test
# case-sensitive inside the case-insensitive pattern.
_HUMP = r"(?<=(?-i:[a-z]))(?=(?-i:[A-Z]))"
LABEL_START = rf"(?:(?<![^\W_])|{_HUMP})"
_LABEL_SUFFIX = r"(?:number|num|no|nr|id)(?![^\W_])"


def label(*alts: str) -> str:
    """A label gate for an `(?i)` pattern, matching any of `alts`.

    The label ends where no letter or digit follows it, or where one of
    `_LABEL_SUFFIX` follows it in any case (`nhsnumber`, `routingNumber`).
    A label written in capitals also ends where a camelCase word starts:
    a capital followed by a lowercase letter (`ABARoutingNumber`), so
    `SINGLE` and `NHSX` do not gate. A label in lower or mixed case
    followed by any other capital does not end there, so `useSinFunction`
    does not gate.
    """
    upper = "|".join(f"(?-i:{a.upper()})" for a in alts)
    any_case = "|".join(alts)
    return (
        rf"{LABEL_START}(?:(?:{upper})(?=(?-i:[A-Z][a-z]))"
        rf"|(?:{any_case})(?:(?![^\W_])|(?={_LABEL_SUFFIX})))"
    )


@runtime_checkable
class Detector(Protocol):
    name: str
    tier: int
    severity: str

    def available(self) -> bool:
        """False when a required binary or optional dependency is missing."""

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        ...
