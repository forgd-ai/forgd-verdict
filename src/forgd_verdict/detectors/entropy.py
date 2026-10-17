"""T0b: entropy detection for secrets no pattern anticipates.

Every rule in t0_regex enumerates a known credential format, which means a
key in a format nobody predicted is invisible. This detector works the other
way round: it looks for strings that are statistically improbable as prose or
identifiers, which is what a randomly generated secret is.

Entropy alone is a false-positive machine -- hashes, UUIDs, base64 payloads,
minified code and git SHAs are all high-entropy and all harmless. So a match
needs to clear four independent gates:

  1. **Shannon entropy** above a per-charset floor. Base64 and hex have
     different achievable maxima, so one threshold for both is wrong.
  2. **Length** in a credential-shaped band. Short strings cannot carry
     enough entropy to be meaningful; very long ones are usually payloads.
  3. **A structural allowlist** for things that are high-entropy by
     construction and not secrets: UUIDs, git SHAs, hex digests at exactly
     the length of a known hash, IP addresses, dates, pure numbers.
  4. **Assignment context** -- the string appears after `=`, `:`, or inside
     quotes following a key that looks like a credential name. Free-floating
     random strings in prose are usually not secrets; a random string on the
     right-hand side of `api_key=` almost always is.

Gate 4 is what makes this usable inline. Without it the rule fires on
every git SHA in a diff and every base64 blob in a tool result, and an
operator switches it off within a day -- which is worse than not shipping it.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable

from ..models import Finding, ScanUnit, digest
from .base import TIER_T0

# Charset-specific entropy floors, in bits per character. Base64's ceiling
# is log2(64)=6, hex's is log2(16)=4, so a single threshold would either
# miss base64 secrets or flood on hex.
FLOOR_BASE64 = 4.2
FLOOR_HEX = 3.2

MIN_LEN = 20
MAX_LEN = 200

# Keys whose value is worth flagging when it looks random. Deliberately
# narrow: this is the gate that keeps the detector precise.
KEY_HINT = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?=[abceprstw])("
    r"api[_-]?key|apikey|secret|token|passwd|password|pwd|auth|credential|"
    r"private[_-]?key|access[_-]?key|client[_-]?secret|bearer|session[_-]?key|"
    r"encryption[_-]?key|signing[_-]?key|refresh[_-]?token|webhook[_-]?secret"
    r")[\"'\s]*+[:=]\s*+[\"']?+([A-Za-z0-9+/=_\-]{20,200})"
)

# Structurally explained high entropy. None of these is a secret.
UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
HEX_ONLY = re.compile(r"(?i)^[0-9a-f]+\Z")
# Exact lengths of common digests and git object ids.
DIGEST_LENGTHS = {32, 40, 56, 64, 96, 128}
DATEISH = re.compile(r"^[0-9][0-9\-:._T]+[0-9]\Z")


def shannon(text: str) -> float:
    """Bits of entropy per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def structurally_explained(value: str) -> str | None:
    """Return a reason when the entropy has a benign explanation."""
    if UUID.match(value):
        return "uuid"
    if value.isdigit():
        return "numeric"
    if DATEISH.match(value):
        return "timestamp"
    if HEX_ONLY.match(value):
        # A hex string at exactly a digest length is a hash, not a key.
        if len(value) in DIGEST_LENGTHS:
            return "hex-digest"
        return None
    return None


def looks_random(value: str) -> tuple[bool, float, str]:
    """(verdict, entropy, charset) for a candidate secret."""
    if not (MIN_LEN <= len(value) <= MAX_LEN):
        return False, 0.0, "length"
    charset = "hex" if HEX_ONLY.match(value) else "base64"
    floor = FLOOR_HEX if charset == "hex" else FLOOR_BASE64
    bits = shannon(value)
    return bits >= floor, bits, charset


class EntropyDetector:
    """Assigned values that look randomly generated.

    Severity defaults to `warn`, not `block`. Entropy is inherently a
    heuristic, and a heuristic that blocks is a heuristic that gets
    switched off. Promote it per-deployment once its false-positive rate is
    known on that deployment's own traffic.
    """

    name = "entropy"
    tier = TIER_T0

    def __init__(self, severity: str = "warn", salt: str = ""):
        self.severity = severity
        self._salt = salt
        self.suppressed: dict[str, int] = {}

    def available(self) -> bool:
        return True

    def matches(self, units: Iterable[ScanUnit]):
        """Yield `(detector_name, matched_value)` for spot checking.

        Mirrors `scan` without building Findings. See
        ChecksumDetector.matches for why this exists.
        """
        for unit in units:
            if not unit.text or unit.structural:
                continue
            for match in KEY_HINT.finditer(unit.text):
                key, value = match.group(1), match.group(2)
                if structurally_explained(value):
                    continue
                ok, _bits, _charset = looks_random(value)
                if ok:
                    yield f"entropy:{key.lower().replace(' ', '')}", value

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        findings: list[Finding] = []
        for unit in units:
            if not unit.text or unit.structural:
                continue
            for match in KEY_HINT.finditer(unit.text):
                key, value = match.group(1), match.group(2)
                reason = structurally_explained(value)
                if reason:
                    self.suppressed[reason] = self.suppressed.get(reason, 0) + 1
                    continue
                ok, bits, charset = looks_random(value)
                if not ok:
                    continue
                findings.append(
                    Finding(
                        # The key name is in the detector id, not the value:
                        # "a value assigned to api_key looks random" is the
                        # finding, and the key name is not sensitive.
                        detector=f"entropy:{key.lower().replace(' ', '')}",
                        severity=self.severity,
                        locator=unit.locator,
                        excerpt_hash=digest(value, self._salt),
                        matched=value,
                        tool_name=unit.tool_name,
                    )
                )
        return findings


DESCRIPTIONS = {"entropy": "a value that appears to be a credential"}
