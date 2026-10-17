"""T2: optional ML/NER PII detectors (LLM Guard, Presidio).

Off by default and budget-gated. These cost tens to hundreds of milliseconds
per KB, which is why `scan.budget_ms` drops them first rather than letting a
frame blow the org's verdict timeout. Install with `forgd-verdict[ml]`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..models import Finding, ScanUnit, digest
from .base import TIER_T2, DetectorFailed


def _offline_suffix_list() -> None:
    """Point tldextract's module-level extractor, the one Presidio's email
    recognizer calls, at the snapshot bundled in its wheel, with no
    suffix-list URLs and no cache, so it never reaches the network."""
    try:
        from tldextract import tldextract as _tld  # type: ignore
    except ImportError:  # pragma: no cover - depends on optional extra
        return
    _tld.TLD_EXTRACTOR = _tld.TLDExtract(
        cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True)

# --- the prose gate --------------------------------------------------------
#
# Presidio's NER entities are trained on natural language and are close to
# worthless on source code. Measured on this repository's own source, 29
# distinct PERSON values were reported and exactly one was a person: the rest
# were box-drawing characters, bare identifiers (`T0`, `AcrPush`), and code
# fragments (`detector.startswith("presidio`). `KB` came back as a
# nationality and `session_id` as a location.
#
# That precision is not a tuning problem -- spaCy scores all of them 0.85, the
# same as a real name -- so no threshold separates them. The fix is to not ask
# the question about text that is not prose. The gate also makes the tier
# cheaper, because code is most of the bytes in a coding transcript.

FENCED = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)
INLINE_CODE = re.compile(r"`[^`\n]+`")
# A diagram, a table rule, or a box-drawing run is never prose.
DECORATION = re.compile(r"[\u2500-\u257F\u2580-\u259F|+=_~^]{2,}")
# A word: alphabetic once surrounding punctuation is stripped. Deliberately
# word-based rather than character-based. Symbol density does not separate
# code from prose, because they share most characters -- `def _scan(self, x):`
# is 96% "prose characters" by that measure. What separates them is that a
# sentence is mostly plain words and a line of code has almost none.
WORD = re.compile(r"^[A-Za-z][a-z]*\Z")
TOKEN_TRIM = ".,;:!?()[]{}'\"\u2018\u2019\u201c\u201d\u2013\u2014"
# A line needs this many plain words, and this share of its tokens to be
# plain words, before the model is asked about it. Checked against real
# content: the sentence above scores 11 words at 0.85, a line of Python or a
# CLI invocation scores 0 or 1.
MIN_WORDS = 5
MIN_WORD_RATIO = 0.6
# A line with no lowercase run has no sentence in it -- a heading, a
# constant, a column of flags.
HAS_WORD = re.compile(r"[a-z]{3,}")


# --- the span filter ------------------------------------------------------
#
# The prose gate removes code. What remains is technical prose, which has its
# own failure: it is full of capitalised product and unit names, and spaCy
# tags a single capitalised token as a person about as readily as a real name
# and with the same 0.85 confidence. Measured on this repository's prose after
# gating, 14 distinct values came back and none was a person: `Claude`, `KB`,
# `GB`, `T0`, `JOSE`, `AcrPush`, `Webfonts`.
#
# Two structural rules and a small vocabulary handle almost all of it.

# Acronyms, units and identifiers. `KB` came back as a nationality.
MIN_SPAN_CHARS = 4
# Product and platform vocabulary that recurs in any transcript about this
# work. A list like this is a maintenance cost and is kept deliberately short;
# the structural rules below do most of the work.
NAME_STOPLIST = frozenset(
    x.lower()
    for x in (
        "Claude", "Cowork", "Anthropic", "Presidio", "Azure", "Entra",
        "Docker", "Kubernetes", "Python", "GitHub", "Slack", "Stripe",
        "Markdown", "Webfonts", "Stdlib", "JOSE", "Luhn", "Caddy",
    )
)


# A name does not contain a dash used as punctuation. The model can report
# a span like "Jane — Accounts" as a person, having swallowed a separator
# and the text either side of it.
PUNCT_DASH = re.compile(r"\s[\u2013\u2014-]\s")


def plausible_name(entity_type: str, span: str) -> bool:
    """Whether a matched span is worth reporting.

    Structural, not a blocklist of values: too short, all upper case, or a
    lone capitalised token. A real name in prose appears as at least two
    tokens somewhere in the text -- "Dana Whitfield" -- and a lone "Dana" is
    weak signal even when correct, so the trade is worth it. PERSON is the
    entity this matters for; a one-word location is often genuine.

    The later rules reject the artifacts the prose gate lets through: spans
    joined by a spaced dash, and spans beginning lower case.
    """
    span = span.strip().rstrip("\u2019'")
    if len(span) < MIN_SPAN_CHARS:
        return False
    if span.isupper():
        return False
    if PUNCT_DASH.search(span):
        return False
    tokens = span.split()
    if any(t.strip(TOKEN_TRIM).lower() in NAME_STOPLIST for t in tokens):
        return False
    if entity_type == "PERSON":
        # A lone capitalised token is where the product vocabulary lands.
        if len(tokens) < 2:
            return False
        # Every token of a name starts upper case. A span starting lower case
        # is a phrase the model ran into, not a person.
        if not all(t[:1].isupper() for t in tokens if t[:1].isalpha()):
            return False
        if not span[:1].isupper():
            return False
    return True


def _origin_span(original: str, matched: str) -> dict[str, int | None]:
    """Where `matched` sits in the text the redactor will edit.

    Presidio is asked about `prose_only(original)`, so its offsets belong
    to a different string. prose_only only REMOVES spans, it does not
    rewrite them, so the matched substring still appears verbatim in the
    original and can be found there.

    Ambiguous when it appears more than once -- the first occurrence is
    returned, and adapter 5 re-scans the masked value afterwards, so a
    second occurrence is caught there rather than forwarded.
    """
    if not matched:
        return {"start": None, "end": None}
    i = original.find(matched)
    if i < 0:
        return {"start": None, "end": None}
    return {"start": i, "end": i + len(matched)}


def prose_only(text: str) -> str:
    """Strip what is not natural language, line by line.

    Returns the prose, joined. An empty result means "do not ask the model
    about this at all", which is the common case for a tool result, a diff or
    a file read.
    """
    text = FENCED.sub(" ", text)
    text = INLINE_CODE.sub(" ", text)
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        # Too short to carry a sentence, and short lines are where bare
        # identifiers live.
        if len(stripped) < 12 or not HAS_WORD.search(stripped):
            continue
        if DECORATION.search(stripped):
            continue
        tokens = stripped.split()
        if not tokens:
            continue
        words = sum(1 for t in tokens if WORD.match(t.strip(TOKEN_TRIM)))
        if words < MIN_WORDS or words / len(tokens) < MIN_WORD_RATIO:
            continue
        kept.append(stripped)
    return "\n".join(kept)

# Findings are named `presidio:<entity_type lowercased>`, so a single
# `presidio:pii` key described nothing that is ever emitted. Descriptions read
# as the object of a sentence -- build_deny_reason composes "... contains X".
DESCRIPTIONS = {
    "llmguard:pii": "personal information",
    "presidio:person": "a person's name",
    "presidio:location": "a location",
    "presidio:email_address": "an email address",
    "presidio:phone_number": "a phone number",
    "presidio:nrp": "a nationality, religious or political affiliation",
    # Configurable, so describe the structured entities too even though the
    # deployed profile leaves them to T0.
    "presidio:credit_card": "a payment card number",
    "presidio:us_ssn": "a US Social Security Number",
    "presidio:iban_code": "an IBAN",
    "presidio:us_passport": "a US passport number",
    "presidio:us_driver_license": "a US driver's licence number",
    "presidio:medical_license": "a medical licence number",
    "presidio:date_time": "a date or time",
    "presidio:ip_address": "an IP address",
}


class PresidioPIIDetector:
    """Presidio analyzer. Entities are configurable; defaults are the ones
    that map onto a DLP policy rather than everything Presidio can find."""

    name = "presidio_pii"
    # The findings say `presidio:<entity>`, and `name` says `presidio_pii`.
    # Adapter 5 validates a redaction list against what the core can emit,
    # so the two namespaces have to be reconcilable or the only spelling
    # that starts is the one that redacts nothing. They were not, and it
    # was not a leak in theory: `redact: [presidio_pii]` booted, logged
    # itself as redacting, and passed an SSN to the wire in an event with
    # no forgd.redacted marker.
    finding_prefix = "presidio"
    tier = TIER_T2

    DEFAULT_ENTITIES = (
        "CREDIT_CARD",
        "US_SSN",
        "IBAN_CODE",
        "US_PASSPORT",
        "US_DRIVER_LICENSE",
        "MEDICAL_LICENSE",
    )

    def __init__(
        self,
        severity: str = "warn",
        salt: str = "",
        entities: tuple[str, ...] | None = None,
        score_threshold: float = 0.6,
        language: str = "en",
    ):
        self.severity = severity
        self._salt = salt
        self._entities = tuple(entities or self.DEFAULT_ENTITIES)
        self._threshold = score_threshold
        self._language = language
        self._analyzer = None
        self._load_failed = False

    def finding_ids(self) -> list[str]:
        """Exactly the ids this instance can emit.

        Enumerable, unlike gitleaks, because the entity list is
        configuration -- so a sink asking to redact `presidio:email_address`
        is checked against the entities actually enabled, and asking for
        one that is switched off is refused rather than silently doing
        nothing.
        """
        return [f"{self.finding_prefix}:{e.lower()}" for e in self._entities]

    def _load(self):
        if self._analyzer is not None or self._load_failed:
            return self._analyzer
        try:
            _offline_suffix_list()
            from presidio_analyzer import AnalyzerEngine  # type: ignore

            self._analyzer = AnalyzerEngine()
        except Exception:  # pragma: no cover - depends on optional extra
            self._load_failed = True
        return self._analyzer

    def available(self) -> bool:
        return self._load() is not None

    def matches(self, units: Iterable[ScanUnit]):
        """Yield `(detector_name, matched_value)` for spot checking.

        The tier whose precision most needs judging: 200 distinct person
        names were reported and the store could not say how many were people.
        """
        analyzer = self._load()
        if analyzer is None:
            return
        for unit in units:
            if not unit.text:
                continue
            text = prose_only(unit.text)
            if not text:
                continue
            try:
                results = analyzer.analyze(
                    text=text, entities=list(self._entities), language=self._language
                )
            except Exception as exc:  # pragma: no cover - model/runtime failure
                # Raised, not skipped. A tier that ran and returned
                # nothing is indistinguishable from a clean one, and
                # adapter 5's `_blind_to` understands only
                # `detectors_skipped` -- so with this tier listed under
                # `redact:` a model failure sent the value out
                # uncensored, with no marker and no counter.
                raise DetectorFailed(
                    f"{self.name} could not analyse: {type(exc).__name__}"
                ) from exc
            for r in results:
                if r.score < self._threshold:
                    continue
                matched = text[r.start : r.end]
                if plausible_name(r.entity_type, matched):
                    yield f"presidio:{r.entity_type.lower()}", matched

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        analyzer = self._load()
        if analyzer is None:
            return []
        findings: list[Finding] = []
        for unit in units:
            if not unit.text:
                continue
            # Ask the model about prose only. See the prose gate above: on
            # code, these entities report ~3% precision at the same
            # confidence they give a real name.
            text = prose_only(unit.text)
            if not text:
                continue
            try:
                results = analyzer.analyze(
                    text=text, entities=list(self._entities), language=self._language
                )
            except Exception as exc:  # pragma: no cover - model/runtime failure
                # Raised, not skipped. A tier that ran and returned
                # nothing is indistinguishable from a clean one, and
                # adapter 5's `_blind_to` understands only
                # `detectors_skipped` -- so with this tier listed under
                # `redact:` a model failure sent the value out
                # uncensored, with no marker and no counter.
                raise DetectorFailed(
                    f"{self.name} could not analyse: {type(exc).__name__}"
                ) from exc
            for r in results:
                if r.score < self._threshold:
                    continue
                matched = text[r.start : r.end]
                if not plausible_name(r.entity_type, matched):
                    continue
                findings.append(
                    Finding(
                        detector=f"presidio:{r.entity_type.lower()}",
                        severity=self.severity,
                        locator=unit.locator,
                        excerpt_hash=digest(matched, self._salt),
                        matched=matched,
                        tool_name=unit.tool_name,
                        # Translated back to the ORIGINAL text, not left in
                        # Presidio's coordinates. `analyze` was given
                        # prose_only(unit.text), which strips fenced and
                        # inline code -- so r.start/r.end index a shorter
                        # string and applying them to the original masks
                        # the wrong substring while leaving the PII in
                        # place. None when the match cannot be located,
                        # which the redactor treats as "replace the whole
                        # value".
                        **_origin_span(unit.text, matched),
                    )
                )
        return findings


class LLMGuardPIIDetector:
    """LLM Guard's Anonymize scanner used as a detector (no rewriting -- the
    Inference hooks protocol is allow/deny, there is nowhere to put redacted
    text)."""

    name = "llmguard_pii"
    # Same split as Presidio: findings say `llmguard:pii`.
    finding_prefix = "llmguard"
    tier = TIER_T2

    def finding_ids(self) -> list[str]:
        return ["llmguard:pii"]

    def __init__(self, severity: str = "warn", salt: str = "", threshold: float = 0.5):
        self.severity = severity
        self._salt = salt
        self._threshold = threshold
        self._scanner = None
        self._load_failed = False

    def _load(self):
        if self._scanner is not None or self._load_failed:
            return self._scanner
        try:
            _offline_suffix_list()
            from llm_guard.input_scanners import Anonymize  # type: ignore
            from llm_guard.vault import Vault  # type: ignore

            self._scanner = Anonymize(Vault(), threshold=self._threshold)
        except Exception:  # pragma: no cover - depends on optional extra
            self._load_failed = True
        return self._scanner

    def available(self) -> bool:
        return self._load() is not None

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        scanner = self._load()
        if scanner is None:
            return []
        findings: list[Finding] = []
        for unit in units:
            if not unit.text:
                continue
            try:
                _sanitized, is_valid, risk = scanner.scan(unit.text)
            except Exception as exc:  # pragma: no cover - model/runtime failure
                # Raised, not skipped. A tier that ran and returned
                # nothing is indistinguishable from a clean one, and
                # adapter 5's `_blind_to` understands only
                # `detectors_skipped` -- so with this tier listed under
                # `redact:` a model failure sent the value out
                # uncensored, with no marker and no counter.
                raise DetectorFailed(
                    f"{self.name} could not analyse: {type(exc).__name__}"
                ) from exc
            if is_valid:
                continue
            findings.append(
                Finding(
                    detector="llmguard:pii",
                    severity=self.severity,
                    locator=unit.locator,
                    # LLM Guard reports a risk score, not spans. Hash the
                    # score bucket so the finding still carries no content.
                    excerpt_hash=digest(f"llmguard-risk-{risk:.2f}", self._salt),
                    tool_name=unit.tool_name,
                )
            )
        return findings
