"""The scan core: detectors -> Finding[], Finding[] -> Verdict.

This is the only place detection logic, severity handling and deny wording
live. The adapters translate transport in and out; none of them makes a
policy decision of its own.
"""

from __future__ import annotations

import binascii
import bisect
import codecs
import itertools
import logging
import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from .budget import Budget
from .cache import SessionCache, SessionState, head_digest, message_shape, resume_point
from .detectors.base import TIER_T1, TIER_T2, DetectorFailed, ScanTruncated
from .detectors.checksums import DESCRIPTIONS as CHECKSUM_DESCRIPTIONS
from .detectors.entropy import DESCRIPTIONS as ENTROPY_DESCRIPTIONS
from .detectors.mlpii import DESCRIPTIONS as ML_DESCRIPTIONS
from .detectors.shell_exfil import DESCRIPTIONS as SHELL_DESCRIPTIONS
from .detectors.t0_regex import DESCRIPTIONS as REGEX_DESCRIPTIONS
from .models import (
    ACTION_ALLOW,
    ACTION_DENY,
    BLOCK_LOCATOR,
    DENY_REASON_MAX,
    FINDINGS_CAPPED,
    MAX_LOCATOR_CHARS,
    MAX_LOCATOR_SEGMENTS,
    MAX_SCAN_UNITS,
    NOT_TAINT_SOURCES,
    SEVERITY_BLOCK,
    UNSCANNED,
    UNSCANNED_ARTIFACT,
    UNSCANNED_CAPPED,
    UNSCANNED_DELETED,
    UNSCANNED_PARTIAL,
    Finding,
    ScanUnit,
    Verdict,
    dedupe_findings,
    make_reference_id,
)
from .plugins import PluginDetector
from .policy import Policy

# detector id -> user-facing noun phrase. Used to build deny_reason.
DESCRIPTIONS: dict[str, str] = {
    "taint:sensitive-data-sent": (
        "sensitive data read earlier in this conversation being sent to a "
        "destination you did not name"),
    "provenance:untrusted-destination": (
        "a request sending data to a destination named by a fetched page, "
        "file or tool result rather than by you"),
    **{f"regex:{k}": v for k, v in REGEX_DESCRIPTIONS.items()},
    **SHELL_DESCRIPTIONS,
    **ML_DESCRIPTIONS,
    **CHECKSUM_DESCRIPTIONS,
}

# gitleaks emits hundreds of rule ids. Rather than enumerate them, map the
# common families and fall back to a generic phrase.
_GITLEAKS_FAMILIES: tuple[tuple[str, str], ...] = (
    ("aws", "an AWS credential"),
    ("github", "a GitHub credential"),
    ("gitlab", "a GitLab credential"),
    ("slack", "a Slack credential"),
    ("stripe", "a Stripe credential"),
    ("private-key", "a private key"),
    ("privatekey", "a private key"),
    ("jwt", "a JSON Web Token"),
    ("azure", "an Azure credential"),
    ("gcp", "a Google Cloud credential"),
    ("google", "a Google credential"),
    ("openai", "an API key"),
    ("anthropic", "an Anthropic API key"),
    ("twilio", "a Twilio credential"),
    ("sendgrid", "a SendGrid credential"),
    ("npm", "an npm token"),
    ("docker", "a Docker registry credential"),
    ("database", "a database connection string"),
    ("postgres", "a database connection string"),
    ("mysql", "a database connection string"),
    ("mongodb", "a database connection string"),
)


def describe(detector: str, plugin_phrases: Mapping[str, str] | None = None) -> str:
    """Human phrasing for a detector id. Never returns matched content.

    `plugin_phrases` is `Policy.plugin_phrases()` of the policy that built
    the detectors; without it a plugin id gets the generic wording."""
    if detector in DESCRIPTIONS:
        return DESCRIPTIONS[detector]
    if detector.startswith("entropy:"):
        return ENTROPY_DESCRIPTIONS["entropy"]
    if detector.startswith("gitleaks:"):
        rule = detector.split(":", 1)[1].lower()
        for needle, phrase in _GITLEAKS_FAMILIES:
            if needle in rule:
                return phrase
        return "a credential or secret"
    if detector.startswith("presidio:"):
        return "personal information"
    return (plugin_phrases or {}).get(detector) or "restricted content"


def short_tag(detector: str) -> str:
    """Compact, charset-safe tag for the reference_id."""
    tail = detector.split(":", 1)[-1]
    return "".join(c for c in tail if c.isalnum() or c in "-.")[:12] or "scan"


log = logging.getLogger("forgd_verdict.core")

# What a locator segment, run, whole locator or tool name that a detector
# matches is replaced with. It carries no digest of the replaced text.
REDACTED = "<redacted>"

# The most findings one `scan` keeps. Units over MAX_SCAN_UNITS and findings
# over this are recorded as UNSCANNED_CAPPED in `detectors_skipped`.
MAX_SCAN_FINDINGS = 5_000

@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    budget_exceeded: bool = False
    cache_hit: bool = False
    messages_scanned: int = 0
    messages_total: int = 0
    detectors_run: list[str] = field(default_factory=list)
    detectors_skipped: list[str] = field(default_factory=list)
    # Locators of values over their adapter's size limit whose middle no
    # detector saw. Empty on every ordinary frame. When it is not empty,
    # `detectors_skipped` also holds UNSCANNED.
    truncated: list[str] = field(default_factory=list)


def scrub_label(text: str, detectors: Sequence[Any]) -> str:
    """Public entry for anything that publishes sender-controlled NAMES.

    Adapter 4's `/stats` reports unrecognised attribute names, and an
    attribute can be named with a credential.
    """
    cheap = [d for d in detectors if getattr(d, "tier", 0) < TIER_T2]
    return _scrub_segment(text, cheap) if cheap else text


# One `_scrub_names` or `scrub_labels` call probes at most
# `_SCRUB_BUDGET_BYTES` of candidate text, as UTF-8, and starts no detector
# call after `_SCRUB_BUDGET_S`. A locator, tool name or label whose
# candidates are not all probed within both is replaced whole by
# `REDACTED`.
_SCRUB_BUDGET_BYTES = 256 * 1024
_SCRUB_BUDGET_S = 0.25
# The candidate text one `_scrub_names` call may build, probed or not, as a
# multiple of `_SCRUB_BUDGET_BYTES`. A locator whose candidates do not fit
# what is left of the budget is abandoned part-built, and that part counts
# here. Past it, nothing more is built and the rest is `REDACTED`.
_SCRUB_BUILD_FACTOR = 2


def scrub_labels(texts: Sequence[str], detectors: Sequence[Any]) -> list[str]:
    """`[scrub_label(t, detectors) for t in texts]`, probing every text's
    candidates in one call per detector per batch, within the scrub budget."""
    cheap = _cheap(detectors)
    if not cheap:
        return list(texts)
    out = list(texts)
    batch: list[str] = []
    owner: list[int] = []
    end: dict[int, int] = {}
    used = 0
    for i, text in enumerate(texts):
        if not text:
            continue
        cands = _candidates(text)
        size = sum(_utf8_len(c) for c in cands)
        if used + size > _SCRUB_BUDGET_BYTES:
            out[i] = REDACTED
            continue
        used += size
        batch.extend(cands)
        owner.extend([i] * len(cands))
        end[i] = len(batch)
    hits, probed = _probe(batch, cheap)
    for k in hits:
        out[owner[k]] = REDACTED
    for i, stop in end.items():
        if stop > probed:
            out[i] = REDACTED
    return out


def scrub_plugin_label(text: str, builtins: Sequence[Any], plugins: Sequence[Any]) -> str:
    """`scrub_label` over the built-in cheap tiers plus `plugins` at every tier."""
    probes = [*(d for d in builtins if getattr(d, "tier", 0) < TIER_T2), *plugins]
    return _scrub_segment(text, probes) if probes else text


def _scrub_segment(text: str, cheap: Sequence[Any]) -> str:
    """Replace a locator segment that is itself a match, or that a detector
    fails on, or whose candidates are over `_SCRUB_BUDGET_BYTES`.

    `extract._walk` builds the locator out of dict keys, and a key is
    arbitrary sender data -- `{"<AWS key>": "..."}` put the key verbatim
    into `Finding.locator`, which `FindingRow` copies to the store and
    `to_log` copies to the verdict log. The comment above that log line
    said "Detector names, locators and hashes only -- never the match".
    """
    if not text:
        return text
    cands = _candidates(text)
    if sum(_utf8_len(c) for c in cands) > _SCRUB_BUDGET_BYTES:
        return REDACTED
    for cand in cands:
        for det in cheap:
            try:
                hit = _hit(det, cand)
            except Exception as exc:  # noqa: BLE001 - a failed probe redacts
                _log_probe_failure(det, exc, "detector failed during the label scrub; "
                                             "segment redacted")
                return REDACTED
            if hit:
                return REDACTED
    return text


def _candidates(text: str, *, whole: bool = False) -> list[str]:
    """The strings a label scrub probes for `text`: the text and its parts
    of at least 8 characters, and the text itself at any length if `whole`."""
    # The whole segment AND its parts. A credential embedded in an
    # identifier -- a tool named `send_AKIA...` -- has a word character
    # right before it, so a detector anchored on a word boundary does not
    # match the whole string and the name went through unchanged. Splitting
    # on `_ . : / @` keeps hyphenated tokens (Slack's `xoxb-...`) whole;
    # splitting on every non-alphanumeric catches the rest.
    candidates = [text, *re.split(r"[_.:/@\s]+", text),
                  *re.split(r"[^A-Za-z0-9]+", text)]
    keep = [c for c in candidates if len(c) >= 8]
    return list(dict.fromkeys([text, *keep] if whole and text else keep))


def _hit(det: Any, text: str) -> bool:
    """Whether `det` matches `text`; a plugin counts any finding its own scan returns."""
    if isinstance(det, PluginDetector):
        return det.probe(text)
    return bool(det.scan([ScanUnit(locator="_", tool_name=None, text=text)]))


def screen_phrases(builtins: Sequence[Any], plugins: Sequence[PluginDetector]) -> None:
    """Refuse when a phrase of any of `plugins` is matched by a built-in cheap
    tier or by any of `plugins` at any tier, its owner included.

    The error names the owner, the finding id and the matching detector. A
    plugin that raises refuses by exception type; a built-in's
    `DetectorFailed` propagates.
    """
    probes = [*(d for d in builtins if getattr(d, "tier", 0) < TIER_T2), *plugins]
    for owner in plugins:
        for fid, phrase in owner.phrases().items():
            for cand in _candidates(phrase, whole=True):
                for det in probes:
                    failed = None
                    try:
                        hit = _hit(det, cand)
                    except DetectorFailed as exc:
                        if not isinstance(det, PluginDetector):
                            raise
                        failed = str(exc)
                    if failed is not None:
                        raise RuntimeError(
                            f"detectors.{owner.name}: screening the phrase for {fid} "
                            f"raised in detectors.{failed}") from None
                    if hit:
                        raise RuntimeError(
                            f"detectors.{owner.name}: the phrase for {fid} is matched "
                            f"by detector {det.name}")


def _cheap(detectors: Sequence[Any]) -> list[Any]:
    """The detectors a locator scrub probes with: every tier below T2."""
    return [d for d in detectors if getattr(d, "tier", 0) < TIER_T2]


# A sender key can itself contain dots (a JWT is three dot-joined parts),
# and splitting on "." first hid it from every detector. Every run of
# consecutive segments is probed as one string -- a detector need not match
# a superstring of what it matches, so no cheaper whole-locator test can
# rule a span out -- and the smallest matching run is redacted, skipping
# any segment that matches alone. The candidates of every locator in a
# call go to each detector together, in batches of at most
# `_batch_limit` bytes. Above MAX_LOCATOR_SEGMENTS or MAX_LOCATOR_CHARS, or
# past the scrub budget, the whole locator is redacted.


def _run_candidates(run: str) -> list[str]:
    """`_candidates` for a dotted run: split on every separator but ".", so
    a prefix such as `send_` cannot hide a dotted secret's word boundary."""
    cands = [run, *re.split(r"[_:/@\s]+", run), *re.split(r"[^A-Za-z0-9.]+", run)]
    return list(dict.fromkeys(c for c in cands if len(c) >= 8))


def _utf8_len(text: str) -> int:
    """`text`'s length in UTF-8 as gitleaks' `_join` counts it."""
    return len(text.encode("utf-8", "replace"))


def _batch_limit(cheap: Sequence[Any]) -> int:
    """The most UTF-8 bytes of candidate text one batch hands a detector:
    `_SCRUB_BUDGET_BYTES`, and an eighth under the smallest `max_bytes`
    of `cheap`."""
    caps = [d.max_bytes for d in cheap if isinstance(getattr(d, "max_bytes", None), int)]
    return max(1, min([_SCRUB_BUDGET_BYTES, *(c - c // 8 for c in caps)]))


def _log_probe_failure(det: Any, exc: Exception,
                       msg: str = "detector failed during the locator scrub; "
                                  "its candidates count as matches") -> None:
    reason = str(exc) if isinstance(exc, DetectorFailed) else type(exc).__name__
    log.error(msg, extra={"fields": {"detector": getattr(det, "name", "?"), "reason": reason}})


def _detector_hits(det: Any, texts: Sequence[str]) -> set[int]:
    """Indexes of `texts` `det` matches, from one call. If it raises, every
    index."""
    try:
        if isinstance(det, PluginDetector):
            return set(det.probe_all(texts))
        units = [ScanUnit(locator=str(i), tool_name=None, text=t) for i, t in enumerate(texts)]
        return {int(f.locator) for f in det.scan(units) if f.locator.isdigit()}
    except Exception as exc:  # noqa: BLE001 - a failed probe redacts
        _log_probe_failure(det, exc)
        return set(range(len(texts)))


def _batch_hits(texts: Sequence[str], cheap: Sequence[Any]) -> set[int]:
    """Indexes of `texts` any of `cheap` matches or fails on, one call per
    detector."""
    hits: set[int] = set()
    if texts:
        for det in cheap:
            hits |= _detector_hits(det, texts)
    return hits


def _probe(texts: Sequence[str], cheap: Sequence[Any],
           deadline: float | None = None) -> tuple[set[int], int]:
    """`_batch_hits` over `texts` in batches of at most `_batch_limit`
    bytes, and how many leading texts every detector probed before
    `deadline`, by default `_SCRUB_BUDGET_S` from now."""
    if deadline is None:
        deadline = time.monotonic() + _SCRUB_BUDGET_S
    limit = _batch_limit(cheap)
    bounds: list[tuple[int, int]] = []
    start = size = 0
    for k, t in enumerate(texts):
        n = _utf8_len(t)
        if k > start and size + n > limit:
            bounds.append((start, k))
            start, size = k, 0
        size += n
    if texts:
        bounds.append((start, len(texts)))
    hits: set[int] = set()
    for a, b in bounds:
        batch = texts[a:b]
        for det in cheap:
            if time.monotonic() >= deadline:
                return hits, a
            hits |= {a + h for h in _detector_hits(det, batch)}
    return hits, len(texts)


def _dotted_probes(parts: Sequence[str], room: int, deadline: float
                   ) -> tuple[tuple[list[str], list[tuple[int, int]],
                                    list[tuple[int, int]]] | None, int]:
    """The candidates `_scrub_locator` probes for `parts`, the (i, j) span each
    belongs to (j == i + 1 is a segment), and every run of two or more
    segments, shortest first; and the UTF-8 bytes of candidate text built.

    Building stops, and the first item is None, once the candidates pass
    `room` bytes or `deadline` passes."""
    texts: list[str] = []
    owner: list[tuple[int, int]] = []
    size = 0

    def take(cands: list[str], span: tuple[int, int]) -> bool:
        nonlocal size
        for c in cands:
            size += _utf8_len(c)
            texts.append(c)
            owner.append(span)
        return size <= room and time.monotonic() < deadline

    for i, p in enumerate(parts):
        if not take(_candidates(p), (i, i + 1)):
            return None, size
    windows = [(i, i + n) for n in range(2, len(parts) + 1) for i in range(len(parts) - n + 1)]
    for i, j in windows:
        run = ".".join(parts[i:j])
        if len(run) >= 8 and not take(_run_candidates(run), (i, j)):
            return None, size
    return (texts, owner, windows), size


def _dotted_resolve(parts: Sequence[str], windows: Sequence[tuple[int, int]],
                    matched: set[tuple[int, int]]) -> str:
    """`parts` rejoined with each matched segment, and the smallest matched
    run containing no matched segment, replaced by `REDACTED`."""
    single = [(i, i + 1) in matched for i in range(len(parts))]
    runs: dict[int, int] = {}
    covered = [False] * len(parts)
    for i, j in windows:                      # shortest first
        if (i, j) in matched and not any(covered[i:j]) and not any(single[i:j]):
            runs[i] = j
            covered[i:j] = [True] * (j - i)
    out: list[str] = []
    i = 0
    while i < len(parts):
        if i in runs:
            out.append(REDACTED)
            i = runs[i]
        else:
            p = parts[i]
            out.append(REDACTED if single[i] else p)
            i += 1
    return ".".join(out)


_TAIL_WORDS = ("#key", "#tail", "#b64", "#log")


def _structural_tail(locator: str) -> int:
    """Where the end of `locator` made of list indexes of at most seven
    digits, `#key`, `#tail`, `#b64`, `#log` and `#seam<n>` with any primes
    starts; `len(locator)` when it has none. That end holds no sender text."""
    i = len(locator)
    while i:
        word = next((w for w in _TAIL_WORDS if locator.endswith(w, 0, i)), None)
        if word is not None:
            i -= len(word)
            continue
        j = i
        while j and locator[j - 1] == "'":
            j -= 1
        k = j
        while k and locator[k - 1].isdigit() and locator[k - 1].isascii():
            k -= 1
        digits = j - k
        if 0 < digits <= 7 and locator.endswith("#seam", 0, k):
            i = k - len("#seam")
            continue
        if j == i and locator.endswith("]", 0, i):
            k = i - 1
            while k and locator[k - 1].isdigit() and locator[k - 1].isascii():
                k -= 1
            if 0 < i - 1 - k <= 7 and k and locator[k - 1] == "[":
                i = k - 1
                continue
        break
    return i


def _scrub_names(locators: Iterable[str], tools: Iterable[str],
                 cheap: Sequence[Any]) -> tuple[dict[str, str], dict[str, str]]:
    """`_scrub_locator` of each distinct locator and `_scrub_segment` of each
    distinct tool name, as {original: scrubbed} maps, probing every
    candidate of all of them through one `_probe`. A locator or tool name
    past the scrub budget is `REDACTED`. A locator's `_structural_tail` is
    kept as it is and the rest scrubbed."""
    split: dict[str, tuple[str, str]] = {}
    for loc in dict.fromkeys(locators):
        cut = _structural_tail(loc) if len(loc) <= MAX_LOCATOR_CHARS else 0
        split[loc] = (loc[:cut], loc[cut:]) if cut else (loc, "")
    stems, tool_out = _scrub_stems((stem for stem, _ in split.values()), tools, cheap)
    loc_out = {loc: stems[stem] if stems[stem] == REDACTED else stems[stem] + tail
               for loc, (stem, tail) in split.items()}
    return loc_out, tool_out


def _scrub_stems(locators: Iterable[str], tools: Iterable[str],
                 cheap: Sequence[Any]) -> tuple[dict[str, str], dict[str, str]]:
    """`_scrub_names` without the structural tails."""
    deadline = time.monotonic() + _SCRUB_BUDGET_S
    budget = _SCRUB_BUDGET_BYTES
    build_left = _SCRUB_BUILD_FACTOR * budget
    texts: list[str] = []
    owner: list[tuple[str | None, Any]] = []   # (locator, span) or (None, tool)
    plans: dict[str, tuple[list[str], list[tuple[int, int]], set[tuple[int, int]]]] = {}
    end: dict[tuple[str | None, str], int] = {}
    loc_out: dict[str, str] = {}
    used = 0
    for loc in dict.fromkeys(locators):
        if (len(loc) > MAX_LOCATOR_CHARS or loc.count(".") >= MAX_LOCATOR_SEGMENTS
                or build_left <= 0 or time.monotonic() >= deadline):
            loc_out[loc] = REDACTED
            continue
        parts = loc.split(".")
        built, size = _dotted_probes(parts, budget - used, deadline)
        build_left -= size
        if built is None:
            loc_out[loc] = REDACTED
            continue
        cands, spans, windows = built
        used += size
        plans[loc] = (parts, windows, set())
        texts.extend(cands)
        owner.extend((loc, span) for span in spans)
        end[(loc, "")] = len(texts)
    tool_out: dict[str, str] = {}
    for tool in dict.fromkeys(tools):
        if len(tool) < 8:
            # No part of it is long enough to be a candidate.
            tool_out[tool] = tool
            continue
        if (len(tool) > budget - used or build_left <= 0
                or time.monotonic() >= deadline):
            tool_out[tool] = REDACTED
            continue
        cands = _candidates(tool)
        size = sum(_utf8_len(c) for c in cands)
        build_left -= size
        if used + size > budget:
            tool_out[tool] = REDACTED
            continue
        used += size
        tool_out[tool] = tool
        texts.extend(cands)
        owner.extend((None, tool) for _ in cands)
        end[(None, tool)] = len(texts)
    hits, probed = _probe(texts, cheap, deadline)
    for k in hits:
        loc, what = owner[k]
        if loc is None:
            tool_out[what] = REDACTED
        else:
            plans[loc][2].add(what)
    for loc, (parts, windows, matched) in plans.items():
        loc_out[loc] = _dotted_resolve(parts, windows, matched)
    for (loc, tool), stop in end.items():
        if stop > probed:
            if loc is None:
                tool_out[tool] = REDACTED
            else:
                loc_out[loc] = REDACTED
    return loc_out, tool_out


def _scrub_locator(locator: str, cheap: Sequence[Any]) -> str:
    """Redact each segment of `locator` that matches alone, and the smallest
    run of two or more consecutive segments that matches only as one
    string."""
    return _scrub_names([locator], [], cheap)[0][locator]


def _scrub(findings: Sequence[Finding], detectors: Sequence[Any]) -> list[Finding]:
    """Keep matched values out of a finding's own metadata.

    Only the cheap tiers run here. T2 is a model over prose and a locator
    segment is not prose, so it would cost the verdict path its budget to
    answer a question it is not built for.
    """
    cheap = _cheap(detectors)
    if not cheap:
        return list(findings)
    locs, tools = _scrub_names((f.locator or "" for f in findings),
                               (f.tool_name or "" for f in findings), cheap)
    out = []
    for f in findings:
        loc = locs[f.locator or ""]
        tool = tools[f.tool_name or ""] or f.tool_name
        if loc != f.locator or tool != f.tool_name:
            f = replace(f, locator=loc, tool_name=tool)
        out.append(f)
    return out


def _placed(findings: Iterable[Finding], folded: set[str]) -> list[Finding]:
    """Drop spans we cannot translate back to the sender's own text.

    Not a loss of protection: `sink/redact.py` reads a missing span as "we
    know this value contains a match and cannot say where" and replaces
    the whole value. That is strictly safer than a range computed in the
    wrong coordinate system, and it only happens on text that carried an
    invisible character or a homoglyph in the first place.
    """
    if not folded:
        return list(findings)
    return [
        replace(f, start=None, end=None)
        if f.locator in folded and (f.start is not None or f.end is not None)
        else f
        for f in findings
    ]


# base64 runs worth decoding. Shorter than this and the decode is noise:
# a 20-character AWS key encodes to 28, and anything under ~24 is as
# likely to be an identifier as a payload.
B64_MIN = 24
B64_MAX = 8192
# Both alphabets: the standard one and the URL-safe one, which has `-` and
# `_` where the standard one has `+` and `/`.
_B64_RUN = re.compile(rf"[A-Za-z0-9+/_-]{{{B64_MIN},{B64_MAX}}}={{0,2}}")
_URLSAFE = str.maketrans("-_", "+/")


_B64_LINE = re.compile(r"[A-Za-z0-9+/_-]+")
_B64_LAST_LINE = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_LINE_BREAK = re.compile(r"\r?\n")


# The shortest run of text kept from a decode that is not all text.
B64_TEXT_RUN_MIN = 8
# The same, read from a run at any alignment but its first: the length of
# the shortest value a blocking detector matches, a separated SSN.
B64_SHIFTED_RUN_MIN = 11


_TAB_CR_LF = str.maketrans("", "", "\t\r\n")
# At least B64_TEXT_RUN_MIN characters none of which is a C0 or C1 control
# other than tab, LF and CR, or U+FFFD. Every character this excludes ends a
# run in `_text_runs`.
_TEXT_CANDIDATE = re.compile(
    rf"[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ufffd]{{{B64_TEXT_RUN_MIN},}}")


def _decodable_text(text: str) -> bool:
    """Every character is printable or one of tab, CR and LF."""
    return text.translate(_TAB_CR_LF).isprintable()


def _text_runs(text: str, least: int = B64_TEXT_RUN_MIN) -> str:
    """`text` when it is all decodable text. Otherwise its runs of at least
    `least` printable characters, tab, CR and LF, one per line, as
    `strings` prints them. U+FFFD, which an undecodable byte becomes, ends
    a run. `least` is at least B64_TEXT_RUN_MIN."""
    if "\ufffd" not in text and _decodable_text(text):
        return text
    runs = []
    for m in _TEXT_CANDIDATE.finditer(text):
        piece = m.group(0)
        if len(piece) < least:
            continue
        if _decodable_text(piece):
            runs.append(piece)
            continue
        start = 0
        for i, c in enumerate(piece):
            if not (c.isprintable() or c in "\t\r\n"):
                if i - start >= least:
                    runs.append(piece[start:i])
                start = i + 1
        if len(piece) - start >= least:
            runs.append(piece[start:])
    return "\n".join(runs)


def _b64_bytes(blob: str) -> bytes | None:
    """What `blob`, base64 characters of either alphabet or a mix of the
    two with or without padding, decodes to, or None when it does not
    decode."""
    return _standard_bytes(blob.rstrip("=").translate(_URLSAFE))


def _standard_bytes(s: str) -> bytes | None:
    """What `s`, standard-alphabet base64 characters without padding,
    decodes to. A last character that cannot complete a byte, which is what
    a length of 1 modulo 4 leaves, is dropped."""
    s = s[:len(s) - 1] if len(s) % 4 == 1 else s
    try:
        return binascii.a2b_base64(s + "=" * (-len(s) % 4))
    except binascii.Error:
        return None


def _run_text(blob: str) -> str:
    """The text the base64 run `blob` decodes to, as `_text_runs` reads it.

    When the run does not decode whole to text, the text runs read from it
    at each of its four alignments, one after another, so characters before
    the encoding that shift it out of alignment do not hide what it holds.
    Runs read at the last three alignments are at least B64_SHIFTED_RUN_MIN
    characters long.
    """
    texts: list[str] = []
    s = blob.rstrip("=").translate(_URLSAFE)
    for k in range(4):
        raw = _standard_bytes(s[k:])
        if raw is None:
            continue
        decoded = raw.decode("utf-8", errors="replace")
        if k == 0 and "\ufffd" not in decoded and _decodable_text(decoded):
            return decoded
        text = _text_runs(decoded, B64_SHIFTED_RUN_MIN if k else B64_TEXT_RUN_MIN)
        if text:
            texts.append(text)
    return "\n".join(texts)


def _wrapped_runs(text: str) -> list[tuple[int, int, list[str]]]:
    """(start, end, lines) for each run of two or more whole lines that read
    as wrapped base64: every line but the last `w` characters of the
    base64 alphabet, `w` a multiple of 4 between B64_MIN and B64_MAX, and
    the last at most `w` long with optional padding. Lines are separated
    by LF or CRLF."""
    bounds: list[tuple[int, int]] = []
    pos = 0
    for m in _LINE_BREAK.finditer(text):
        bounds.append((pos, m.start()))
        pos = m.end()
    bounds.append((pos, len(text)))
    runs: list[tuple[int, int, list[str]]] = []
    i = 0
    while i < len(bounds):
        s, e = bounds[i]
        width = e - s
        if not (B64_MIN <= width <= B64_MAX and width % 4 == 0
                and _B64_LINE.fullmatch(text, s, e)):
            i += 1
            continue
        j = i + 1
        while j < len(bounds) and bounds[j][1] - bounds[j][0] == width \
                and _B64_LINE.fullmatch(text, *bounds[j]):
            j += 1
        if j < len(bounds) and 0 < bounds[j][1] - bounds[j][0] <= width \
                and _B64_LAST_LINE.fullmatch(text, *bounds[j]):
            j += 1
        if j - i >= 2:
            runs.append((bounds[i][0], bounds[j - 1][1],
                         [text[a:b] for a, b in bounds[i:j]]))
            i = j
        else:
            i += 1
    return runs


def _decode_wrapped(lines: list[str]) -> list[str]:
    """The text `lines` decode to, joined, in pieces of at most B64_MAX
    base64 characters cut on line boundaries. The last line is dropped
    when the run does not decode with it. Empty when it does not decode."""
    width = len(lines[0])
    per_piece = max(1, B64_MAX // width)
    for candidate in (lines, lines[:-1]):
        if len(candidate) < 2:
            continue
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        out: list[str] = []
        try:
            for k in range(0, len(candidate), per_piece):
                raw = _b64_bytes("".join(candidate[k:k + per_piece]))
                if raw is None:
                    raise ValueError
                last = k + per_piece >= len(candidate)
                out.append(decoder.decode(raw, final=last))
        except ValueError:
            continue
        return [t for t in map(_text_runs, out) if t]
    return []


def _decoded(units: list[ScanUnit], room: int) -> tuple[list[ScanUnit], bool]:
    """Scan what a base64 run decodes to: at most `room` decoded units, and
    whether there were more.

    Nothing decoded base64 before scanning -- `t0_regex` unpacks a JWT
    header and nothing else -- so a wrapped credential was invisible to
    T0, the checksum tier and gitleaks at once. `EntropyDetector` fires
    only behind a credential-shaped key name and ships at `warn`, so even
    the one tier that might notice could not deny.

    A run is read in the standard and the URL-safe alphabet, padded or
    not. A run that decodes to text, printable characters and tab, CR and
    LF, is kept whole. Otherwise bytes that are not valid UTF-8 are
    replaced and only the runs of text in it are kept, as `_run_text`
    reads them, in one unit per base64 run.
    Base64 wrapped over several lines is joined and decoded as one run;
    when the joined run does not decode, each line is tried alone.

    Units are read last first, as extraction reads them, and each unit's
    runs in order. Decoding stops at the first decoded unit past `room`. Every
    unit decoded from one source shares one locator string.
    """
    per_unit: list[list[ScanUnit]] = []
    left = room + 1
    for unit in reversed(units):
        if left <= 0:
            break
        if len(unit.text) < B64_MIN:
            continue
        texts: list[str] = []
        wrapped: list[tuple[int, int, list[str]]] = []
        for run in _wrapped_runs(unit.text):
            if len(texts) >= left:
                break
            joined = _decode_wrapped(run[2])
            if joined:
                texts.extend(joined)
                wrapped.append(run)
        w = 0
        for m in _B64_RUN.finditer(unit.text):
            if len(texts) >= left:
                break
            while w < len(wrapped) and wrapped[w][1] <= m.start():
                w += 1
            if w < len(wrapped) and wrapped[w][0] <= m.start():
                continue
            blob = m.group(0)
            text = _run_text(blob)
            if not text or text == blob:
                continue
            texts.append(text)
        del texts[left:]
        if texts:
            locator = f"{unit.locator}{_DECODED_SUFFIX}"
            per_unit.append([ScanUnit(locator=locator, tool_name=unit.tool_name,
                                      text=text, folded=True, structural=unit.structural)
                             for text in texts])
            left -= len(texts)
    over = left == 0
    if over:
        # The one decoded unit past `room`, the last one read.
        per_unit[-1].pop()
    return [u for decoded in reversed(per_unit) for u in decoded], over


_KEY_SUFFIX = "#key"
_DECODED_SUFFIX = "#b64"
_SEAM_SUFFIX = "#seam"

# How much of each side of a join a seam window reaches. A credential is
# at most a couple of hundred characters.
SEAM_CHARS = 256

# One seam window's parts: (unit locator, start, end) in the window's text,
# in order.
SeamParts = tuple[tuple[str, int, int], ...]


def _seams(units: list[ScanUnit], taken: Iterable[str] = ()
           ) -> list[tuple[ScanUnit, SeamParts]]:
    """Each seam unit of `units` with its parts; see `_each_seam`."""
    out: list[tuple[ScanUnit, SeamParts]] = []
    _each_seam(units, taken, lambda seam, parts: out.append((seam, parts)))
    return out


def _seam_units(units: list[ScanUnit], taken: Iterable[str] = ()) -> list[ScanUnit]:
    """The seam units of `units`, without their parts."""
    out: list[ScanUnit] = []
    _each_seam(units, taken, lambda seam, _parts: out.append(seam))
    return out


class _SeamPartsOf:
    """Parts of the seams of `units`, looked up by seam locator.

    A seam's parts are rebuilt only when a finding names it: holding them
    for every seam of a wide list of short values raised the scan's peak
    memory by about a third."""

    def __init__(self, units: list[ScanUnit], taken: list[str]):
        self._units = units
        self._taken = taken
        self._known: dict[str, SeamParts | None] = {}

    def prime(self, locators: Iterable[str]) -> None:
        """Rebuild, in one pass, the parts of each of `locators` not looked
        up before."""
        new = {loc for loc in locators if _SEAM_SUFFIX in loc and loc not in self._known}
        if not new:
            return
        for loc in new:
            self._known[loc] = None

        def keep(seam: ScanUnit, parts: SeamParts) -> None:
            if seam.locator in new:
                self._known[seam.locator] = parts

        _each_seam(self._units, self._taken, keep)

    def get(self, locator: str) -> SeamParts | None:
        self.prime((locator,))
        return self._known.get(locator)


def _each_seam(units: list[ScanUnit], taken: Iterable[str],
               emit: Callable[[ScanUnit, SeamParts], None]) -> None:
    """Re-scan the text around the joins between adjacent units.

    Every unit was scanned alone, so a secret cut across two or more of
    them matched nothing:

        whole key, one text block            findings=1 deny
        split across two text blocks         findings=0 allow
        split across two tool_input fields   findings=0 allow

    Units with no text are passed over, and a tail unit is not joined to
    the head before it. Two kinds of window:

    - Each adjacent pair: the last SEAM_CHARS characters of the first and
      the first SEAM_CHARS of the second.
    - Each run of joined text cut into windows of 4 * SEAM_CHARS characters
      starting every 3 * SEAM_CHARS, where a window holds part of three or
      more units. A unit over 2 * SEAM_CHARS joins only its first SEAM_CHARS
      characters to what comes before it and its last SEAM_CHARS to what
      comes after. A match of up to SEAM_CHARS across three or more units
      is wholly inside one of these.

    A seam unit is marked folded and carries the first part's locator with
    `_SEAM_SUFFIX` and the window's number, followed by `'` until it is no
    locator of `units`, of `taken` or of another seam. `_on_seams` finds a seam by that locator
    and turns a finding on it into one on the units its match lies in.
    """
    seen = [0]
    run: list[tuple[ScanUnit, str]] = []
    # A seam's locator can equal another locator only if that one holds
    # `_SEAM_SUFFIX`, so only those are kept to check against. With none,
    # every seam's locator is already unique.
    real = {loc for loc in itertools.chain((u.locator for u in units), taken)
            if _SEAM_SUFFIX in loc}

    def close() -> None:
        if len(run) > 2:
            _seam_windows(run, emit, seen, real)
        run.clear()

    prev: ScanUnit | None = None
    for unit in units:
        if not unit.text:
            continue
        if unit.tail and unit.truncated:
            close()
            prev = None
        if prev is not None:
            _add_seam(emit, seen, [(prev, prev.text[-SEAM_CHARS:]),
                                   (unit, unit.text[:SEAM_CHARS])], real)
        if len(unit.text) > 2 * SEAM_CHARS:
            run.append((unit, unit.text[:SEAM_CHARS]))
            close()
            run.append((unit, unit.text[-SEAM_CHARS:]))
        else:
            run.append((unit, unit.text))
        prev = unit
    close()


def _add_seam(emit: Callable[[ScanUnit, SeamParts], None], seen: list[int],
              pieces: list[tuple[ScanUnit, str]], real: set[str]) -> None:
    """Emit the seam unit joining `pieces`, numbered by `seen[0]`, the count
    of seams emitted before it.
    When `real` holds any locator, the seam's is made none of them and is
    added to it."""
    parts = []
    texts = []
    pos = 0
    structural = False
    for unit, piece in pieces:
        parts.append((unit.locator, pos, pos + len(piece)))
        texts.append(piece)
        pos += len(piece)
        structural = structural or unit.structural
    text = "".join(texts)
    first = pieces[0][0]
    locator = f"{first.locator}{_SEAM_SUFFIX}{seen[0]}"
    seen[0] += 1
    if real:
        while locator in real:
            locator += "'"
        real.add(locator)
    seam = ScanUnit(locator=locator,
                    tool_name=first.tool_name, text=text, folded=True,
                    structural=structural)
    if seam.text != text:
        # Folding moved characters, so no offset maps to a part.
        parts = [(loc, 0, 0) for loc, _, _ in parts]
    emit(seam, tuple(parts))


def _seam_windows(run: list[tuple[ScanUnit, str]],
                  emit: Callable[[ScanUnit, SeamParts], None], seen: list[int],
                  real: set[str]) -> None:
    """Emit the windows of one run of joined pieces that hold part of
    three or more of them."""
    total = sum(len(piece) for _, piece in run)
    starts: list[int] = []
    pos = 0
    for _, piece in run:
        starts.append(pos)
        pos += len(piece)
    lo = 0
    while True:
        hi = min(lo + 4 * SEAM_CHARS, total)
        first = bisect.bisect_right(starts, lo) - 1
        last = bisect.bisect_left(starts, hi) - 1
        if last - first >= 2:
            _add_seam(emit, seen, [
                (run[k][0], run[k][1][max(lo - starts[k], 0):hi - starts[k]])
                for k in range(first, last + 1)], real)
        if hi == total:
            return
        lo += 3 * SEAM_CHARS


def _on_seams(found: Iterable[Finding],
              seams: dict[str, SeamParts] | _SeamPartsOf) -> list[Finding]:
    """`found`, each finding on a seam moved to the units its match lies in.

    The finding takes the locator of the first such unit and lists the rest
    in `seam_others`, without a span. With no span, or a span no part
    overlaps, it lies in every unit of its window. A finding not on a seam
    keeps no `seam_others`."""
    found = list(found)
    if isinstance(seams, _SeamPartsOf):
        seams.prime(f.locator for f in found)
    out: list[Finding] = []
    for f in found:
        parts = seams.get(f.locator)
        if parts is None:
            out.append(replace(f, seam_others=()) if f.seam_others else f)
            continue
        hit = parts
        if f.start is not None and f.end is not None and f.start < f.end:
            ends = [end for _, _, end in parts]
            k = bisect.bisect_right(ends, f.start)
            overlap = []
            while k < len(parts) and parts[k][1] < f.end:
                if parts[k][2] > parts[k][1]:
                    overlap.append(parts[k])
                k += 1
            hit = tuple(overlap) or parts
        locators = list(dict.fromkeys(loc for loc, _, _ in hit))
        out.append(replace(f, locator=locators[0], start=None, end=None,
                           seam_others=tuple(locators[1:])))
    return out


def _blocking_tiers(policy: Policy, dropped: Sequence[str]) -> set[str]:
    """Which of the skipped detectors could have denied."""
    configs = policy.detector_configs()
    return {
        name for name in dropped
        if getattr(configs.get(name), "severity", "") == SEVERITY_BLOCK
    }


def gitleaks_left_out(policy: Policy, detectors: Sequence[Any]) -> bool:
    """Whether `policy` enables gitleaks and none of `detectors` is it: an
    `auto` T1 whose binary `build_detectors` could not find."""
    cfg = policy.detector_configs().get("gitleaks")
    if cfg is None or cfg.enabled is False:
        return False
    return not any(getattr(d, "name", None) == "gitleaks" for d in detectors)


def left_out_tiers(policy: Policy, detectors: Sequence[Any], where: str) -> list[str]:
    """`["gitleaks"]`, logged as a warning naming `where`, when
    `gitleaks_left_out(policy, detectors)`; otherwise empty. An adapter adds
    it to every scan's `detectors_skipped` with `with_left_out`."""
    if not gitleaks_left_out(policy, detectors):
        return []
    log.warning("gitleaks (T1) is enabled but was not built: its binary was not "
                "found. Every verdict reports it in tiers_dropped",
                extra={"fields": {"detector": "gitleaks", "adapter": where}})
    return ["gitleaks"]


def with_left_out(skipped: Sequence[str], left_out: Sequence[str]) -> list[str]:
    """`skipped` followed by each of `left_out` it does not already name."""
    return [*skipped, *(t for t in left_out if t not in skipped)]


def t1_dropped(dropped: Sequence[str]) -> bool:
    """Whether `dropped`, a scan's `detectors_skipped` or a wire verdict's
    `tiers_dropped`, says gitleaks (T1) did not run or did not finish."""
    return "gitleaks" in dropped


def t1_unchecked(policy: Policy, findings: Sequence[Finding]) -> Verdict:
    """The deny under `hook.on_error: block` for content gitleaks (T1) did
    not check."""
    return Verdict(
        action=ACTION_DENY,
        deny_reason=("forgd-verdict: this could not be checked: gitleaks "
                     "did not run." + (f" {policy.contact_line}"
                                       if policy.contact_line else "")),
        reference_id=make_reference_id("gitleaks"),
        findings=list(findings))


def _cache_put(cache, key, state) -> None:
    try:
        cache.put(key, state)
    except Exception as exc:  # noqa: BLE001 - any backend, any failure
        log.warning("cache write failed; the verdict stands",
                    extra={"fields": {"error": type(exc).__name__}})


def _matched_key_paths(findings: Sequence[Finding],
                       units: Sequence[ScanUnit]) -> dict[str, str]:
    """`{path: redacted path}` for each `<path>#key` unit a finding landed on.

    A key unit is recognised by its text: its locator is `<prefix>.<text>#key`,
    so the key is cut off by length rather than by splitting on dots. A
    finding on the unit's decoded form counts as landing on it, and so does
    a finding whose `seam_others` names it.
    """
    keys: dict[str, str] = {}
    for u in units:
        path = u.locator.removesuffix(_KEY_SUFFIX)
        if path != u.locator and u.text and path.endswith("." + u.text):
            keys[u.locator] = path[:-len(u.text)] + REDACTED
    hit: dict[str, str] = {}
    for f in findings:
        for loc in ((f.locator or "").removesuffix(_DECODED_SUFFIX), *f.seam_others):
            if loc in keys:
                hit[loc.removesuffix(_KEY_SUFFIX)] = keys[loc]
    return hit


def _key_path_rewriter(paths: dict[str, str]) -> Callable[[str], str]:
    """A function that returns a locator with each matched key path
    replaced, innermost first.

    Paths are applied in order of length, longest first, and among equal
    lengths in the order of `paths`. Each is tested once, against the
    locator as rewritten by the paths before it. A path applies when the
    locator starts with it and the next character is `.`, `[` or `#`, or
    there is none. A prefix is built and looked up only at a length some
    path has, so one locator costs one lookup per distinct path length,
    however many boundaries it has.
    A locator over MAX_LOCATOR_CHARS is returned as REDACTED unexamined.
    """
    order = {path: i for i, path in enumerate(paths)}
    lengths = sorted({len(path) for path in paths}, reverse=True)

    def rewrite(locator: str) -> str:
        if len(locator) > MAX_LOCATOR_CHARS:
            return REDACTED
        for i in lengths:
            # One path applied at this length can leave a prefix that is
            # another path of the same length, later in `order`.
            last = -1
            while i <= len(locator) and (i == len(locator) or locator[i] in ".[#"):
                prefix = locator[:i]
                k = order.get(prefix)
                if k is None or k <= last:
                    break
                locator = paths[prefix] + locator[i:]
                last = k
        return locator

    return rewrite


def _scrub_keys(findings: Sequence[Finding], paths: dict[str, str]) -> list[Finding]:
    """Replace each of `paths` in every locator that contains it, and in
    `seam_others`."""
    if not paths:
        return list(findings)
    rewrite = _key_path_rewriter(paths)
    out = []
    for f in findings:
        loc = rewrite(f.locator or "")
        others = tuple(rewrite(o) for o in f.seam_others)
        out.append(replace(f, locator=loc, seam_others=others)
                   if loc != f.locator or others != f.seam_others else f)
    return out


def _taint_key(f: Finding) -> tuple[str, bool, str] | None:
    """What taint joins `f` on: its block, whether it is in a call's input,
    and its digest. None for a detector taint does not take sources from."""
    m = BLOCK_LOCATOR.match(f.locator or "")
    if m is None or f.detector.startswith(NOT_TAINT_SOURCES):
        return None
    return m.group(0), f.locator[m.end():].startswith(".input"), f.excerpt_hash


def _keep(findings: list[Finding], limit: int) -> list[Finding]:
    """`limit` of `findings`, in their original order, taken by rank: the
    first finding of each detector, then block severity, then the first per
    taint key, then the first per detector and locator, then the rest."""
    detectors: set[str] = set()
    taint: set[tuple[str, bool, str]] = set()
    placed: set[tuple[str, str]] = set()
    ranks: list[int] = []
    for f in findings:
        key = _taint_key(f)
        if f.detector not in detectors:
            rank = 0
        elif f.severity == SEVERITY_BLOCK:
            rank = 1
        elif key is not None and key not in taint:
            rank = 2
        elif (f.detector, f.locator) not in placed:
            rank = 3
        else:
            rank = 4
        detectors.add(f.detector)
        if key is not None:
            taint.add(key)
        placed.add((f.detector, f.locator))
        ranks.append(rank)
    kept = sorted(sorted(range(len(findings)), key=ranks.__getitem__)[:limit])
    return [findings[i] for i in kept]


def scan(
    units: Iterable[ScanUnit],
    detectors: Sequence[Any],
    budget: Budget | None = None,
) -> ScanResult:
    """Run detectors over units in tier order, dropping T2 if budget is gone.

    At most the last MAX_SCAN_UNITS units are scanned. Over that, or when
    `units` is an `extract.Units` whose extraction stopped at the cap,
    UNSCANNED_CAPPED is recorded, as it is when a T1 detector raises
    `ScanTruncated`. At most MAX_SCAN_FINDINGS findings are kept, chosen by
    `_keep`, once every detector has run; over that, FINDINGS_CAPPED is
    recorded.
    """
    capped = getattr(units, "capped", False)
    units = list(units)
    result = ScanResult()
    if capped or len(units) > MAX_SCAN_UNITS:
        log.warning("too many units to scan; the earliest were not scanned",
                    extra={"fields": {"units": len(units), "limit": MAX_SCAN_UNITS}})
        units = units[-MAX_SCAN_UNITS:]
        result.detectors_skipped.append(UNSCANNED_CAPPED)
    # Units whose text was folded before the detectors saw it. A span from
    # one of these indexes the folded string, and the sink replaces ranges
    # in the ORIGINAL -- so it would censor the wrong characters and leave
    # part of the secret in place. Collected once rather than per detector.
    decoded, over = _decoded(units, MAX_SCAN_UNITS - len(units))
    taken = [u.locator for u in decoded]
    seams = _seam_units(units, taken)
    seam_parts = _SeamPartsOf(units, taken)
    if over:
        log.warning("too many decoded units to scan; the earliest were not scanned",
                    extra={"fields": {"limit": MAX_SCAN_UNITS}})
        if UNSCANNED_CAPPED not in result.detectors_skipped:
            result.detectors_skipped.append(UNSCANNED_CAPPED)
    units = units + seams + decoded
    folded = {u.locator for u in units if getattr(u, "folded", False)}
    cheap = _cheap(detectors)
    truncated = [u.locator for u in units
                 if getattr(u, "truncated", False) and not getattr(u, "tail", False)]
    if truncated:
        result.detectors_skipped.append(UNSCANNED)
    for detector in detectors:
        if budget is not None and detector.tier >= TIER_T2 and not budget.check():
            result.detectors_skipped.append(detector.name)
            continue
        finished = True
        try:
            found = detector.scan(units)
        except ScanTruncated as exc:
            # Skipped, and the findings of the units it did scan kept. A T1
            # detector that stopped at its size limit also records
            # UNSCANNED_CAPPED.
            result.detectors_skipped.append(detector.name)
            if detector.tier == TIER_T1 and UNSCANNED_CAPPED not in result.detectors_skipped:
                result.detectors_skipped.append(UNSCANNED_CAPPED)
            log.warning("detector stopped early; tier did not finish", extra={"fields": {
                "detector": detector.name, "reason": str(exc)}})
            found, finished = exc.findings, False
        except DetectorFailed as exc:
            # Skipped, not run. The distinction is the whole point: an
            # empty result would be recorded as a successful clean scan.
            result.detectors_skipped.append(detector.name)
            log.warning("detector failed; tier did not run", extra={"fields": {
                "detector": detector.name, "reason": str(exc)}})
            continue
        result.findings.extend(_placed(dedupe_findings(_on_seams(found, seam_parts)),
                                       folded))
        if finished:
            result.detectors_run.append(detector.name)
    if len(result.findings) > MAX_SCAN_FINDINGS:
        log.warning("too many findings to keep; the rest were dropped",
                    extra={"fields": {"findings": len(result.findings),
                                      "limit": MAX_SCAN_FINDINGS}})
        result.findings = _keep(result.findings, MAX_SCAN_FINDINGS)
        result.detectors_skipped.append(FINDINGS_CAPPED)
    if budget is not None:
        budget.check()  # latch `exceeded` even if no T2 detector was configured
        result.budget_exceeded = budget.exceeded
    paths = _matched_key_paths(result.findings, units)
    result.findings = [replace(f, raw_locator=f.locator) for f in result.findings]
    if truncated:
        rewrite = _key_path_rewriter(paths)
        rewritten = [rewrite(loc) for loc in truncated]
        scrubbed, _ = _scrub_names(rewritten, [], cheap)
        result.truncated = [scrubbed[loc] for loc in rewritten]
        log.warning("value over the size limit; its middle was not scanned",
                    extra={"fields": {"locators": result.truncated[:10],
                                      "count": len(result.truncated)}})
    # After dedupe: scrubbing changes the locator, and two findings that
    # differ only in a scrubbed segment are the same finding.
    result.findings = _scrub(dedupe_findings(_scrub_keys(result.findings, paths)),
                             detectors)
    return result


def _any_blocking(policy: Policy) -> bool:
    """Whether any enabled detector in the policy has `block` severity."""
    return any(c.severity == SEVERITY_BLOCK and c.enabled is not False
               for c in policy.detector_configs().values())


# The `dropped` entries for content never read, each with the phrase the
# deny reason uses for it.
_UNREAD_PARTS = {
    UNSCANNED_ARTIFACT: "an artifact could not be fetched to scan",
    UNSCANNED_DELETED: "it was deleted before its messages could be read",
    UNSCANNED_PARTIAL: "only part of its history could be read",
}


def decide(findings: Sequence[Finding], policy: Policy,
           dropped: Sequence[str] = ()) -> Verdict:
    """Any block-severity finding denies. Everything else allows.

    `dropped` is the tiers that did not run. With
    `server.on_tier_dropped: deny` a blocking tier that was skipped denies
    on its own -- otherwise a caller fills the budget with benign volume
    and the tier that would have denied never runs, which no adapter
    acted on. `allow` is the shipped behaviour and is right for the
    shipped policy, where no blocking detector sits in T2.

    UNSCANNED_ARTIFACT in `dropped` is an artifact no detector saw,
    UNSCANNED_DELETED a deleted chat whose messages could not be read, and
    UNSCANNED_PARTIAL a history read only in part. Each counts as every
    tier dropped: under `deny` it denies whenever the policy has a blocking
    detector.

    UNSCANNED and UNSCANNED_CAPPED are text no detector, or no T1
    detector, read: the middle of a value over its adapter's size limit,
    units over MAX_SCAN_UNITS, or units past a T1 detector's `max_bytes`.
    Either denies whenever the policy has a blocking detector, under
    `allow` as well as `deny`. Under `allow` a blocking finding is reported
    as itself rather than as the size limit. FINDINGS_CAPPED decides
    nothing: block findings are kept first, so the findings decide.
    """
    findings = list(findings)
    blocking = [f for f in findings if f.severity == SEVERITY_BLOCK]
    deny_dropped = policy.on_tier_dropped == "deny"
    capped = ((UNSCANNED_CAPPED in dropped or UNSCANNED in dropped)
              and (deny_dropped or not blocking))
    if dropped and (deny_dropped or capped):
        blocking_tiers = _blocking_tiers(policy, dropped) if deny_dropped else set()
        any_blocking = _any_blocking(policy)
        unscanned = capped and any_blocking
        unread = ([m for m in _UNREAD_PARTS if m in dropped]
                  if deny_dropped and any_blocking else [])
        if blocking_tiers or unscanned or unread:
            named = sorted(blocking_tiers)
            parts = [", ".join(named) + " did not run"] if named else []
            if unscanned:
                parts.append("part of it is over the size limit for scanning")
            parts.extend(_UNREAD_PARTS[m] for m in unread)
            # Detector names only. The deny reason is shown to the person
            # who was blocked and must never carry matched content.
            return Verdict(
                action=ACTION_DENY,
                deny_reason=(
                    "This request could not be checked: "
                    + "; ".join(parts)
                    + "."
                    + (f" {policy.contact_line}" if policy.contact_line else "")
                ),
                reference_id=make_reference_id(short_tag(
                    named[0] if named else "oversize" if unscanned else unread[0])),
                findings=findings,
                findings_count=len(findings),
            )
    if not blocking:
        return Verdict(
            action=ACTION_ALLOW, findings=findings, findings_count=len(findings)
        )

    # Collapse to one detector per distinct matched value before wording the
    # reason. T0 and T1 routinely flag the same string, which would otherwise
    # read "an AWS access key ID and an AWS credential". Detectors run in
    # tier order, so the first to report a given excerpt_hash is the most
    # specific one.
    by_excerpt: dict[str, str] = {}
    for f in blocking:
        by_excerpt.setdefault(f.excerpt_hash, f.detector)

    seen: list[str] = []
    for detector in by_excerpt.values():
        if detector not in seen:
            seen.append(detector)

    return Verdict(
        action=ACTION_DENY,
        deny_reason=build_deny_reason(seen, policy.contact_line, policy.plugin_phrases()),
        reference_id=make_reference_id(short_tag(seen[0])),
        findings=findings,
        findings_count=len(findings),
    )


def build_deny_reason(detectors: Sequence[str], contact_line: str = "",
                      plugin_phrases: Mapping[str, str] | None = None) -> str:
    """User-facing deny text. Names the detector class, never the value.

    Anthropic truncates at 500 characters and appends the org's standing
    message (or a built-in default) after a blank line, so this stays
    self-contained and short.
    """
    phrases: list[str] = []
    for detector in detectors:
        phrase = describe(detector, plugin_phrases)
        if phrase not in phrases:
            phrases.append(phrase)
    if not phrases:
        phrases = ["restricted content"]

    if len(phrases) == 1:
        subject = phrases[0]
    elif len(phrases) == 2:
        subject = f"{phrases[0]} and {phrases[1]}"
    else:
        subject = ", ".join(phrases[:-1]) + f", and {phrases[-1]}"

    reason = (
        f"This request appears to contain {subject}, which your organization's "
        f"data policy does not allow to be sent to Claude. Remove it from your "
        f"prompt, the files you attached, and any tool output in this "
        f"conversation, then try again."
    )
    if contact_line:
        reason = f"{reason} {contact_line}"
    if len(reason) > DENY_REASON_MAX:
        reason = reason[: DENY_REASON_MAX - 1].rstrip() + "…"
    return reason


def _prefix_end(messages: list[Any], extractor, first: int) -> int:
    """The end of the longest run of whole messages from `first` whose units,
    and the units those decode to, number at most MAX_SCAN_UNITS. Each
    message is extracted on its own, which counts at least as many units as
    extracting the run at once."""
    total = 0
    for i in range(first, len(messages)):
        units = extractor(messages[i:i + 1], i)
        if getattr(units, "capped", False):
            return i
        decoded, _ = _decoded(units, MAX_SCAN_UNITS)
        total += len(units) + len(decoded)
        if total > MAX_SCAN_UNITS:
            return i
    return len(messages)


def scan_frame(
    messages: list[Any],
    extractor,
    detectors: Sequence[Any],
    budget: Budget,
    cache: SessionCache | None = None,
    cache_key: tuple[str | None, str | None] | None = None,
) -> ScanResult:
    """Incremental scan of a cumulative transcript.

    `extractor` turns a slice of messages into ScanUnits, given the index
    offset so locators stay absolute across frames.

    When the messages from the resume point are over MAX_SCAN_UNITS, the
    longest run of whole messages from there that fits is scanned, cached as
    the new high-water mark if nothing else was skipped, and the frame
    records UNSCANNED_CAPPED for the rest. When not even the first new
    message fits, the frame is scanned as `scan` would, and nothing is
    cached.
    """
    state = cache.get(cache_key) if (cache is not None and cache_key is not None) else None
    start = resume_point(state, messages)
    cache_hit = start > 0

    # Already-scanned messages are extracted again, back to the first that
    # brings their text to 2 * SEAM_CHARS, so `_seams` can join them to the
    # first new one: a secret split across that boundary is otherwise in
    # neither scan. Messages that yield no text are walked past.
    first = start
    behind = 0
    while first > 0 and behind < 2 * SEAM_CHARS:
        first -= 1
        behind += sum(len(u.text) for u in extractor(messages[first:first + 1], first))
    units = extractor(messages[first:], first)
    end = len(messages)
    if getattr(units, "capped", False) or len(units) > MAX_SCAN_UNITS:
        cut = _prefix_end(messages, extractor, first)
        if cut > start:
            end = cut
            units = extractor(messages[first:end], first)
    result = scan(units, detectors, budget)
    complete = not result.detectors_skipped
    if end < len(messages):
        result.detectors_skipped.append(UNSCANNED_CAPPED)
    result.cache_hit = cache_hit
    result.messages_scanned = end - start
    result.messages_total = len(messages)

    prior = list(state.findings) if (state is not None and cache_hit) else []
    result.findings = dedupe_findings([*prior, *result.findings])

    if cache is not None and cache_key is not None and complete:
        # Only advance the high-water mark over a COMPLETE scan of the
        # messages up to `end`: caching a frame that skipped detectors would
        # make the gap permanent for the rest of the session. Note the
        # condition is "nothing was skipped" in what was scanned,
        # not "budget was not exceeded" -- a large frame can legitimately run
        # past budget_ms with every detector still having run, and refusing
        # to cache that would force a full rescan on every later frame.
        # A cache WRITE must not decide a verdict. `SessionCache` exists so
        # Redis can replace the in-process LRU, and a Redis outage would
        # otherwise turn every governed request into a 500 in enforce
        # mode -- a webhook failure, when the verdict had already been
        # computed and only the bookkeeping failed.
        #
        # The shipped LRU cannot raise, so this is a trap for the
        # documented extension point rather than a live bug.
        _cache_put(
            cache,
            cache_key,
            SessionState(
                scanned_messages=end,
                shapes=[message_shape(m) for m in messages[:end]],
                head=head_digest(messages),
                findings=result.findings,
            ),
        )
    return result
