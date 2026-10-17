"""T0: built-in regex detectors. Stdlib only, microseconds per KB.

Every pattern here is deliberately narrow. This runs on every frame of every
governed request in an organization, so a false positive is a blocked user.
Where a cheap structural check exists (Luhn for card numbers, JWT header
decode, SSN allocation rules) it is applied before a Finding is emitted.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable, Iterable, Iterator
from typing import NamedTuple

from ..models import Finding, ScanUnit, digest, load_json
from .base import LABEL_START, TIER_T0, label


class Rule(NamedTuple):
    id: str
    pattern: re.Pattern[str]
    # Optional structural check over the matched text. Returning False
    # suppresses the finding. This is where false positives are killed.
    validate: Callable[[str], bool] | None = None
    # Which capture group holds the sensitive text (0 = whole match).
    group: int = 0
    # Reports exactly the spans of `group` that `pattern.finditer` would, in
    # linear time, where finditer itself is not.
    find: Callable[[str], Iterator[tuple[int, int]]] | None = None


def spans(rule: Rule, text: str) -> Iterator[tuple[int, int]]:
    """(start, end) of `rule.group` for each match of `rule` in `text`."""
    if rule.find is not None:
        yield from rule.find(text)
        return
    for match in rule.pattern.finditer(text):
        if match.group(rule.group) is not None:
            yield match.span(rule.group)


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


SEPARATORS = re.compile(r"[\s\u2013\u2014.,_-]+")


def _digits(text: str) -> str:
    """Strip every separator the patterns accept.

    This has to agree with the character classes in the rules. It did
    not: the classes accepted dots and en dashes while this stripped
    only spaces and hyphens, so a dotted SSN matched the pattern and was
    then thrown away by the length check. A validator that disagrees with
    its own pattern fails silently, which is the worst way to fail.
    """
    return SEPARATORS.sub("", text)


def _is_pan(text: str) -> bool:
    digits = _digits(text)
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    if len(set(digits)) <= 2:  # 4111111111111111 is a test PAN, 0000... is noise
        return False
    if not _luhn(digits):
        return False
    # Require a plausible major-industry identifier. Without this, any Luhn-
    # valid long number (some order IDs, IMEIs) trips the rule.
    return digits[0] in "3456" or digits.startswith(("2221", "2720"))


def _is_ssn(text: str) -> bool:
    digits = _digits(text)
    if len(digits) != 9 or not digits.isdigit():
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    # Repdigits (111-11-1111 and friends) are placeholders, not SSNs.
    return len(set(digits)) != 1


def _is_jwt(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 3:
        return False
    head = parts[0]
    try:
        raw = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
        payload = load_json(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    # A real JOSE header always carries `alg`. This rejects the many
    # dot-separated base64-ish strings that are not tokens.
    return isinstance(payload, dict) and "alg" in payload


_HEX = re.compile(r"[0-9A-F]+")
_NOT_BASE32 = re.compile(r"[0189]")


def _not_hex(text: str) -> bool:
    """False when the characters after a four-character prefix are all
    uppercase hex digits and one of them is a digit base32 does not use,
    as where an uppercase hex digest holds `ACCA`."""
    return _HEX.fullmatch(text, 4) is None or _NOT_BASE32.search(text, 4) is None


_JWT_CLASS = r"A-Za-z0-9_\-"
_JWT = re.compile(
    rf"eyJ[{_JWT_CLASS}]{{8,}}+\.[{_JWT_CLASS}]{{8,}}+\."
    rf"[{_JWT_CLASS}]{{8,}}\b"
)
# A maximal run of segment characters at least `eyJ` plus 8 long, followed by
# a dot.
_JWT_HEADER_RUN = re.compile(rf"(?<![{_JWT_CLASS}])[{_JWT_CLASS}]{{11,}}+(?=\.)")
_JWT_START = re.compile(r"eyJ")


def _jwt_spans(text: str) -> Iterator[tuple[int, int]]:
    """Spans of `_JWT`.

    A header's characters run to the end of the run it starts in, so a start
    is possible only where that run ends at a dot at least 11 characters on.
    Every start in one run reaches the same payload and signature, so one
    anchored match per run decides all of them, from the earliest start.
    """
    pos = 0
    for run in _JWT_HEADER_RUN.finditer(text):
        dot = run.end()
        lo = max(run.start(), pos)
        latest = dot - 11
        if lo > latest:
            continue
        start = _JWT_START.search(text, lo, latest + 3)
        if start is None:
            continue
        match = _JWT.match(text, start.start())
        if match is not None:
            yield match.span()
            pos = match.end()


# The rules for credentials with a fixed prefix have no word boundary on
# either side: a letter, digit or `_` touching the value, `key_AKIA...` or
# `xoxb-...7`, does not stop a match. The PAN rule ends at a letter or digit
# and not at `_`; the SSN rules end at a digit and not at a letter.
RULES: tuple[Rule, ...] = (
    # Not after an uppercase letter or digit, and not when the rest is an
    # uppercase hex digest's. Each lookbehind in these patterns follows the
    # first character it tests, so the search starts from that character.
    Rule("aws-access-key", re.compile(r"A(?<![A-Z0-9]A)(?:KIA|SIA|BIA|CCA)[0-9A-Z]{16}"),
         validate=_not_hex),
    Rule(
        "aws-secret-key",
        # Only when labelled: a bare 40-char base64 string is far too common.
        re.compile(
            rf"(?i){LABEL_START}aws"
            r"[_\-. ]?(?:secret|sk)[_\-. ]?(?:access[_\-. ]?)?key[\"'\s:=]{1,10}"
            r"([A-Za-z0-9/+=]{40})"
        ),
        group=1,
    ),
    Rule("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    Rule("github-pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,255}")),
    Rule(
        "anthropic-api-key",
        re.compile(r"sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{32,150}"),
    ),
    # Claude OAuth access and refresh tokens: what `claude setup-token`
    # prints and an Agent SDK agent holds as CLAUDE_CODE_OAUTH_TOKEN. Its own
    # rule because it is revoked from claude.ai, not the Console, and a
    # finding that says "API key" sends someone to the wrong place. They were
    # caught only by the OpenAI rule's `sk-` prefix, so tightening that rule
    # would have stopped detecting them.
    Rule(
        "anthropic-oauth-token",
        re.compile(r"sk-ant-(?:oat|ort)[0-9]{2}-[A-Za-z0-9_\-]{32,200}"),
    ),
    # A claude.ai session key: a signed-in browser session, as good as a
    # password until it expires.
    Rule(
        "anthropic-session-key",
        re.compile(r"sk-ant-sid[0-9]{2}-[A-Za-z0-9_\-]{32,200}"),
    ),
    # Not `sk-ant-`: every Anthropic credential also matched this, so one
    # value produced two findings and counted under OpenAI.
    # After a letter, digit or `_` only when the value holds `T3BlbkFJ`.
    Rule("openai-api-key", re.compile(
        r"sk-(?:(?<!\wsk-)|(?=[A-Za-z0-9_\-]{0,200}T3BlbkFJ))"
        r"(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{40,200}")),
    Rule("slack-token", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,250}")),
    Rule("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    Rule("stripe-secret-key", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,120}")),
    Rule(
        "private-key-pem",
        re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
    Rule(
        "jwt",
        # The first two segments are possessive; their class excludes the
        # dot that follows, so giving back characters could never help.
        _JWT,
        validate=_is_jwt,
        find=_jwt_spans,
    ),
    # A separator is required here: a bare nine-digit run is far too
    # common (order ids, timestamps, account numbers) to block on.
    #
    # The separator must be the SAME in both positions, hence the
    # backreference. Choosing them independently matched shapes no human
    # writes: `DDD DD.DDDD` and `DDD.DD DDDD` are ordinary decimal figures
    # in spreadsheet content, and at block severity this rule would deny
    # those prompts in enforce mode.
    #
    # The dot stays in the set. It is not an SSA convention, but a
    # consistently dotted `123.45.6789` is a form people do paste, and the
    # measured false positives were all mixed-separator rather than dotted.
    # Fixing what the evidence showed, not more.
    Rule(
        "ssn",
        re.compile(r"\d(?<!\d\d)\d{2}([-\u2013. ])\d{2}\1\d{4}(?!\d)"),
        validate=_is_ssn,
    ),
    # The unseparated form, gated on a nearby label -- same approach as
    # aws-secret-key. Without the label this cannot be distinguished from
    # any other nine-digit number; with it, the intent is explicit.
    Rule(
        "ssn-labeled",
        re.compile(
            "(?i)"
            + label(r"ssn", r"s\.s\.n",
                    r"social[ _-]?security(?:[ _-]?(?:number|no|#))?",
                    r"soc[ _-]?sec", r"tax[ _-]?(?:id|payer[ _-]?id)")
            + r"[^0-9\n]{0,20}(\d{3}[-\u2013. ]?\d{2}[-\u2013. ]?\d{4})(?!\d)"
        ),
        validate=_is_ssn,
        group=1,
    ),
    Rule(
        "pan",
        re.compile(r"\d(?<![^\W_]\d)(?:[ -]?\d){12,18}(?![^\W_])"),
        validate=_is_pan,
    ),
)

# No pattern above matches fewer characters than this.
SHORTEST_MATCH = 11

# Human-readable phrasing for deny_reason. Keyed by rule id. Never include the
# matched value; these strings are shown verbatim to the end user.
DESCRIPTIONS: dict[str, str] = {
    "aws-access-key": "an AWS access key ID",
    "aws-secret-key": "an AWS secret access key",
    "github-token": "a GitHub access token",
    "github-pat": "a GitHub personal access token",
    "anthropic-api-key": "an Anthropic API key",
    "anthropic-oauth-token": "a Claude sign-in token",
    "anthropic-session-key": "a Claude session key",
    "openai-api-key": "an API key",
    "slack-token": "a Slack token",
    "google-api-key": "a Google API key",
    "stripe-secret-key": "a Stripe secret key",
    "private-key-pem": "a private key",
    "jwt": "a JSON Web Token",
    "ssn": "a US Social Security number",
    "ssn-labeled": "a US Social Security number",
    "pan": "a payment card number",
}


class T0RegexDetector:
    name = "regex"
    tier = TIER_T0

    def __init__(
        self,
        severity: str = "block",
        salt: str = "",
        enabled_rules: set[str] | None = None,
    ):
        self.severity = severity
        self._salt = salt
        self._rules = tuple(r for r in RULES if enabled_rules is None or r.id in enabled_rules)

    def available(self) -> bool:
        return True

    def matches(self, units: Iterable[ScanUnit]):
        """Yield `(detector_name, matched_value)` for spot checking.

        Mirrors `scan` without building Findings. See ChecksumDetector.matches
        for why this exists rather than reconstructing values from hashes.
        """
        for unit in units:
            if len(unit.text or "") < SHORTEST_MATCH:
                continue
            for rule in self._rules:
                for start, end in spans(rule, unit.text):
                    matched = unit.text[start:end]
                    if rule.validate is not None and not rule.validate(matched):
                        continue
                    yield f"regex:{rule.id}", matched

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        findings: list[Finding] = []
        for unit in units:
            if len(unit.text or "") < SHORTEST_MATCH:
                continue
            for rule in self._rules:
                for start, end in spans(rule, unit.text):
                    matched = unit.text[start:end]
                    if rule.validate is not None and not rule.validate(matched):
                        continue
                    findings.append(
                        Finding(
                            detector=f"regex:{rule.id}",
                            severity=self.severity,
                            locator=unit.locator,
                            excerpt_hash=digest(matched, self._salt),
                            matched=matched,
                            tool_name=unit.tool_name,
                            start=start,
                            end=end,
                        )
                    )
        return findings
