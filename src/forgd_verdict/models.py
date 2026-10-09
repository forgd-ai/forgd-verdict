"""Core value types shared by the scan core and every adapter.

Privacy invariant: no field on any type in this module may ever hold matched
secret or PII text. `Finding.excerpt_hash` is the only channel that carries
anything derived from a match, and it is a one-way digest. Enforced by
tests/test_privacy.py.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SEVERITY_BLOCK = "block"
SEVERITY_WARN = "warn"
SEVERITIES = (SEVERITY_BLOCK, SEVERITY_WARN)

ACTION_ALLOW = "allow"
ACTION_DENY = "deny"

# Anthropic's constraint on the verdict's reference_id.
REFERENCE_ID_MAX = 50
REFERENCE_ID_CHARSET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-"
)
DENY_REASON_MAX = 500

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid() -> str:
    """A 26-char Crockford-base32 ULID. Stdlib only; sorts by creation time."""
    value = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    out = bytearray(26)
    for i in range(25, -1, -1):
        out[i] = ord(_CROCKFORD[value & 0x1F])
        value >>= 5
    return out.decode()


# The org segment for a record that carries no org. Records written before
# multi-org existed have no `org=` segment at all; readers treat both as this
# value, so nothing written earlier disappears from a default view.
#
# A name, not an empty string: `org=` with nothing after it is ambiguous
# between "no org" and a truncated path, and it sorts oddly in a blob
# listing.
ORG_UNATTRIBUTED = "unattributed"


def digest(text: str, salt: str = "") -> str:
    """sha256 of `salt` followed by the matched text.

    With an empty salt this is a bare sha256, which is brute-forceable for a
    low-entropy value: an SSN has ~1e9 possibilities and a PAN fewer once
    Luhn is applied. So a service that logs or records findings refuses to
    start without `privacy.hash_salt` unless the policy file sets
    `privacy.allow_unsalted: true`, the hook salts with a per-device salt
    (hook/device.py), and `forgd-verdict scan` with no salt uses a random
    per-process key. Hashes made with different salts do not compare.

    Encoded with `surrogatepass`, so a lone surrogate, which a JSON unicode
    escape can produce, hashes instead of raising `UnicodeEncodeError`.
    """
    return hashlib.sha256(salt.encode("utf-8", "surrogatepass")
                          + text.encode("utf-8", "surrogatepass")).hexdigest()


def hasher_for(salt: str) -> Callable[[str], str]:
    """`digest` with `salt` bound in.

    The closure holds a sha256 state that has absorbed the salt, not the
    salt string, so `hasher_for(salt)(text) == digest(text, salt)` without
    the salt being reachable from the returned function.
    """
    base = hashlib.sha256(salt.encode("utf-8", "surrogatepass"))

    def hasher(text: str) -> str:
        h = base.copy()
        h.update(text.encode("utf-8", "surrogatepass"))
        return h.hexdigest()

    return hasher


# An intake device id: "d" and 12 hex characters, the hook's salt namespace,
# derived from its random device salt. Anything else, a machine name for
# instance, is treated as no device id, so a person's name is never stored.
# Not a credential.
DEVICE_ID = re.compile(r"d[0-9a-f]{12}")


def pseudonym(value: str | None, salt: str = "", prefix: str = "id") -> str | None:
    """Stable pseudonym for an org or person identifier.

    A grouping key for a dashboard, not a cryptographic commitment.

    The ten-character prefix is 40 bits. Against a candidate list of a
    million emails the false-positive rate is about 1e-6, so anyone
    holding both the pseudonyms and a candidate list can confirm a guess
    essentially every time. The truncation raises the cost of a
    COLLISION-FREE dictionary attack at very large list sizes; it does
    not hide a guessable identifier.

    The salt is what protects one. Without it `digest` is a bare sha256
    over the value. A service that logs or records findings refuses to
    start without `privacy.hash_salt` unless the policy file sets
    `privacy.allow_unsalted: true` (`Policy.refuse_unsalted`); with that
    opt-out it runs and `applog.warn_if_unsalted` warns at startup.

    Widening the prefix splits every existing org partition in two, so
    the length is fixed by the data already written rather than by the
    property above.
    """
    if not value:
        return None
    return f"{prefix}_{digest(value, salt)[:10]}"


@dataclass(frozen=True)
class ScanUnit:
    """One piece of scannable text, with enough context to locate it again.

    `text` is the FOLDED form -- see `normalize.fold`. Folding happens here
    rather than in each `extract` module because every adapter builds its
    units through this constructor and none of them should be able to
    forget: one zero-width character inside a credential defeated the
    regex tier, the checksum tier, the entropy tier and gitleaks at once,
    and an adapter added later would have inherited that.

    `folded` says the text was changed, which means an offset into it is
    not an offset into what the sender actually sent. `core.scan` drops
    spans on findings from such a unit.
    """

    locator: str
    tool_name: str | None
    text: str
    folded: bool = False
    # The value was over its adapter's size limit and part of its middle
    # was not scanned. Set on both the head unit and its tail unit.
    truncated: bool = False
    # The end of an over-limit value. Its head is the unit before it in
    # the list, and the two are not adjacent text.
    tail: bool = False
    # An identifier field of a content block (`id`, `tool_use_id`, `name`).
    # The entropy detector skips it; every other detector scans it.
    structural: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):  # pragma: no cover - guard
            raise TypeError("ScanUnit.text must be str")
        from .normalize import fold

        text, changed = fold(self.text)
        if changed:
            object.__setattr__(self, "text", text)
            object.__setattr__(self, "folded", True)


TAIL_SUFFIX = "#tail"

# The most units one scan runs detectors over. Extraction stops building
# units at this many, keeping the last ones, and `core.scan` keeps the last
# this many of whatever it is given.
MAX_SCAN_UNITS = 30_000
# The longest locator, in characters and in dot-separated segments.
MAX_LOCATOR_CHARS = 1024
MAX_LOCATOR_SEGMENTS = 32

# The entry `core.scan` adds to `detectors_skipped` when part of a value was
# not scanned. A colon cannot appear in a detector or plugin name.
UNSCANNED = "unscanned:oversize"
# The entry `core.scan` adds when it hit MAX_SCAN_UNITS, for units or for
# decoded units, so a match may be missing from any unit of the scan.
UNSCANNED_CAPPED = "unscanned:capped"
# The entry `core.scan` adds when it kept only MAX_SCAN_FINDINGS of its
# findings. Every unit was scanned.
FINDINGS_CAPPED = "findings:capped"
# The entry the Compliance chat pass adds when an artifact could not be
# fetched, so its content was not scanned.
UNSCANNED_ARTIFACT = "unscanned:artifact"
# The entry the Compliance chat pass adds when a chat deleted in claude.ai
# no longer serves its messages, so nothing in it was scanned.
UNSCANNED_DELETED = "unscanned:deleted"
# The entry the Managed Agents pass adds when a session's history could not
# be paged to its end, so only the events read were scanned.
UNSCANNED_PARTIAL = "unscanned:partial"
# Entries that say part or all of an item's content was not read by any
# detector. Every one starts with UNSCANNED_PREFIX.
UNSCANNED_PREFIX = "unscanned:"
# Entries that say an item's content was never read at all, so a record
# carrying one is no evidence about what the item held.
NO_CONTENT_READ = (UNSCANNED_DELETED,)


# The transcript block a locator is in: message index, content index.
BLOCK_LOCATOR = re.compile(r"^msg\[(\d+)\]\.content\[(\d+)\]")

# DLP detectors that do not make a result a taint source. Entropy fires on
# ordinary high-randomness strings -- hashes, ids -- and every file its
# call named would become tainted.
# Names and places are in nearly everything an agent reads -- an email
# thread, a slide deck -- and nearly everything it writes back, so as taint
# sources they would mark ordinary work as a leak.
NOT_TAINT_SOURCES = ("provenance:", "taint:", "entropy", "presidio:person", "presidio:location")


def head_and_tail(text: str, limit: int, tail_chars: int) -> tuple[str, str, int]:
    """`text` as a head of at most `limit` characters, a tail of at most
    `tail_chars` from its end, and the number of characters in neither.

    The tail is empty when `text` fits in `limit`. The count is zero when
    the tail starts where the head ends.
    """
    if len(text) <= limit:
        return text, "", 0
    rest = text[limit:]
    tail = rest[-tail_chars:] if tail_chars > 0 else ""
    return text[:limit], tail, len(rest) - len(tail)


def tail_unit(head: ScanUnit, text: str) -> ScanUnit:
    """The unit for the tail of `head`'s value, located at `head` + `#tail`.

    Marked folded: an offset into the tail is not an offset into the value.
    """
    return ScanUnit(locator=head.locator + TAIL_SUFFIX, tool_name=head.tool_name,
                    text=text, folded=True, truncated=head.truncated, tail=True,
                    structural=head.structural)


@dataclass(frozen=True)
class Finding:
    detector: str
    severity: str
    locator: str
    excerpt_hash: str
    tool_name: str | None = None
    # Where the match sat in the ScanUnit's text. IN MEMORY ONLY -- adapter
    # 5 needs them to replace a matched span without destroying the prose
    # around it, and nothing else reads them.
    #
    # They are deliberately NOT on FindingRow. `from_finding` copies five
    # fields by position, so a span cannot reach the store by accident, and
    # that is the property to preserve: offsets plus the original text are
    # the matched value, and the store is the one place that must never be
    # able to reconstruct it.
    #
    # None means the detector did not report a span. A redactor must treat
    # that as "redact the whole value" rather than "nothing to redact".
    start: int | None = None
    end: int | None = None
    # For a finding on a seam, the locators of the other units its match
    # lies in; the finding's own locator is the first. IN MEMORY ONLY, like
    # the span: adapter 5 masks each of them whole, and nothing else reads
    # them. Matched key paths are rewritten in them as in the locator, but
    # the cheap-tier locator scrub does not run on them, so they are kept
    # out of repr and equality.
    seam_others: tuple[str, ...] = field(default=(), repr=False, compare=False)
    # The locator `core.scan` placed the finding at, before matched key
    # paths were rewritten and the cheap-tier scrub ran. IN MEMORY ONLY,
    # like the span: adapter 5 files findings under it, and nothing else
    # reads it. It is sender data, so it is kept out of repr and equality.
    raw_locator: str | None = field(default=None, repr=False, compare=False)

    def to_log(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "severity": self.severity,
            "locator": self.locator,
            "excerpt_hash": self.excerpt_hash,
            "tool_name": self.tool_name,
        }


@dataclass
class Verdict:
    action: str
    deny_reason: str | None = None
    reference_id: str | None = None
    findings: list[Finding] = field(default_factory=list)
    # Not part of Anthropic's schema. Unknown verdict fields are ignored by
    # Anthropic, so we return this for our own tooling and load tests.
    findings_count: int = 0
    budget_exceeded: bool = False

    def to_wire(self) -> dict[str, Any]:
        """The JSON body Anthropic reads. Never includes matched content."""
        body: dict[str, Any] = {"action": self.action}
        if self.action == ACTION_DENY:
            body["deny_reason"] = self.deny_reason
            body["reference_id"] = self.reference_id
        body["findings_count"] = self.findings_count
        return body


def sanitize_reference_id(value: str) -> str:
    """Coerce to Anthropic's charset and length.

    A malformed reference_id is silently dropped on their side, which would
    break the Activity Feed join, so we never emit one we know is invalid.
    """
    cleaned = "".join(c if c in REFERENCE_ID_CHARSET else "-" for c in value)
    return cleaned[:REFERENCE_ID_MAX]


def make_reference_id(detector_short: str) -> str:
    short = sanitize_reference_id(detector_short)[:12] or "scan"
    return sanitize_reference_id(f"fv_{short}_{ulid()}")


# Values that mean "nobody has issued this yet". The bootstrap and the
# Terraform modules write them so a service can be created before its
# credential exists, and they are PUBLIC -- they are in this repository.
#
# So they must never be accepted as a credential. The verdict server already
# rejects a signing secret that does not decode, but a bearer token has no
# format to fail: any non-empty string authenticated, which made the
# placeholder a working key for anyone who read the repo.
PLACEHOLDERS = frozenset({
    "placeholder-not-yet-issued",
    "changeme",
    "REPLACE_ME",
})


def usable_secret(value: str | None) -> str | None:
    """A credential, or None if nothing has been issued yet."""
    if not value:
        return None
    return None if str(value).strip() in PLACEHOLDERS else value


# A bearer token has no format to fail, so length is the only floor
# available. 24 characters is what `openssl rand -base64 18` produces and
# is far above anything typed by hand; the filter was three literals plus
# empty, so a one-character token registered and the service started with
# an ordinary INFO record.
MIN_TOKEN_CHARS = 24


def require_strong_token(where: str, value: str) -> str:
    """Refuse a token too short to be one. Not the same as absent.

    Deliberately separate from `usable_secret`, which answers "has a
    credential been issued yet" and whose None means NOT CONFIGURED --
    an org with no key is skipped, which is right. Folding a length test
    into that would make a real-but-weak token silently disappear instead
    of being reported.
    """
    if len(value.strip()) < MIN_TOKEN_CHARS:
        raise ValueError(
            f"{where} is {len(value.strip())} characters; a bearer token has "
            f"no format to fail, so length is the only floor and this one is "
            f"under {MIN_TOKEN_CHARS}. Generate one with "
            "`openssl rand -base64 24`."
        )
    return value


def env_or_literal(value: str | None) -> str | None:
    """Resolve a policy value written as `$ENV_VAR` to its environment value."""
    if value is None:
        return None
    if isinstance(value, str) and value.startswith("$"):
        return os.environ.get(value[1:]) or None
    return value or None


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Stable dedupe. Cumulative frames re-report the same finding otherwise.

    Findings with one key are merged into the first: it counts on every
    unit either names in `seam_others`, and it has no span when either has
    none.
    """
    index: dict[tuple[str, str, str], int] = {}
    out: list[Finding] = []
    for f in findings:
        key = (f.detector, f.locator, f.excerpt_hash)
        i = index.get(key)
        if i is None:
            index[key] = len(out)
            out.append(f)
        else:
            out[i] = _merged(out[i], f)
    return out


def _merged(a: Finding, b: Finding) -> Finding:
    """`a` counting on the units `a` or `b` counts on, without a span when
    either has none."""
    others = tuple(dict.fromkeys((*a.seam_others, *b.seam_others)))
    spanless = None in (a.start, a.end, b.start, b.end)
    if others == a.seam_others and (not spanless or a.start is a.end is None):
        return a
    return replace(a, seam_others=others,
                   start=None if spanless else a.start, end=None if spanless else a.end)


def load_json(text: str | bytes | bytearray) -> Any:
    """`json.loads`, except that an integer with more digits than
    `sys.get_int_max_str_digits()` is kept as its digit string instead of
    raising ValueError, and nesting past the recursion limit raises
    ValueError instead of RecursionError."""
    try:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise
        except ValueError:
            return json.loads(text, parse_int=_parse_int)
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None


def _parse_int(digits: str) -> int | str:
    limit = sys.get_int_max_str_digits()
    if limit and len(digits.lstrip("-")) > limit:
        return digits
    return int(digits)


# -- URLs as they may be shown ----------------------------------------------

URL_REDACTED = "<redacted>"

_URL_ENV_REFERENCE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://")
_HOSTNAME = re.compile(r"[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_.])?")
_IPV6 = re.compile(r"[0-9a-f:.]{2,45}")
_PLAIN = re.compile(r"[^@?#;=%\\\s]*")
_SEGMENT_UNSAFE = re.compile(r"[;=@%\\\s]|[^\x21-\x7e]")
# Anything URL-shaped inside free text.
_EMBEDDED = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>]*")


def shown_url(value: str) -> str:
    """`value` with anything credential-shaped replaced by `<redacted>`, for
    showing a URL or URL-like setting in the policy view, a log line or an
    error.

    Kept: scheme, host, port and path. Replaced with `<redacted>`: userinfo,
    the query, the fragment, a host that is not plainly a hostname or an IP
    address, and any path segment carrying `;`, `=`, `@`, `%`, a backslash,
    whitespace or a non-ASCII character. A `$NAME` reference is shown as
    written. A string with no scheme is shown as written only when it holds
    none of `@ ? # ; = %`, whitespace or a backslash.
    """
    if _URL_ENV_REFERENCE.fullmatch(value):
        return value
    scheme = _SCHEME.match(value)
    if scheme is None:
        return value if _PLAIN.fullmatch(value) and value.isascii() else URL_REDACTED
    name = scheme.group(1)
    try:
        parts = urlsplit(value)
        port = parts.port
        host = parts.hostname or ""
    except ValueError:
        return f"{name}://{URL_REDACTED}"
    raw_netloc = parts.netloc
    if "[" in raw_netloc:
        host_shown = f"[{host}]" if _IPV6.fullmatch(host) else URL_REDACTED
    else:
        host_shown = host if (not host or _HOSTNAME.fullmatch(host)) else URL_REDACTED
    netloc = host_shown + (f":{port}" if port is not None else "")
    if "@" in raw_netloc:
        netloc = f"{URL_REDACTED}@{netloc}"
    path = "/".join(URL_REDACTED if _SEGMENT_UNSAFE.search(seg) else seg
                    for seg in parts.path.split("/"))
    query = URL_REDACTED if parts.query or "?" in value else ""
    fragment = URL_REDACTED if parts.fragment or "#" in value else ""
    shown = urlunsplit((name, netloc, path, query, fragment))
    if "?" in value and not parts.query and "?" not in shown:
        shown += "?" + URL_REDACTED
    return shown


def shown_text(text: str) -> str:
    """`text` with every URL inside it passed through `shown_url`."""
    if "://" not in text:
        return text
    return _EMBEDDED.sub(lambda m: shown_url(m.group(0)), text)


# -- state names --------------------------------------------------------------

# The runtime overrides object's name under the store's `state/` prefix.
CONTROL_STATE = "runtime-overrides.json"
# Prefixes of the state names the store's own writers use: the org
# registries, the lockout reports and the Managed Agents cursors.
RESERVED_STATE_PREFIXES = ("org-registry-", "overrides-lockout-", "managed-")


def safe_state_name(name: str) -> str:
    """Reject a state key that could escape the store's namespace.

    The caller derives these from configuration -- an org's `state_path` --
    so a traversal here would be a config file reaching outside the store.
    Refused rather than sanitised: silently rewriting a key means two orgs
    could be given the same one, which is the corruption the per-org cursor
    exists to avoid.
    """
    if not name or name != name.strip():
        raise ValueError(f"state name must be non-empty and unpadded: {name!r}")
    if "/" in name or "\\" in name or name.startswith("."):
        raise ValueError(f"state name must be a flat key, got {name!r}")
    return name


def config_state_name(name: str) -> str:
    """`safe_state_name`, and also refuse a name the store reserves, compared
    without case or surrounding space. For a key derived from configuration,
    such as a compliance org's `state_path`."""
    folded = name.strip().lower() if isinstance(name, str) else name
    if folded == CONTROL_STATE or (isinstance(folded, str)
                                   and folded.startswith(RESERVED_STATE_PREFIXES)):
        raise ValueError(f"state name {name!r} is reserved for the store's own objects")
    return safe_state_name(name)
