"""OTel records -> ScanUnits, plus the identity to file the findings under.

Schema-tolerant on purpose. Of the three surfaces this adapter serves, one
schema is published and beta ("span names and attributes may change between
releases"), one is published and stable, and one -- Cowork -- has no public
attribute reference at the time of writing. All three ship on Anthropic's
release cadence, not ours.

So: a hardcoded allowlist of attribute names decides what a finding is
CALLED and where identity comes from, but it does not decide what gets
scanned. Anything string-shaped that is not structural gets scanned. The
failure this avoids is the one this project keeps meeting -- adapter 3
missing claude.ai chats entirely, the hook reading the wrong prompt field --
where an upstream rename turns into silence rather than an error.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..extract import API_TOOL_ID, Units, locator_key
from ..models import MAX_SCAN_UNITS, ScanUnit, tail_unit
from . import (
    SURFACE_CODE,
    SURFACE_COWORK,
    SURFACE_EXCEL,
    SURFACE_M365,
    SURFACE_OUTLOOK,
    SURFACE_POWERPOINT,
    SURFACE_UNKNOWN,
    SURFACE_WORD,
)
from .payload import IDENTITY_MAX_CHARS, KEY_SUFFIX, OtelRecord

MAX_UNIT_BYTES = 1 * 1024 * 1024
# Below this, a string is too short to hold anything a detector would match
# and long enough lists of them cost real time. The shortest thing T0 can
# find is an 8-char pattern.
MIN_SCAN_CHARS = 8

# Attributes that identify rather than describe. These are NEVER scanned.
#
# This is not an optimisation. `user.email` is on every event from every
# surface, and the PII detectors would flag it every time -- so every event
# becomes a finding, the dashboard reports 100% detection, and the signal is
# gone. The same argument applies to any identifier: we pseudonymise these
# deliberately, and a finding that says "we found an email address, and it
# was the one in the envelope" is noise dressed as a result.
IDENTITY_KEYS = frozenset(
    {
        "organization.id",
        "user.email",
        "user.account_uuid",
        "user.account_id",
        "user.id",
        "session.id",
        "prompt.id",
        "message.uuid",
        "request_id",
        "client_request_id",
        "trace_id",
        "span_id",
        "service.name",
        "service.version",
        "event.name",
        "event.timestamp",
        "event.sequence",
        "app.version",
        "app.entrypoint",
        "terminal.type",
        "model",
        "tool_name",
        "tool_use_id",
        "success",
        "error_type",
        "decision_type",
        "decision_source",
        "query_source",
        "command_name",
        "command_source",
        "mcp_server_scope",
        # Ours, not the sender's. Both decoders drop any inbound
        # `forgd.`-prefixed key (payload.RESERVED_PREFIX), because this one
        # is READ BACK to decide whether an event belongs to a dropped
        # turn: a sender setting it could keep its own event on the wire
        # while the honest path dropped both.
        "forgd.parent_span",
    }
)

# Structural suffixes: counters, sizes, durations, identifiers.
IDENTITY_SUFFIXES = (
    ".id",
    "_id",
    ".uuid",
    "_uuid",
    "_length",
    "_bytes",
    "_ms",
    ".count",
    "_count",
)

# Known content-bearing attributes, per surface. Membership here does not
# gate scanning -- it orders the units so the most likely carrier is scanned
# first when a budget is tight, and it is how we notice a rename.
CONTENT_KEYS = (
    # Claude Code, logs
    "prompt",
    "response",
    "tool_parameters",
    "user_system_prompt",
    "error",
    "api_request_body",
    "api_response_body",
    # Office agents and Cowork, spans
    "tool.input",
    "tool.output",
    "tool.parameters",
    "file.path",
    "file.name",
    "document.url",
    "filename",
    "gen_ai.prompt",
    "gen_ai.completion",
    # The log record body, from payload.py
    "_body",
)

_SURFACE_BY_SERVICE = {
    "claude-code": SURFACE_CODE,
    "claude_code": SURFACE_CODE,
    "cowork": SURFACE_COWORK,
    "claude-cowork": SURFACE_COWORK,
    "sheet": SURFACE_EXCEL,
    "excel": SURFACE_EXCEL,
    "doc": SURFACE_WORD,
    "word": SURFACE_WORD,
    "slide": SURFACE_POWERPOINT,
    "powerpoint": SURFACE_POWERPOINT,
    "mail": SURFACE_OUTLOOK,
    "outlook": SURFACE_OUTLOOK,
    # LAST on purpose, and it is a substring match. The office agents send
    # `service.name: office-agent` -- a FOURTH spelling of this product,
    # after `sheet_agent` on the inference hook and `office_agents` /
    # `office_agents/<app>` on the Compliance API. None of the tokens above
    # is a substring of it, so without this entry those records attribute
    # to otel-unknown although service.name says what they are.
    #
    # The `office.*` attribute fallback catches records carrying
    # office.version and misses these: a token_usage or tool event from the
    # same agent carries no office.* key at all.
    #
    # Last, because it is the least specific. `office-outlook` matches
    # `outlook` above and keeps that answer; only a name that commits to no
    # application falls through to the product.
    "office": SURFACE_M365,
}


def attribution_hint(record: OtelRecord) -> str:
    """What a record called itself, for a record nothing could attribute.

    Only reached for otel-unknown. `service.name` is a service identifier,
    not content -- and without it, an unattributed export is a dead end:
    the counters say records arrived and the dashboard says otel-unknown,
    and nothing anywhere says what the sender claimed to be, although the
    payload named it.
    """
    return (
        record.get("service.name")
        or record.get("agent.type", "agent.name", "app.name")
        or (record.name.split(".")[0] if record.name else "")
        or "(nothing)"
    )


# Service names Anthropic's products are known to send. The table above
# matches most of them by substring, so its keys alone missed
# `office-agent`, and declaring it would have moved every M365 record into
# an agent row. A name that merely contains a product token is allowed:
# `email-triage` is exactly the misattribution a declaration corrects.
_PRODUCT_SERVICE_NAMES = frozenset(_SURFACE_BY_SERVICE) | {
    "office-agent", "excel-agent", "word-agent", "powerpoint-agent",
    "outlook-agent", "sheet_agent", "doc_agent", "slide_agent", "mail_agent",
}

AGENT_NAME_OK = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\Z")


def agent_services(config: dict) -> frozenset[str]:
    """`otel.agents`: service names that are the deployment's own agents.

    The Agent SDK reports `service.name: claude-code` unless the builder
    sets `OTEL_SERVICE_NAME`, and a name it does set otherwise falls into
    the substring match below: `email-triage` is filed as Outlook,
    `docs-bot` as Word, and anything else as otel-unknown.

    Raises ValueError rather than dropping a bad entry, so a typo refuses
    to start instead of leaving an agent quietly filed as something else.
    A product's own service name is refused too: declaring `claude-code`
    would move every developer laptop into an agent row.
    """
    raw = config.get("agents") or []
    if not isinstance(raw, list):
        raise ValueError("otel.agents must be a list of service names")
    out = set()
    for entry in raw:
        name = str(entry).strip().lower()
        if not AGENT_NAME_OK.fullmatch(name):
            raise ValueError(f"otel.agents: {name!r} is not a service name "
                             "(lowercase letters, digits, '.', '_', '-'; at most 64)")
        if name in _PRODUCT_SERVICE_NAMES:
            raise ValueError(f"otel.agents: {name!r} is a product's own service name")
        out.add(name)
    return frozenset(out)


def surface_of(record: OtelRecord, agents: frozenset[str] = frozenset()) -> str:
    """Which product emitted this.

    Checked in order of how much the sender committed to the answer: an
    explicit service name beats a guess from an event name prefix.

    A declared agent is an exact match and comes first, so the substring
    match cannot claim it. Only a configured name becomes a surface; the
    sender's own string never does.
    """
    service = (record.get("service.name") or "").strip().lower()
    if service in agents:
        return f"agent:{service}"
    if service:
        if service in _SURFACE_BY_SERVICE:
            return _SURFACE_BY_SERVICE[service]
        for token, surface in _SURFACE_BY_SERVICE.items():
            if token in service:
                return surface
    name = (record.name or "").lower()
    if name.startswith("claude_code."):
        return SURFACE_CODE
    # `agent.*` spans are the office agents' shape. Cowork also emits tool
    # and prompt events, so this is only reached when nothing named itself.
    agent = (record.get("agent.type", "agent.name", "app.name") or "").lower()
    for token, surface in _SURFACE_BY_SERVICE.items():
        if token and token in agent:
            return surface
    # An `office.*` attribute is the office agents naming themselves, and
    # it is the only thing on such an export that does.
    #
    # A trace carrying office.version, tool.owner and tool.accept_decision
    # would otherwise attribute to otel-unknown, because service.name
    # matches no token and no agent.* attribute is present.
    #
    # Which Office application it is does not follow from office.version,
    # so this does not guess one. claude-for-m365 is the same surface the
    # inference hook and the Compliance API already report, which is the
    # honest answer: one product, seen by three control points.
    if any(k.startswith("office.") for k in (*record.attributes, *record.resource)):
        return SURFACE_M365
    if name.startswith("agent."):
        return SURFACE_UNKNOWN
    return SURFACE_UNKNOWN


def is_identity(key: str, value: object = None) -> bool:
    """Is this attribute structural rather than content?

    The name alone decided it, and the suffix list is broad -- anything
    ending `_id`, `_bytes`, `_count`, `_ms` or `_length`:

        prompt      scanned=True
        prompt_id   scanned=False
        note.id     scanned=False
        blob_bytes  scanned=False

    so any sender with a valid org token, or any upstream rename into that
    shape, put content somewhere permanently unscanned. The VALUE now gets
    a say: a long string under an identity-shaped name is scanned anyway.
    An identifier that really is one is far below the threshold.
    """
    if key in IDENTITY_KEYS:
        named = True
    else:
        lowered = key.lower()
        named = any(lowered.endswith(suffix) for suffix in IDENTITY_SUFFIXES)
    if not named:
        return False
    # A long value overrules the name.
    return not (isinstance(value, str) and len(value) > IDENTITY_MAX_CHARS)


def unrecognised_keys(record: OtelRecord, detectors) -> list[str]:
    """Scannable attributes we have no name for.

    Emitted as a metric rather than a log line. An upstream rename shows up
    as this number rising, which is a thing an operator can alert on --
    unlike findings going to zero, which looks exactly like a quiet week.

    An attribute NAME is sender-controlled and this list reaches /stats,
    which needs no credential, so a name that is itself a match is
    reported as `<redacted>`. A shape check is not enough: an AWS key is
    identifier-shaped.

    `detectors` is required rather than defaulted. A default would
    mean a caller that forgot it published names unscrubbed, which is
    the failure this argument exists to prevent.
    """
    from ..core import scrub_labels

    return sorted(scrub_labels(_unrecognised(record), detectors))


def batch_unrecognised_keys(records: Iterable[OtelRecord], detectors) -> set[str]:
    """`unrecognised_keys` over every record, each distinct name scrubbed
    once and all of them in one `scrub_labels` call."""
    from ..core import scrub_labels

    names = sorted({key for record in records for key in _unrecognised(record)})
    return set(scrub_labels(names, detectors))


def _unrecognised(record: OtelRecord) -> list[str]:
    """The unscrubbed names `unrecognised_keys` reports for `record`."""
    return [
        key for key, value in record.attributes.items()
        if key not in CONTENT_KEYS
        and not is_identity(key, value)
        and isinstance(value, str)
        and len(value) >= MIN_SCAN_CHARS
    ]


def record_units_by_key(
    record: OtelRecord, index: int = 0
) -> list[tuple[str, ScanUnit]]:
    """(attribute key, ScanUnit), known content keys first.

    The keyed form exists because adapter 5 has to put a redacted value
    BACK on the attribute it came from, and the locator cannot be parsed
    to recover the key: `otel[3].agent.query.user.message` splits on dots
    that appear in both the record name and the attribute name.

    `record_units` delegates here so there is one place that decides what
    is scannable. Two implementations of that rule would drift, and the
    way it would drift is a value the scanner reads and the redactor does
    not -- which forwards a match the scan already found.
    """
    # The record name and each attribute key go through `locator_key`, so a
    # long one appears as a placeholder.
    base = locator_key(f"otel[{index}]", record.name or record.kind, 0)
    tool_name = record.attributes.get("tool_name") or None
    known: list[tuple[str, ScanUnit]] = []
    rest: list[tuple[str, ScanUnit]] = []
    for position, (key, value) in enumerate(record.attributes.items()):
        if is_identity(key, value) or not isinstance(value, str):
            continue
        if len(value) < MIN_SCAN_CHARS:
            continue
        text = value[:MAX_UNIT_BYTES]
        # `payload` keeps the end of an over-limit value on `.tail`.
        truncated = getattr(value, "gap", 0) > 0 or len(value) > MAX_UNIT_BYTES
        # `_body` is ours, not the sender's; name it for what it is so a
        # locator on a finding points at something a reader can find.
        #
        # But a sender can also supply an attribute literally called
        # `body`, and then both produced `otel[i].<name>.body`. A locator
        # is the key adapter 5 looks findings up by, and `dedupe_findings`
        # keys on it -- so the same secret in both collapsed to one
        # finding and the redactor applied one set of offsets to two
        # different strings. The collision is resolved in favour of the
        # SENDER's key, because that is the one a reader can go and look
        # at; ours takes the suffix.
        if key == "_body":
            locator = locator_key(base, "body", position)
            if "body" in record.attributes:
                locator += "#log"
        else:
            locator = locator_key(base, key, position)
        leaves = getattr(value, "leaves", ())
        if leaves:
            # An array or kvlist: one unit per scalar, in order, so a match
            # cut across elements is found on the seam between them, as
            # `extract.frame_units` makes one unit per list element. The
            # kvlist keys follow every value, so no key sits between two.
            leaves = sorted(leaves, key=lambda leaf: leaf[0].endswith(KEY_SUFFIX))
            # Every scalar of a value cut short is marked truncated.
            units = [(key, ScanUnit(locator=f"{locator}{path}", tool_name=tool_name,
                                    text=leaf[:MAX_UNIT_BYTES],
                                    truncated=truncated or len(leaf) > MAX_UNIT_BYTES))
                     for path, leaf in leaves]
        else:
            units = [(key, ScanUnit(locator=locator, tool_name=tool_name, text=text,
                                    truncated=truncated))]
        (known if key in CONTENT_KEYS else rest).extend(units)
    return known + rest


def record_units(record: OtelRecord, index: int = 0) -> list[ScanUnit]:
    """One record -> ScanUnits, known content keys first.

    A capped value's tail follows its head. `record_units_by_key` leaves
    tails out, since adapter 5 forwards only the head.
    """
    return [unit for unit, _ in _record_units_known(record, index)]


def _record_units_known(record: OtelRecord, index: int) -> list[tuple[ScanUnit, bool]]:
    """`record_units`, each unit paired with whether its key is in
    CONTENT_KEYS. A tail is paired as its head is."""
    units: list[tuple[ScanUnit, bool]] = []
    for key, unit in record_units_by_key(record, index):
        known = key in CONTENT_KEYS
        units.append((unit, known))
        value = record.attributes.get(key)
        tail = "" if getattr(value, "leaves", ()) else getattr(value, "tail", "")
        if tail:
            units.append((tail_unit(unit, tail), known))
    return units


# Identity values not scanned: UUIDs, ISO 8601 timestamps, 16 and 32 digit
# hex trace and span ids, and Anthropic tool-use ids.
_PLAIN_IDENTITY = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|[0-9a-f]{16}|[0-9a-f]{32}")


def _identity_units(record: OtelRecord, index: int) -> list[tuple[str, ScanUnit]]:
    """(attribute key, structural unit) for the attributes `record_units`
    leaves out as identity, each a string of at least MIN_SCAN_CHARS
    characters that is not a _PLAIN_IDENTITY or an API_TOOL_ID."""
    base = locator_key(f"otel[{index}]", record.name or record.kind, 0)
    tool_name = record.attributes.get("tool_name") or None
    return [
        (key, ScanUnit(locator=locator_key(base, key, position), tool_name=tool_name,
                       text=value, structural=True))
        for position, (key, value) in enumerate(record.attributes.items())
        if isinstance(value, str) and len(value) >= MIN_SCAN_CHARS
        and is_identity(key, value)
        and not _PLAIN_IDENTITY.fullmatch(value) and not API_TOOL_ID.fullmatch(value)
    ]


def records_units(records: list[OtelRecord]) -> Units:
    """`record_units` of each record, in order, then one structural unit per
    distinct identity attribute and value, at most MAX_SCAN_UNITS units in
    all, and capped when there were more.

    Over the cap, units of CONTENT_KEYS are kept first, the last ones when
    they alone are over it, then the last of the other content units, then
    the last identity units. The kept units stay in that order.
    """
    marked: list[tuple[ScanUnit, int]] = [
        (unit, 2 if is_known else 1)
        for i, record in enumerate(records)
        for unit, is_known in _record_units_known(record, i)]
    seen: set[tuple[str, str]] = set()
    for i, record in enumerate(records):
        for key, unit in _identity_units(record, i):
            if (key, unit.text) not in seen:
                seen.add((key, unit.text))
                marked.append((unit, 0))
    if len(marked) <= MAX_SCAN_UNITS:
        return Units(unit for unit, _ in marked)
    kept: list[int] = []
    for rank in (2, 1, 0):
        room = MAX_SCAN_UNITS - len(kept)
        if room <= 0:
            break
        kept += [j for j, (_, r) in enumerate(marked) if r == rank][-room:]
    out = Units(marked[j][0] for j in sorted(kept))
    out.capped = True
    return out
