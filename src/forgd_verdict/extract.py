"""Turn each adapter's payload into ScanUnits.

Locators are absolute and stable across the cumulative frames of a session:
`msg[4].content[1]`, plus a field suffix where a block has more than one
scannable field (`msg[4].content[1].input`).

Forward compatibility is a hard requirement on adapter 1: a block type or
field we don't recognize is accepted, and never refused for being unknown.
Its string fields are still scanned, because an unrecognized block is
exactly where new exfiltration surface would appear, and a finding in one
is enforced like any other: it denies in `enforce`.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .models import (
    MAX_LOCATOR_CHARS,
    MAX_LOCATOR_SEGMENTS,
    MAX_SCAN_UNITS,
    ScanUnit,
    head_and_tail,
    load_json,
    tail_unit,
)

# The API block's OWN structural fields. Scanning them adds noise --
# `tool_use_id` is a high-entropy identifier that trips the entropy tier
# on every call.
#
# SKIPPED ONLY WHERE THE BLOCK ITSELF IS WALKED. Applied to every dict it
# meant a value under any key named `id` was never scanned, and a tool
# result is output the caller fully controls:
#
#   content {"id": "<anthropic key>", "name": "prod key"}   findings: 0  allow
#   the same value under "key_id"                           findings: 2  deny
#
# Depth is the wrong test for this: `_walk` is called on `input` and
# `content`, so its depth 0 is already inside sender data.
_SKIP_KEYS = frozenset(
    {"type", "id", "tool_use_id", "media_type", "size_bytes", "is_error", "role"}
)
# A claude.ai chat message's own fields that are not content: ids,
# timestamps and the sender's role.
_CHAT_META = frozenset({"id", "uuid", "role", "sender", "index", "created_at",
                        "updated_at", "parent_message_uuid", "stop_reason", "truncated"})
# The fields of a chat message's file, artifact or attachment entry that
# are ids or sizes rather than content.
_CHAT_ITEM_SKIP = _SKIP_KEYS | {"uuid", "file_uuid", "version_id", "created_at",
                                "updated_at", "mime_type", "file_kind", "file_size"}
# Of a block's own fields, the ones scanned as structural units: a string
# of at least MIN_KEY_CHARS characters, by every detector but entropy.
_STRUCTURAL_KEYS = frozenset({"id", "tool_use_id", "name", "tool_name"})
# An Anthropic tool-use id. Not scanned: no T0 rule matches after its `_`.
API_TOOL_ID = re.compile(r"(?:srv|mcp)?toolu_[A-Za-z0-9]{1,64}")
MAX_UNIT_BYTES = 4 * 1024 * 1024
# A value over MAX_UNIT_BYTES is scanned as its first MAX_UNIT_BYTES and
# its last TAIL_UNIT_BYTES. Anything between them is reported as unscanned.
TAIL_UNIT_BYTES = MAX_UNIT_BYTES // 8
MAX_DEPTH = 8

# A dict KEY is sender data and can hold a secret, but yielding every key
# would add a unit per field of every object. Only keys at least as long as
# the shortest identifier the detectors match: nine, an SSN without dashes.
MIN_KEY_CHARS = 9


# A key longer than this, one that starts like a placeholder, or one that
# holds LOCATOR_MARK, appears in locators as `<key:N>`, N being its index in
# its dict. Its `#key` unit still carries the whole key.
MAX_KEY_CHARS = 128
_PLACEHOLDER_HEAD = "<key:"
# What starts every suffix the scan adds to a locator: `#key`, `#tail`,
# `#log`, `#b64`, `#seam<n>`. No locator segment made from sender data
# holds it.
LOCATOR_MARK = "#"
# A key is written into a locator only while the locator stays within half
# of each locator cap. The other half holds what can follow: a placeholder
# or an index for each level down to MAX_DEPTH, and suffixes such as
# `#key#tail`.
_KEY_ROOM_CHARS = MAX_LOCATOR_CHARS // 2
_KEY_ROOM_SEGMENTS = MAX_LOCATOR_SEGMENTS // 2


# Every locator `hook_units` and `core.scan` can place a hook finding at: a
# hook field, then dict keys within MAX_KEY_CHARS of a key charset, key
# placeholders and list indexes, then the scan's suffixes. A key outside the
# charset fails, so a shipped locator that fails is either a key a tool
# chose or text a sender wrote.
HOOK_LOCATOR = re.compile(
    r"(?:prompt|user_input|slash_command|command_args|tool_input|tool_response"
    r"|<redacted>|<not an input locator>)"
    r"(?:\.(?:[A-Za-z0-9_\-]{1,128}|<key:\d{1,7}>|<redacted>)|\[\d{1,7}\])*"
    r"(?:#(?:key|tail|b64|log|seam\d{1,7}))*")


def is_hook_locator(locator: str) -> bool:
    """Whether `locator` is in the form `HOOK_LOCATOR` describes and within
    MAX_LOCATOR_CHARS."""
    return len(locator) <= MAX_LOCATOR_CHARS and HOOK_LOCATOR.fullmatch(locator) is not None


class Units(list):
    """ScanUnits in document order. `capped` is True when extraction stopped
    at MAX_SCAN_UNITS, so the units before these were never built."""

    capped = False


def locator_key(prefix: str, key: str, index: int) -> str:
    """`prefix.key`, or `prefix.<key:index>` when the key is over
    MAX_KEY_CHARS, starts like a placeholder, holds LOCATOR_MARK, or would
    take the locator past half of either locator cap."""
    if (len(key) <= MAX_KEY_CHARS and not key.startswith(_PLACEHOLDER_HEAD)
            and LOCATOR_MARK not in key
            and len(prefix) + 1 + len(key) <= _KEY_ROOM_CHARS
            and prefix.count(".") + key.count(".") + 2 <= _KEY_ROOM_SEGMENTS):
        return f"{prefix}.{key}"
    return f"{prefix}.{_PLACEHOLDER_HEAD}{index}>"


class _Collector:
    """Units added last first, at most MAX_SCAN_UNITS of them. Extractors
    walk every container in reverse and stop once `full()`, so the units
    kept are the last ones in document order, as `core.scan` keeps.

    The walk stops after one unit past the cap. That unit is dropped and
    marks the result capped, so a cap reached with nothing left but empty
    containers is not reported as one."""

    __slots__ = ("_rev", "_limit", "_structural", "tool_content")

    def __init__(self) -> None:
        self._rev: list[ScanUnit] = []
        self._limit = MAX_SCAN_UNITS
        self._structural: set[str] = set()
        # Set while a tool_result's content or an attachment's text is added.
        self.tool_content = False

    def full(self) -> bool:
        """Whether a unit past the cap has been added."""
        return len(self._rev) > self._limit

    def add(self, locator: str, tool_name: str | None, text: Any,
            structural: bool = False) -> None:
        """A unit for `text`. A structural text already added adds nothing."""
        if not isinstance(text, str) or not text or self.full():
            return
        if structural:
            if text in self._structural:
                return
            self._structural.add(text)
        head, tail, gap = head_and_tail(text, MAX_UNIT_BYTES, TAIL_UNIT_BYTES)
        unit = ScanUnit(locator=locator, tool_name=tool_name, text=head,
                        truncated=gap > 0, structural=structural,
                        tool_content=self.tool_content)
        if tail:
            self._rev.append(tail_unit(unit, tail))
            if self.full():
                return
        self._rev.append(unit)

    def units(self) -> Units:
        capped = len(self._rev) > self._limit
        out = Units(reversed(self._rev[:self._limit]))
        out.capped = capped
        return out


def _deep(value: Any) -> str:
    """Whatever is past the depth limit, as one string."""
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return str(value)


def _walk(out: _Collector, value: Any, prefix: str, tool_name: str | None,
          depth: int = 0, skip: frozenset[str] = frozenset()) -> None:
    """Add a unit for every string reachable in a JSON-ish value, and for
    every int or float as `str(value)`; a bool adds nothing. Units are added
    last first, and the walk stops once `out` is full.

    `skip` is empty by default: a caller walking sender data wants all of
    it. Only a branch walking a whole API block passes `_SKIP_KEYS`, and
    it is not propagated downward.
    """
    if isinstance(value, str):
        out.add(prefix, tool_name, value)
        return
    if isinstance(value, int | float) and not isinstance(value, bool):
        out.add(prefix, tool_name, str(value))
        return
    if not isinstance(value, dict | list):
        return
    if depth >= MAX_DEPTH:
        # Serialised, not dropped. Returning here would produce NO units
        # at all -- nine levels of nesting around a key would scan nothing
        # and allow. The serialised whole is scanned at the one place where
        # recursion stops.
        out.add(prefix, tool_name, _deep(value))
        return
    if isinstance(value, dict):
        last = len(value) - 1
        for j, (key, sub) in enumerate(reversed(value.items())):
            if out.full():
                return
            if key in skip:
                if key in _STRUCTURAL_KEYS:
                    _structural(out, sub, locator_key(prefix, str(key), last - j), tool_name)
                continue
            key = str(key)
            path = locator_key(prefix, key, last - j)
            # `skip` is NOT passed down: it names one block's own fields,
            # not every dict underneath it.
            _walk(out, sub, path, tool_name, depth + 1)
            if len(key) >= MIN_KEY_CHARS:
                # The key itself. `{"<AWS key>": "value"}` yielded one unit
                # for the value and never looked at the name.
                out.add(f"{path}#key", tool_name, key)
    else:
        for i in range(len(value) - 1, -1, -1):
            if out.full():
                return
            _walk(out, value[i], f"{prefix}[{i}]", tool_name, depth + 1)


def frame_units(messages: list[Any], offset: int = 0) -> Units:
    """Prompt-frame transcript -> ScanUnits.

    `offset` is the absolute index of `messages[0]` in the full transcript, so
    incremental scanning keeps locators comparable across frames.
    """
    out = _Collector()
    _frame(out, messages, offset)
    return out.units()


def _frame(out: _Collector, messages: list[Any], offset: int) -> None:
    for rel in range(len(messages) - 1, -1, -1):
        if out.full():
            return
        message = messages[rel]
        idx = offset + rel
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            out.add(f"msg[{idx}]", None, content)
            continue
        if not isinstance(content, list):
            continue
        for bidx in range(len(content) - 1, -1, -1):
            if out.full():
                return
            block = content[bidx]
            base = f"msg[{idx}].content[{bidx}]"
            if not isinstance(block, dict):
                if isinstance(block, str):
                    out.add(base, None, block)
                continue
            btype = block.get("type")
            tool_name = block.get("tool_name")
            if not isinstance(tool_name, str):
                tool_name = None

            # Each branch adds its units last first: `_rest` before the
            # block's own field.
            if btype == "text":
                _rest(out, block, base, tool_name, {"text"})
                out.add(base, tool_name, block.get("text"))
            elif btype == "tool_use":
                # `input` is arbitrary JSON. Every reachable string, every
                # key long enough to be a credential, and whatever sits
                # past the depth limit as one serialised blob.
                _rest(out, block, base, tool_name, {"input"})
                _walk(out, block.get("input"), f"{base}.input", tool_name)
            elif btype == "tool_result":
                # `content` is the tool's output as text, parts newline-joined.
                _rest(out, block, base, tool_name, {"content"})
                out.tool_content = True
                _walk(out, block.get("content"), f"{base}.content", tool_name)
                out.tool_content = False
            elif btype == "attachment":
                _rest(out, block, base, tool_name, {"text", "file_name"})
                out.add(f"{base}.file_name", tool_name, block.get("file_name"))
                out.tool_content = True
                out.add(f"{base}.text", tool_name, block.get("text"))
                out.tool_content = False
            else:
                # Unrecognized block type: accepted, and its string fields
                # scanned like any other block's.
                _walk(out, block, base, tool_name, skip=_SKIP_KEYS)


def _rest(out: _Collector, block: dict, base: str,
          tool_name: str | None, handled: set[str]) -> None:
    """Scan the fields a known block type does not name.

    Reading only the fields a type is known to have inverted the intent
    stated at the top of this module -- an unrecognised block is where
    new exfiltration surface appears, so the `else` branch walked
    everything, and the RECOGNISED types were the porous ones:

        {"type": "text", "text": "hi", "caption": "<key>"}   allow
        the byte-identical block labelled "wingding"         deny

    It is also a forward-compatibility hazard: when Anthropic adds a
    field to `text`, this would stop reading it silently.

    `_SKIP_KEYS` still applies -- these are a block's own fields, which is
    the one place that list describes.
    """
    last = len(block) - 1
    for j, (key, value) in enumerate(reversed(block.items())):
        if out.full():
            return
        if key in handled:
            continue
        if key in _SKIP_KEYS or key in _STRUCTURAL_KEYS:
            if key in _STRUCTURAL_KEYS:
                _structural(out, value, locator_key(base, str(key), last - j), tool_name)
            continue
        _walk(out, value, locator_key(base, str(key), last - j), tool_name)


def _structural(out: _Collector, value: Any, path: str, tool_name: str | None) -> None:
    """A structural unit for `value` when it is a string of at least
    MIN_KEY_CHARS characters and not an API_TOOL_ID."""
    if (isinstance(value, str) and len(value) >= MIN_KEY_CHARS
            and not API_TOOL_ID.fullmatch(value)):
        out.add(path, tool_name, value, structural=True)


# The envelope of an inference-hook frame: identifiers, not content.
FRAME_ENVELOPE_KEYS = frozenset(
    {"type", "request_id", "tenant_id", "actor", "source", "session_id", "model"}
)


def unknown_frame_units(frame: dict[str, Any]) -> Units:
    """A frame whose `type` is not `prompt` -> ScanUnits.

    `messages`, when it is a list, is read as a prompt frame's transcript.
    Every other field outside the envelope is walked whole, its keys
    included, with the same size limits as any other unit.
    """
    out = _Collector()
    messages = frame.get("messages")
    last = len(frame) - 1
    for j, (key, value) in enumerate(reversed(frame.items())):
        if out.full():
            break
        if key in FRAME_ENVELOPE_KEYS or (key == "messages" and isinstance(messages, list)):
            continue
        key = str(key)
        path = locator_key("frame", key, last - j)
        _walk(out, value, path, None)
        if len(key) >= MIN_KEY_CHARS:
            out.add(f"{path}#key", None, key)
    if isinstance(messages, list):
        _frame(out, messages, 0)
    return out.units()


# --- adapter 2: Claude Code hook payloads --------------------------------

# Fields worth scanning per tool, in the order a reviewer would look at them.
# Anything not listed still gets scanned via the generic walk below.
_TOOL_PRIORITY_FIELDS = ("command", "content", "new_string", "file_text", "prompt", "query")


def hook_units(payload: dict[str, Any]) -> Units:
    """Claude Code hook stdin JSON -> ScanUnits.

    Field names against code.claude.com/docs/en/hooks. The docs have shown
    the UserPromptSubmit prompt as both `user_input` and `prompt`, so both
    are read, and every field present is scanned.

    `UserPromptExpansion` carries the original `prompt` and the
    `command_args`, and both are scanned. It carries no expanded content,
    so whatever a skill or MCP prompt adds on expansion is not seen here.

    On both prompt events `prompt` is the last unit in document order, so
    a detector that keeps the newest units keeps it.
    """
    event = payload.get("hook_event_name")
    out = _Collector()

    # Units are added last first.
    if event == "UserPromptSubmit":
        for field in ("prompt", "user_input", "slash_command"):
            out.add(field, None, payload.get(field))
        return out.units()

    # Fires when a slash command or MCP prompt expands, and is blockable.
    if event == "UserPromptExpansion":
        for field in ("prompt", "command_args"):
            out.add(field, None, payload.get(field))
        return out.units()

    if event == "PreToolUse":
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str):
            tool_name = None
        tool_input = payload.get("tool_input")
        if isinstance(tool_input, dict):
            handled = {key for key in _TOOL_PRIORITY_FIELDS
                       if isinstance(tool_input.get(key), str)}
            # Added before the generic walk, which stops once the collector
            # is full, so they are always kept. Units are added last first,
            # so these come after everything else in document order.
            for key in reversed(_TOOL_PRIORITY_FIELDS):
                if key in handled:
                    out.add(f"tool_input.{key}", tool_name, tool_input[key])
            # Anything not handled -- including a priority field holding a
            # dict or a list rather than a string -- falls through to the
            # generic walk.
            last = len(tool_input) - 1
            for j, (key, value) in enumerate(reversed(tool_input.items())):
                if out.full():
                    break
                key = str(key)
                path = locator_key("tool_input", key, last - j)
                if key not in handled:
                    _walk(out, value, path, tool_name)
                if len(key) >= MIN_KEY_CHARS:
                    out.add(f"{path}#key", tool_name, key)
        else:
            _walk(out, tool_input, "tool_input", tool_name)
        return out.units()

    # What a tool returned, before the model sees it. The input was scanned
    # at PreToolUse, so only the response is read here. An Agent SDK
    # callback can act on a deny by replacing the output (`updatedToolOutput`);
    # the command hook cannot un-run the tool, and whether it can replace
    # the output is not documented.
    if event == "PostToolUse":
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str):
            tool_name = None
        _walk(out, payload.get("tool_response"), "tool_response", tool_name)
        return out.units()

    # Unknown event: scan nothing rather than guess at a field layout.
    return out.units()


# --- adapter 3: Compliance API transcripts -------------------------------


def compliance_units(messages: list[Any]) -> Units:
    """Compliance API session messages -> ScanUnits.

    The transcript shape differs from the prompt frame: `tool_use.input` is a
    JSON-encoded *string* rather than an object, `tool_result.content` is a
    list of `{type: text, text: ...}` entries, and blocks carry `truncated`.
    A truncated tool_use input is no longer valid JSON, so it is scanned as
    raw text rather than parsed.
    """
    out = _Collector()
    for idx in range(len(messages) - 1, -1, -1):
        if out.full():
            break
        message = messages[idx]
        if not isinstance(message, dict):
            continue
        blocks = message.get("content")
        if not isinstance(blocks, list):
            # A string content is scanned whole; any other shape is walked.
            _walk(out, blocks, f"msg[{idx}]", None)
            continue
        for bidx in range(len(blocks) - 1, -1, -1):
            if out.full():
                break
            block = blocks[bidx]
            base = f"msg[{idx}].content[{bidx}]"
            if not isinstance(block, dict):
                _walk(out, block, base, None)
                continue
            btype = block.get("type")
            tool_name = block.get("name") if isinstance(block.get("name"), str) else None
            if btype == "text":
                _rest(out, block, base, tool_name, {"text"})
                out.add(base, tool_name, block.get("text"))
            elif btype == "tool_use":
                _rest(out, block, base, tool_name, {"input", "truncated"})
                raw = block.get("input")
                if isinstance(raw, str) and not block.get("truncated"):
                    try:
                        parsed = load_json(raw)
                    except (ValueError, RecursionError):
                        parsed = raw
                    _walk(out, parsed, f"{base}.input", tool_name)
                else:
                    _walk(out, raw, f"{base}.input", tool_name)
            elif btype == "tool_result":
                _rest(out, block, base, tool_name, {"content"})
                out.tool_content = True
                _walk(out, block.get("content"), f"{base}.content", tool_name)
                out.tool_content = False
            else:
                _walk(out, block, base, tool_name, skip=_SKIP_KEYS)
    return out.units()


def chat_units(chat: dict[str, Any]) -> Units:
    """claude.ai chat -> ScanUnits.

    A third transcript shape. Messages live under `chat_messages` rather
    than `data`, each with `content` blocks plus optional `files`,
    `generated_files` and `artifacts` arrays -- any of which can be null.

    Attachment and artifact *content* is mostly not inline: the message
    carries metadata and an id, and the bytes come from a separate
    endpoint, which the ingest job fetches for artifacts. Every field a
    message carries is scanned except the ones in `_CHAT_META`, so a field
    added upstream is read rather than skipped; the chat's `name` is
    scanned too.
    """
    out = _Collector()
    messages = chat.get("chat_messages")
    if not isinstance(messages, list):
        messages = []
    for idx in range(len(messages) - 1, -1, -1):
        if out.full():
            break
        message = messages[idx]
        base = f"msg[{idx}]"
        if not isinstance(message, dict):
            _walk(out, message, base, None)
            continue
        # Last first: the message's other fields, then its content blocks.
        last = len(message) - 1
        for j, (key, value) in enumerate(reversed(message.items())):
            if out.full():
                break
            if key == "content" or key in _CHAT_META:
                continue
            path = locator_key(base, str(key), last - j)
            if isinstance(value, list):
                for i in range(len(value) - 1, -1, -1):
                    _walk(out, value[i], f"{path}[{i}]", None, skip=_CHAT_ITEM_SKIP)
            else:
                _walk(out, value, path, None, skip=_CHAT_ITEM_SKIP)
        blocks = message.get("content")
        if not isinstance(blocks, list):
            _walk(out, blocks, f"{base}.content", None)
            continue
        for bidx in range(len(blocks) - 1, -1, -1):
            if out.full():
                break
            block = blocks[bidx]
            bbase = f"{base}.content[{bidx}]"
            if not isinstance(block, dict):
                _walk(out, block, bbase, None)
            elif block.get("type") == "text":
                _rest(out, block, bbase, None, {"text"})
                out.add(bbase, None, block.get("text"))
            else:
                _walk(out, block, bbase, None, skip=_SKIP_KEYS)
    out.add("name", None, chat.get("name"))
    return out.units()


def artifact_units(locator: str, content: str | None) -> Units:
    """One fetched artifact version's text.

    Artifacts hold the code and markdown Claude generates, so a credential
    written into one is invisible to a scan that only reads message text.
    """
    out = _Collector()
    out.add(locator, None, content)
    return out.units()
