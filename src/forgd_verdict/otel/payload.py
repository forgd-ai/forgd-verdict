"""Decode OTLP/HTTP into a flat list of records.

Both encodings Anthropic offers are handled here -- HTTP/JSON and
HTTP/protobuf -- and neither pulls in a dependency. gRPC is deliberately
absent: Anthropic rejects it at configuration time for the office agents,
so an implementation would be untestable against the real sender.

The protobuf path is a ~100-line wire-format walker rather than the
generated `opentelemetry-proto` classes. Two reasons. The container that
runs this receives raw prompt text from surfaces where Anthropic redacts
nothing, so every dependency it does not have is attack surface it does not
have. And we need almost nothing from the schema: field numbers for the
nesting, then key/value pairs. The full generated schema would be carried to
use four messages of it.

The output is deliberately lossy. Everything becomes a string keyed by
attribute name, because the scan core takes text and the detectors do not
care whether a value arrived as an int. What we must not lose is WHICH
attribute a string came from, since that is the locator on the finding.
"""

from __future__ import annotations

import json
import sys
import zlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from ..models import head_and_tail, load_json

# The most records one export may carry, counting log records, or spans and
# their events. A body over it is refused whole: nothing in it is scanned or
# stored.
MAX_RECORDS = 10_000


class TooManyRecords(Exception):
    """The body holds more than MAX_RECORDS records. Raised as the walk
    passes the cap, so the rest of the body is not decoded."""


class DecodedTooLarge(Exception):
    """Rendering the body's values took more than its decode budget. Raised
    as the walk passes the budget, so the rest of the body is not decoded."""


MAX_DEPTH = 12
# Fields in one protobuf message. A real OTLP message carries at most
# MAX_RECORDS records and a few dozen fields around each; past this,
# `_walk` raises DecodeError.
MAX_FIELDS = 100_000
MAX_VALUE_CHARS = 1_000_000
# A value over MAX_VALUE_CHARS keeps its first MAX_VALUE_CHARS as the
# attribute and its last TAIL_VALUE_CHARS on `CappedValue.tail`.
TAIL_VALUE_CHARS = MAX_VALUE_CHARS // 8
# The characters one body's attribute values may render to, counting every
# intermediate JSON encoding of a nested array or kvlist: this many per
# byte of the body, and never less than MIN_DECODE_CHARS. Past it the body
# is refused whole with DecodedTooLarge.
DECODE_CHARS_PER_BYTE = 8
MIN_DECODE_CHARS = 4 * MAX_VALUE_CHARS

# How long a name-matched attribute has to be before the name stops
# deciding. A session id, a byte count and a duration are all short; four
# hundred characters under a key called `prompt_id` is content whatever it
# is called.
IDENTITY_MAX_CHARS = 96

KIND_LOG = "log"
KIND_SPAN = "span"

# Which OTLP signal a body carries. This is NOT inferable from the bytes:
# ExportLogsServiceRequest.resource_logs and
# ExportTraceServiceRequest.resource_spans are both field 1, and the
# collision continues all the way down -- scope_logs and scope_spans are
# both 2, log_records and spans are both 2. A logs body read as traces
# decodes into phantom spans with garbage names rather than failing. The
# request path is the only thing that knows, so the caller must say.
SIGNAL_LOGS = "logs"
SIGNAL_TRACES = "traces"
# Not decoded into records -- see metric_names() -- but named here so the
# collector can route it rather than 404.
SIGNAL_METRICS = "metrics"

# Correlation a span event inherits from its span. NOT content: copying
# `tool.input` down would scan the same text twice and report two findings
# where the user typed one value. Without this, an office agent turn split
# into one record for the span and one for each of its events, because the
# events carry the content and the span carries the identity.
INHERITED_KEYS = (
    "session.id",
    "prompt.id",
    "user.email",
    "user.account_uuid",
    "user.id",
    "model",
)


class DecodeError(ValueError):
    """The body was not OTLP we could read."""


class UnsupportedEncoding(Exception):
    """A Content-Encoding other than gzip or identity."""


class InflatedTooLarge(Exception):
    """The body decompresses to more than its limit. Raised as the
    decompression passes it, so the rest is not decompressed."""


# Content-Encoding values `inflate` reads.
ENCODINGS = ("gzip", "x-gzip", "identity")


def inflate(body: bytes, encoding: str, limit: int) -> bytes:
    """`body` with its Content-Encoding undone, at most `limit` bytes.

    Every member of a multi-member gzip body is read. Raises
    UnsupportedEncoding for an encoding not in ENCODINGS (a list of
    encodings included), InflatedTooLarge past `limit`, and DecodeError for
    a body that is not gzip, is cut short or has bytes after its last
    member.
    """
    name = (encoding or "").strip().lower()
    if name in ("", "identity"):
        return body
    if name not in ENCODINGS:
        raise UnsupportedEncoding(name)
    out: list[bytes] = []
    total = 0
    data = body
    while True:
        member = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            chunk = member.decompress(data, limit - total + 1)
        except zlib.error:
            raise DecodeError("not gzip") from None
        total += len(chunk)
        if total > limit:
            raise InflatedTooLarge()
        out.append(chunk)
        if not member.eof:
            raise DecodeError("gzip body cut short")
        data = member.unused_data
        if not data:
            return b"".join(out)


@dataclass
class OtelRecord:
    """One log record, span, or span event, flattened.

    `resource` is kept separate from `attributes` because identity lives
    there for some senders and in the record for others, and merging them
    would make it impossible to say which one claimed the org.
    """

    kind: str
    name: str = ""
    attributes: dict[str, str] = field(default_factory=dict)
    resource: dict[str, str] = field(default_factory=dict)

    def get(self, *keys: str) -> str | None:
        """First present value across attributes then resource."""
        for key in keys:
            value = self.attributes.get(key) or self.resource.get(key)
            if value:
                return value
        return None


def decode(body: bytes, content_type: str, signal: str) -> list[OtelRecord]:
    """OTLP body -> records. Raises DecodeError on anything unreadable,
    TooManyRecords past MAX_RECORDS and DecodedTooLarge past the body's
    decode budget."""
    if signal not in (SIGNAL_LOGS, SIGNAL_TRACES):
        raise DecodeError(f"unknown signal: {signal}")
    ctype = (content_type or "").split(";")[0].strip().lower()
    try:
        if ctype in ("application/x-protobuf", "application/protobuf"):
            return _decode_protobuf(body, signal)
        if ctype == "application/json" or not ctype:
            return _decode_json(body, signal)
    except RecursionError as exc:
        # `json.loads` recurses once per level of nesting.
        raise DecodeError("nested too deeply") from exc
    except (AttributeError, TypeError) as exc:
        # A node of a type the walk does not expect. Named by type only:
        # the message can quote the value.
        raise DecodeError(f"unexpected shape: {type(exc).__name__}") from None
    raise DecodeError(f"unsupported content-type: {ctype}")


class _Budget:
    """Characters left to render for one body."""

    __slots__ = ("left",)

    def __init__(self, chars: int) -> None:
        self.left = chars

    @classmethod
    def for_body(cls, body: bytes) -> _Budget:
        return cls(max(DECODE_CHARS_PER_BYTE * len(body), MIN_DECODE_CHARS))

    def charge(self, chars: int) -> None:
        self.left -= chars
        if self.left < 0:
            raise DecodedTooLarge()


def _keep(out: list[OtelRecord], records: list[OtelRecord]) -> None:
    """Append `records`, or raise TooManyRecords if that passes the cap."""
    if len(out) + len(records) > MAX_RECORDS:
        raise TooManyRecords(MAX_RECORDS)
    out.extend(records)


# --- JSON -----------------------------------------------------------------


def _decode_json(body: bytes, signal: str) -> list[OtelRecord]:
    try:
        doc = load_json(body.decode("utf-8", "replace") or "{}")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError(f"invalid json: {exc}") from exc
    if not isinstance(doc, dict):
        raise DecodeError("top level of an OTLP body is an object")

    budget = _Budget.for_body(body)
    out: list[OtelRecord] = []
    if signal == SIGNAL_LOGS:
        for group in _dicts(doc, "resourceLogs", "resource_logs"):
            resource = _json_attrs(group.get("resource"), budget)
            for scope in _dicts(group, "scopeLogs", "scope_logs"):
                for rec in _dicts(scope, "logRecords", "log_records"):
                    _keep(out, [_json_log(rec, resource, budget)])
        return out

    for group in _dicts(doc, "resourceSpans", "resource_spans"):
        resource = _json_attrs(group.get("resource"), budget)
        for scope in _dicts(group, "scopeSpans", "scope_spans"):
            for span in _dicts(scope, "spans"):
                _keep(out, _json_span(span, resource, budget))
    return out


def _dicts(node: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    """The objects in the lists under `keys` of `node`, in order; any other
    item is left out."""
    return [item for key in keys for item in _as_list(node.get(key))
            if isinstance(item, dict)]


def _json_log(rec: dict[str, Any], resource: dict[str, str], budget: _Budget) -> OtelRecord:
    attrs = _json_attrs(rec, budget)
    # The body of a log record carries content for some emitters and a bare
    # event name for others. It is kept under the reserved key `_body`; a
    # sender attribute of that name is dropped so it cannot stand in for it.
    attrs.pop("_body", None)
    body = _any_value(rec.get("body"), budget)
    if body:
        attrs["_body"] = body
    name = (
        attrs.get("event.name")
        or rec.get("eventName")
        or rec.get("event_name")
        or ""
    )
    return OtelRecord(KIND_LOG, str(name), attrs, resource)


def _json_span(span: dict[str, Any], resource: dict[str, str],
               budget: _Budget) -> list[OtelRecord]:
    parent = _json_attrs(span, budget)
    out = [OtelRecord(KIND_SPAN, str(span.get("name") or ""), parent, resource)]
    # Span events carry the content on the office agents; a span with none
    # of its events would report the turn happened and nothing about it.
    for event in _as_list(span.get("events")):
        if isinstance(event, dict):
            child = _inherit(_json_attrs(event, budget), parent)
            # The parent's name, recorded on the child. Adapter 5's
            # `drop_events` matches a record's own name, so cutting a turn
            # by naming the span dropped the SPAN and forwarded its
            # events -- and the events are where the office agents put the
            # content, with the parent's identity keys inherited onto
            # them. An operator cutting `agent.query` kept the record that
            # actually carried tool.output.
            parent_name = str(span.get("name") or "")
            if parent_name:
                child.setdefault("forgd.parent_span", parent_name)
            out.append(
                OtelRecord(
                    KIND_SPAN,
                    str(event.get("name") or span.get("name") or ""),
                    child,
                    resource,
                )
            )
    return out


def _inherit(child: dict[str, str], parent: dict[str, str]) -> dict[str, str]:
    """`child` with each INHERITED_KEYS value of `parent` it lacks, skipping
    any that is not a string of at most IDENTITY_MAX_CHARS."""
    for key in INHERITED_KEYS:
        value = parent.get(key)
        if value and isinstance(value, str) and len(value) <= IDENTITY_MAX_CHARS:
            child.setdefault(key, value)
    return child


# OURS, AND ONLY OURS. Every attribute we add on the way through is
# `forgd.`-prefixed, and both decoders drop a sender-supplied key in that
# namespace before anything reads it.
#
# Without this the prefix is a claim, not a fact. `forgd.parent_span` is
# written with setdefault and READ BACK by adapter 5 to decide whether an
# event belongs to a dropped turn -- so a sender setting it to a name
# nobody dropped kept its own event on the wire, with the parent span's
# identity keys inherited onto it, while the honest path dropped both. It
# is also in IDENTITY_KEYS as "ours, not the sender's", which holds only
# because of this.
#
# Reserved at the boundary rather than defended at each use: there is one
# place to get this right, and every later reader gets to assume it.
RESERVED_PREFIX = "forgd."


# The path suffix of a kvlist key's leaf.
KEY_SUFFIX = "#key"


class StructuredValue(str):
    """An array or kvlist value rendered as JSON text.

    `leaves` holds (path, text) for each scalar the rendering read, in
    document order: `[i]` per array element or kvlist entry, nested, and
    `[i]#key` for a kvlist entry's key. A bool is left out.
    """

    leaves: tuple[tuple[str, str], ...] = ()


class CappedValue(StructuredValue):
    """An attribute value cut to MAX_VALUE_CHARS. The string is the head.

    `tail` is the end of the original value and `gap` the number of
    characters between the head and the tail that were discarded.
    """

    tail: str = ""
    gap: int = 0


def _cap(text: str, cut: list[bool]) -> str:
    """`text` as a CappedValue when it is over MAX_VALUE_CHARS, or when an
    array or kvlist inside it was cut short (`cut` is not empty)."""
    head, tail, gap = head_and_tail(text, MAX_VALUE_CHARS, TAIL_VALUE_CHARS)
    if not tail and not cut:
        return text
    out = CappedValue(head)
    out.tail, out.gap = tail, gap or (1 if cut else 0)
    return out


def _fitted(text: str, limit: int, cut: list[bool], budget: _Budget) -> str | None:
    """`json.dumps(text)` if it is at most `limit` long; otherwise the
    encoding of the longest head of `text` that is, with `cut` set. None
    when not even an empty string fits. Every encoding made is charged to
    `budget`."""
    if limit < 2:
        cut.append(True)
        return None
    head = text[:limit - 2]
    enc = json.dumps(head)
    budget.charge(len(enc))
    if len(enc) > limit:
        head = head[:len(head) * limit // len(enc)]
        enc = json.dumps(head)
        budget.charge(len(enc))
    over = len(enc) - limit
    if over > 0:
        # Each character encodes to at least one, so dropping `over` of
        # them is enough.
        head = head[:len(head) - over]
        enc = json.dumps(head)
        budget.charge(len(enc))
    if len(head) < len(text):
        cut.append(True)
    return enc


def _json_array(children: Iterable[Any], render: Callable[[Any, int], str],
                room: int, cut: list[bool], budget: _Budget, *,
                skip_empty: bool = False) -> str:
    """`json.dumps` of the rendered children, never longer than `room`.

    `render(child, avail)` returns the child's text and keeps any array or
    kvlist inside it within `avail`. Children are encoded one at a time.
    The first that does not fit is cut to the room left, the rest are
    dropped, and `cut` is set. The output is byte-identical to
    `json.dumps(list)` when everything fits.
    """
    parts: list[str] = []
    used = 2
    for child in children:
        sep = 2 if parts else 0
        limit = room - used - sep
        text = render(child, max(limit - 2, 0))
        if skip_empty and not text:
            continue
        before = len(cut)
        enc = _fitted(text, limit, cut, budget)
        if enc is not None:
            parts.append(enc)
            used += sep + len(enc)
        if len(cut) > before:
            break
    return "[" + ", ".join(parts) + "]"


def _json_object(pairs: Iterable[tuple[str, Any]], render: Callable[[Any, int], str],
                 room: int, cut: list[bool], budget: _Budget,
                 on_key: Callable[[str, Any], Any] | None = None) -> str:
    """`json.dumps` of `{key: rendered child}`, never longer than `room`.

    A repeated key keeps its first position and takes the last value, as a
    dict does. Otherwise as `_json_array`. `on_key(key, child)` is called
    for each key rendered.
    """
    entries: dict[str, tuple[str, str]] = {}
    used = 2
    for key, child in pairs:
        old = entries.get(key)
        if old is not None:
            ekey, base = old[0], used - len(old[1])
        else:
            sep = 2 if entries else 0
            key_cut: list[bool] = []
            ekey = _fitted(key, room - used - sep - 4, key_cut, budget)
            if ekey is None or key_cut:
                cut.append(True)
                break
            base = used + sep + len(ekey) + 2
        if on_key is not None:
            on_key(key, child)
        limit = room - base
        text = render(child, max(limit - 2, 0))
        before = len(cut)
        enc = _fitted(text, limit, cut, budget)
        if enc is not None:
            entries[key] = (ekey, enc)
            used = base + len(enc)
        if len(cut) > before:
            break
    return "{" + ", ".join(f"{k}: {v}" for k, v in entries.values()) + "}"


def _json_attrs(node: Any, budget: _Budget) -> dict[str, str]:
    if not isinstance(node, dict):
        return {}
    out: dict[str, str] = {}
    for item in _as_list(node.get("attributes")):
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if not isinstance(key, str) or key.startswith(RESERVED_PREFIX):
            continue
        value = _any_value(item.get("value"), budget)
        if value:
            out[key] = value
    return out


def _any_value(node: Any, budget: _Budget | None = None) -> str:
    """OTLP AnyValue -> str, capped. Non-strings are stringified, not dropped.
    Without `budget`, nothing is charged."""
    if budget is None:
        budget = _Budget(sys.maxsize)
    cut: list[bool] = []
    leaves: list[tuple[str, str]] = []
    text = _any_text(node, 0, cut, MAX_VALUE_CHARS, budget, leaves)
    budget.charge(len(text))
    return _structured(_cap(text, cut), leaves)


def _structured(value: str, leaves: list[tuple[str, str]]) -> str:
    """`value` carrying `leaves`, as a StructuredValue, when there are any."""
    if not leaves:
        return value
    if not isinstance(value, StructuredValue):
        value = StructuredValue(value)
    value.leaves = tuple(leaves)
    return value


def _leaf(leaves: list[tuple[str, str]] | None, depth: int, path: str, text: str) -> str:
    """Record `text` at `path` in `leaves` when inside an array or kvlist."""
    if leaves is not None and depth > 0 and text:
        leaves.append((path, text))
    return text


def _raw_leaves(node: Any, depth: int, path: str, leaves: list[tuple[str, str]]) -> None:
    """The scalars of a plain JSON list or object, as `_leaf` records them."""
    if depth > MAX_DEPTH:
        return
    if isinstance(node, list):
        for i, child in enumerate(node):
            _raw_leaves(child, depth + 1, f"{path}[{i}]", leaves)
    elif isinstance(node, dict):
        for i, (key, child) in enumerate(node.items()):
            _leaf(leaves, depth + 1, f"{path}[{i}]{KEY_SUFFIX}", str(key))
            _raw_leaves(child, depth + 1, f"{path}[{i}]", leaves)
    elif isinstance(node, str):
        _leaf(leaves, depth, path, node)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        _leaf(leaves, depth, path, str(node))


def _any_text(node: Any, depth: int, cut: list[bool], room: int, budget: _Budget,
              leaves: list[tuple[str, str]] | None = None, path: str = "") -> str:
    """`_any_value` before the cap. An array or kvlist is kept within
    `room`; a string is returned whole. Each scalar inside an array or
    kvlist is added to `leaves` at its path."""
    if depth > MAX_DEPTH:
        cut.append(True)
        return ""
    if node is None:
        return ""
    if isinstance(node, str):
        return _leaf(leaves, depth, path, node)
    if isinstance(node, bool):
        return "true" if node else "false"
    if isinstance(node, (int, float)):
        return _leaf(leaves, depth, path, str(node))
    if isinstance(node, list):
        text = json.dumps(node)
        budget.charge(len(text))
        if leaves is not None:
            _raw_leaves(node, depth, path, leaves)
        return text
    if not isinstance(node, dict):
        return ""
    for key in ("stringValue", "string_value"):
        if key in node:
            return _leaf(leaves, depth, path, str(node[key]))
    for key in ("intValue", "int_value", "doubleValue", "double_value"):
        if key in node:
            return _leaf(leaves, depth, path, str(node[key]))
    for key in ("boolValue", "bool_value"):
        if key in node:
            return "true" if node[key] else "false"
    for key in ("bytesValue", "bytes_value"):
        if key in node:
            return _leaf(leaves, depth, path, str(node[key]))
    for key in ("arrayValue", "array_value"):
        if key in node:
            values = _as_list(_as_dict(node[key]).get("values"))
            return _json_array(
                enumerate(values),
                lambda iv, r: _any_text(iv[1], depth + 1, cut, r, budget, leaves,
                                        f"{path}[{iv[0]}]"),
                room, cut, budget)
    for key in ("kvlistValue", "kvlist_value"):
        if key in node:
            pairs = _as_list(_as_dict(node[key]).get("values"))
            entries = [(str(p.get("key")), (i, p.get("value")))
                       for i, p in enumerate(pairs) if isinstance(p, dict)]
            return _json_object(
                entries,
                lambda iv, r: _any_text(iv[1], depth + 1, cut, r, budget, leaves,
                                        f"{path}[{iv[0]}]"),
                room, cut, budget,
                on_key=lambda k, iv: _leaf(leaves, depth + 1, f"{path}[{iv[0]}]{KEY_SUFFIX}", k))
    return ""


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


# --- protobuf -------------------------------------------------------------
#
# Wire format, all we need of it: each field is a varint tag carrying
# (field_number << 3 | wire_type), then a payload whose length depends on the
# wire type. We only ever read length-delimited (2) submessages and strings,
# and skip everything else.
#
# Field numbers, from opentelemetry-proto v1. These are frozen by protobuf's
# own compatibility rules -- a field number cannot be reused for a different
# meaning -- which is what makes hardcoding them safe in a way that
# hardcoding attribute NAMES is not.
_F_RESOURCE_LOGS = 1  # ExportLogsServiceRequest.resource_logs
_F_RESOURCE_SPANS = 1  # ExportTraceServiceRequest.resource_spans
_F_RESOURCE = 1  # Resource{Logs,Spans}.resource
_F_SCOPE_LOGS = 2  # ResourceLogs.scope_logs
_F_SCOPE_SPANS = 2  # ResourceSpans.scope_spans
_F_LOG_RECORDS = 2  # ScopeLogs.log_records
_F_SPANS = 2  # ScopeSpans.spans
_F_ATTRIBUTES = 1  # Resource.attributes
_F_LOG_BODY = 5  # LogRecord.body
_F_LOG_ATTRS = 6  # LogRecord.attributes
_F_LOG_EVENT_NAME = 12  # LogRecord.event_name
_F_SPAN_NAME = 5  # Span.name
_F_SPAN_ATTRS = 9  # Span.attributes
_F_SPAN_EVENTS = 11  # Span.events
_F_EVENT_NAME = 2  # Span.Event.name
_F_EVENT_ATTRS = 3  # Span.Event.attributes
_F_KV_KEY = 1  # KeyValue.key
_F_KV_VALUE = 2  # KeyValue.value

_WIRE_VARINT = 0
_WIRE_64 = 1
_WIRE_LEN = 2
_WIRE_32 = 5


def _walk(buf: bytes) -> Iterator[tuple[int, int, Any]]:
    """(field_number, wire_type, value) for each field, at most MAX_FIELDS.
    Length-delimited -> bytes."""
    i, n = 0, len(buf)
    count = 0
    while i < n:
        count += 1
        if count > MAX_FIELDS:
            raise DecodeError(f"more than {MAX_FIELDS} fields in one message")
        tag, i = _varint(buf, i)
        field_no, wire = tag >> 3, tag & 0x07
        if wire == _WIRE_VARINT:
            value, i = _varint(buf, i)
        elif wire == _WIRE_64:
            value, i = buf[i : i + 8], i + 8
        elif wire == _WIRE_LEN:
            length, i = _varint(buf, i)
            if length < 0 or i + length > n:
                raise DecodeError("length-delimited field runs past the buffer")
            value, i = buf[i : i + length], i + length
        elif wire == _WIRE_32:
            value, i = buf[i : i + 4], i + 4
        else:
            # Groups (3, 4) were removed from proto3. Anything here means we
            # are not reading what we think we are; stop rather than guess.
            raise DecodeError(f"unsupported wire type {wire}")
        yield field_no, wire, value


def _fields(buf: bytes) -> list[tuple[int, int, Any]]:
    """`_walk` as a list, for a message read more than once."""
    return list(_walk(buf))


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if i >= len(buf):
            raise DecodeError("truncated varint")
        if shift > 63:
            raise DecodeError("varint too long")
        byte = buf[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, i
        shift += 7


def _sub(fields: Iterable[tuple[int, int, Any]], field_no: int) -> list[bytes]:
    return [v for f, w, v in fields if f == field_no and w == _WIRE_LEN]


def _text(fields: list[tuple[int, int, Any]], field_no: int) -> str:
    for value in _sub(fields, field_no):
        return value.decode("utf-8", "replace")[:MAX_VALUE_CHARS]
    return ""


def _pb_attrs(blobs: list[bytes], budget: _Budget) -> dict[str, str]:
    out: dict[str, str] = {}
    for blob in blobs:
        kv = _fields(blob)
        key = _text(kv, _F_KV_KEY)
        if not key or key.startswith(RESERVED_PREFIX):
            continue
        values = _sub(kv, _F_KV_VALUE)
        out[key] = _pb_any(values[0], budget) if values else ""
    return out


def _pb_any(blob: bytes, budget: _Budget | None = None) -> str:
    """AnyValue, capped. Field 1 is the string case and covers everything we
    scan. Without `budget`, nothing is charged."""
    if budget is None:
        budget = _Budget(sys.maxsize)
    cut: list[bool] = []
    leaves: list[tuple[str, str]] = []
    text = _pb_text(blob, 0, cut, MAX_VALUE_CHARS, budget, leaves)
    budget.charge(len(text))
    return _structured(_cap(text, cut), leaves)


def _pb_text(blob: bytes, depth: int, cut: list[bool], room: int, budget: _Budget,
             leaves: list[tuple[str, str]] | None = None, path: str = "") -> str:
    """`_pb_any` before the cap. An array or kvlist is kept within `room`;
    a string is returned whole. Leaves as `_any_text`."""
    if depth > MAX_DEPTH:
        cut.append(True)
        return ""
    for field_no, wire, value in _walk(blob):
        if field_no == 1 and wire == _WIRE_LEN:  # string_value
            return _leaf(leaves, depth, path, value.decode("utf-8", "replace"))
        if field_no == 2 and wire == _WIRE_VARINT:  # bool_value
            return "true" if value else "false"
        if field_no == 3 and wire == _WIRE_VARINT:  # int_value
            return _leaf(leaves, depth, path, str(value))
        if field_no == 7 and wire == _WIRE_LEN:  # bytes_value
            return _leaf(leaves, depth, path, value.decode("utf-8", "replace"))
        if field_no == 5 and wire == _WIRE_LEN:  # array: AnyValue entries
            return _json_array(
                enumerate(_sub(_walk(value), 1)),
                lambda ib, r: _pb_text(ib[1], depth + 1, cut, r, budget, leaves,
                                       f"{path}[{ib[0]}]"),
                room, cut, budget, skip_empty=True)
        if field_no == 6 and wire == _WIRE_LEN:  # kvlist: KeyValue entries
            return _json_object(
                ((k, (i, b)) for i, (k, b) in enumerate(_pb_entries(value))),
                lambda ib, r: "" if ib[1] is None else _pb_text(
                    ib[1], depth + 1, cut, r, budget, leaves, f"{path}[{ib[0]}]"),
                room, cut, budget,
                on_key=lambda k, ib: _leaf(leaves, depth + 1, f"{path}[{ib[0]}]{KEY_SUFFIX}", k))
    return ""


def _pb_entries(kvlist: bytes) -> Iterator[tuple[str, bytes | None]]:
    """(key, AnyValue blob or None) for each KeyValue in a KeyValueList."""
    for entry in _sub(_walk(kvlist), 1):
        kv = _fields(entry)
        values = _sub(kv, _F_KV_VALUE)
        yield _text(kv, _F_KV_KEY), (values[0] if values else None)


def _decode_protobuf(body: bytes, signal: str) -> list[OtelRecord]:
    try:
        top = _fields(body)
    except DecodeError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        raise DecodeError(f"undecodable protobuf: {exc}") from exc

    budget = _Budget.for_body(body)
    out: list[OtelRecord] = []
    # Field 1 either way -- see SIGNAL_LOGS. `signal` decides which schema
    # these bytes are read against; reading both would double-count every
    # body and invent a record that never happened.
    for group_blob in _sub(top, _F_RESOURCE_LOGS):
        group = _fields(group_blob)
        resource = _pb_resource(group, budget)
        if signal == SIGNAL_LOGS:
            for scope_blob in _sub(group, _F_SCOPE_LOGS):
                for rec_blob in _sub(_walk(scope_blob), _F_LOG_RECORDS):
                    record = _pb_log(_fields(rec_blob), resource, budget)
                    if _usable(record.name, record.attributes):
                        _keep(out, [record])
            continue
        for scope_blob in _sub(group, _F_SCOPE_SPANS):
            for span_blob in _sub(_walk(scope_blob), _F_SPANS):
                _keep(out, [
                    r
                    for r in _pb_span(_fields(span_blob), resource, budget)
                    if _usable(r.name, r.attributes)
                ])
    return out


def _usable(name: str, attributes: dict[str, str]) -> bool:
    """Is this a record, or the wrong schema read through the right one?

    `signal` stops a body being decoded twice, but it cannot stop a
    MISROUTED body being decoded once: a logs payload posted to /v1/traces
    still finds field 2 where spans live and produces one record whose
    "name" is raw submessage bytes. Requiring a record to carry either
    attributes or a printable name drops those without needing to guess at
    the sender's intent.
    """
    if attributes:
        return True
    return bool(name) and name.isprintable()


def _pb_log(rec: list[tuple[int, int, Any]], resource: dict[str, str],
            budget: _Budget) -> OtelRecord:
    attrs = _pb_attrs(_sub(rec, _F_LOG_ATTRS), budget)
    attrs.pop("_body", None)
    bodies = _sub(rec, _F_LOG_BODY)
    if bodies:
        body_text = _pb_any(bodies[0], budget)
        if body_text:
            attrs["_body"] = body_text
    name = attrs.get("event.name") or _text(rec, _F_LOG_EVENT_NAME)
    return OtelRecord(KIND_LOG, name, attrs, resource)


def _pb_span(
    span: list[tuple[int, int, Any]], resource: dict[str, str], budget: _Budget
) -> list[OtelRecord]:
    name = _text(span, _F_SPAN_NAME)
    parent = _pb_attrs(_sub(span, _F_SPAN_ATTRS), budget)
    out = [OtelRecord(KIND_SPAN, name, parent, resource)]
    for event_blob in _sub(span, _F_SPAN_EVENTS):
        event = _fields(event_blob)
        child = _inherit(_pb_attrs(_sub(event, _F_EVENT_ATTRS), budget), parent)
        # Same as the JSON path; a test asserts the two decoders agree.
        if name:
            child.setdefault("forgd.parent_span", name)
        out.append(
            OtelRecord(
                KIND_SPAN,
                _text(event, _F_EVENT_NAME) or name,
                child,
                resource,
            )
        )
    return out


def _pb_resource(group: list[tuple[int, int, Any]], budget: _Budget) -> dict[str, str]:
    for blob in _sub(group, _F_RESOURCE):
        return _pb_attrs(_sub(_walk(blob), _F_ATTRIBUTES), budget)
    return {}


# --- metrics --------------------------------------------------------------
#
# Metrics are NOT decoded into records and never scanned. An OTLP metric
# carries measurements and attribute keys, not message content, so there is
# nothing for a detector to find -- and decoding a third signal shape to
# discard it would be work that buys nothing.
#
# The NAMES are worth keeping. Anthropic's exporter sends every enabled
# signal to the same base endpoint, so metrics arrive whether or not anyone
# asked for them; knowing which ones is how you decide what is worth
# reporting on, and it is the difference between "nothing is being sent"
# and "something is, and we are dropping it on the floor".
#
# Best effort by design: a body that will not parse yields no names rather
# than an error, because rejecting a metrics batch would make an exporter
# retry forever over something we do not use.


def metric_names(body: bytes, content_type: str) -> list[str]:
    """Metric names in an OTLP metrics body. Never raises."""
    ctype = (content_type or "").split(";")[0].strip().lower()
    try:
        if ctype in ("application/x-protobuf", "application/protobuf"):
            return _metric_names_protobuf(body)
        return _metric_names_json(body)
    except Exception:  # noqa: BLE001 - diagnostics must not break ingest
        return []


def _metric_names_json(body: bytes) -> list[str]:
    doc = load_json(body.decode("utf-8", "replace") or "{}")
    out: list[str] = []
    for rm in _as_list(doc.get("resourceMetrics")):
        for sm in _as_list(rm.get("scopeMetrics")):
            for m in _as_list(sm.get("metrics")):
                name = m.get("name")
                if isinstance(name, str) and name:
                    out.append(name)
    return out


def _metric_names_protobuf(body: bytes) -> list[str]:
    """resource_metrics(1) -> scope_metrics(2) -> metrics(2) -> name(1)."""
    out: list[str] = []
    for f1, _w1, rm in _walk(body):
        if f1 != 1 or not isinstance(rm, bytes):
            continue
        for f2, _w2, sm in _walk(rm):
            if f2 != 2 or not isinstance(sm, bytes):
                continue
            for f3, _w3, metric in _walk(sm):
                if f3 != 2 or not isinstance(metric, bytes):
                    continue
                for f4, _w4, value in _walk(metric):
                    if f4 == 1 and isinstance(value, bytes):
                        out.append(value.decode("utf-8", "replace"))
                        break
    return out
