"""Incremental session scanning.

Prompt frames carry the cumulative transcript, so naive rescanning makes an
agentic session O(n^2) in bytes. The cache records how much of a session has
already been scanned, plus the findings from that prefix, and a new frame is
scanned only past the high-water mark.

Validating the prefix is the subtle part. The docs note that "a turn whose
every block is excluded is omitted entirely", so message indices are not
guaranteed stable across frames of the same session. A bare message count
would silently skip a shifted message. Instead the cache stores a cheap shape
signature per scanned message (block count and per-block text lengths) plus a
digest of the first message, and falls back to a full rescan on any mismatch.
The shape check is O(messages), not O(bytes).

Correctness never depends on the cache: every path degrades to a full rescan.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Protocol

from .models import Finding


def _block_bytes(block: dict) -> bytes:
    """The whole block, for the shape digest.

    Every field, because extraction scans fields beyond `text`, `content`
    and `input` (a `caption`, for one), and a field left out of the digest
    could be edited without the cache noticing.
    """
    return json.dumps(block, sort_keys=True, default=str).encode("utf-8", "replace")


def message_shape(message: Any) -> tuple:
    """Structural signature of one message, including a content digest.

    It was LENGTHS ONLY, and lengths do not change under an in-place
    edit. Two frames of one session where an already-scanned message was
    rewritten at identical length, with the transcript growing, resumed
    past it and never rescanned:

        frame1  "note XXXXXXXXXXXXXXXXXXXX end"   allow
        frame2  "note AKIAIOSFODNN7EXAMPLE end"   cache_hit, scanned 1, allow

    A dict `input` is worse: `json.dumps(sort_keys=True)` sizing is a
    total, so the value AND the key set can both change at a constant
    size.

    The transcript is client-asserted -- `session_id` is best-effort and
    client-asserted for Claude Code, and the platform marks prior turns
    unverified -- so nothing upstream guarantees message `i` is what it
    was last frame.

    Hashing costs about a millisecond per megabyte against the hundreds
    of milliseconds of detector work the cache exists to skip, so
    "correctness never depends on the cache" is affordable to mean.
    """
    if not isinstance(message, dict):
        return ("?",)
    content = message.get("content")
    role = message.get("role")
    if isinstance(content, str):
        return (role, "s", len(content), _sha(content.encode("utf-8", "replace")))
    if not isinstance(content, list):
        return (role, "n")
    parts: list[Any] = []
    for block in content:
        if isinstance(block, str):
            # Extraction scans a bare string block, so it is fingerprinted.
            raw = block.encode("utf-8", "replace")
            parts.append(("s", len(raw), _sha(raw)))
            continue
        if not isinstance(block, dict):
            raw = json.dumps(block, sort_keys=True, default=str).encode("utf-8", "replace")
            parts.append(("?", len(raw), _sha(raw)))
            continue
        raw = _block_bytes(block)
        parts.append((block.get("type"), len(raw), _sha(raw)))
    return (role, tuple(parts))


def _sha(raw: bytes) -> str:
    """Truncated: this is a change detector, not a credential store, and a
    128-bit prefix makes an accidental collision impossible in practice."""
    return hashlib.sha256(raw).hexdigest()[:32]


def head_digest(messages: list[Any]) -> str:
    if not messages:
        return ""
    return hashlib.sha256(
        json.dumps(messages[0], sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


@dataclass
class SessionState:
    scanned_messages: int = 0
    shapes: list[tuple] = field(default_factory=list)
    head: str = ""
    findings: list[Finding] = field(default_factory=list)
    expires_at: float = 0.0


class SessionCache(Protocol):
    """Swap for a Redis-backed implementation without touching the core."""

    def get(self, key: tuple[str | None, str | None]) -> SessionState | None: ...
    def put(self, key: tuple[str | None, str | None], state: SessionState) -> None: ...
    def stats(self) -> dict[str, int]: ...


class InMemoryLRUCache:
    """Process-local LRU with TTL. Cold start is a full scan, by design."""

    def __init__(self, max_sessions: int = 5000, ttl_s: float = 86400.0):
        self._max = max_sessions
        self._ttl = ttl_s
        self._data: OrderedDict[tuple, SessionState] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key: tuple[str | None, str | None]) -> SessionState | None:
        if key[1] is None:
            # No session_id: every frame is independent. Not a cache miss to
            # report, just an uncacheable request.
            return None
        now = time.monotonic()
        with self._lock:
            state = self._data.get(key)
            if state is None:
                self._misses += 1
                return None
            if state.expires_at <= now:
                del self._data[key]
                self._misses += 1
                return None
            self._data.move_to_end(key)
            self._hits += 1
            return state

    def put(self, key: tuple[str | None, str | None], state: SessionState) -> None:
        if key[1] is None:
            return
        state.expires_at = time.monotonic() + self._ttl
        with self._lock:
            self._data[key] = state
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)
                self._evictions += 1

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "sessions": len(self._data),
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
            }


def resume_point(state: SessionState | None, messages: list[Any]) -> int:
    """How many leading messages can be trusted as already scanned.

    Returns 0 (full rescan) when there is no state, the transcript shrank,
    the head message changed, or any scanned message's shape moved.
    """
    if state is None or state.scanned_messages == 0:
        return 0
    n = state.scanned_messages
    if len(messages) < n:
        return 0  # transcript shrank: client reset or compacted
    if head_digest(messages) != state.head:
        return 0
    for i in range(n):
        if message_shape(messages[i]) != state.shapes[i]:
            return 0
    return n
