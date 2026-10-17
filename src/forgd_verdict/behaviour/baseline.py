"""Cross-session baselines: an agent using a tool it has never used before.

For each surface and actor, the tools seen in that actor's earlier sessions
are kept as salted digests in a state object. Once the baseline holds
`min_sessions` distinct sessions, a session that calls a tool not in it is
flagged `new_tool` (`behaviour.flags`), and the tool joins the baseline
either way. A session the scanner reads again is not counted again: the
last `MAX_RECENT_SESSIONS` session digests are kept, and `min_sessions` is
at most that many, so the baseline is warm before a digest is dropped. An
actor whose sessions have called more than `MAX_TOOLS` distinct tools has
no usable baseline; it stops changing and flags nothing.
Run by the Compliance scanner with `behaviour.baseline.enabled`. No tool
name or session id is stored, only their digests.

The update is a read and a write with nothing between them to stop a second
writer; the one writer is the ingest CronJob, which runs with
`concurrencyPolicy: Forbid`. A failed read raises, so a baseline is never
replaced by an empty one because the store was briefly unreachable.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from ..models import digest

REASON_NEW_TOOL = "new_tool"
STATE_PREFIX = "behaviour-tools-"
DEFAULT_MIN_SESSIONS = 10
# Digests kept per surface and actor.
MAX_TOOLS = 500
# Session digests kept to recognise a session read again.
MAX_RECENT_SESSIONS = 200


def tools_in(messages: Sequence[Any]) -> set[str]:
    """The tool names a transcript's tool calls use."""
    out: set[str] = set()
    for msg in messages or []:
        content = msg.get("content") if isinstance(msg, dict) else None
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                name = block.get("tool_name") or block.get("name")
                if isinstance(name, str) and name:
                    out.add(name)
    return out


class ToolBaseline:
    def __init__(self, store: Any, salt: str, min_sessions: int = DEFAULT_MIN_SESSIONS):
        self.store = store
        self.salt = salt or "behaviour-baseline"
        self.min_sessions = min_sessions

    def _name(self, surface: str, actor: str) -> str:
        return f"{STATE_PREFIX}{digest(f'{surface}|{actor}', self.salt)}.json"

    def observe(self, surface: str | None, actor: str | None, session_id: str,
                tools: Iterable[str]) -> str | None:
        """REASON_NEW_TOOL when a warmed-up baseline lacks one of `tools`;
        records them either way. None for a session with no actor. A store
        read that fails raises."""
        if not actor:
            return None
        name = self._name(surface or "", actor)
        blob = self.store.get_state(name)
        try:
            data = json.loads(blob) if blob else {}
        except (ValueError, RecursionError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        known = set(data.get("tools") or [])
        recent = [r for r in data.get("recent") or [] if isinstance(r, str)]
        sessions = data.get("sessions") if isinstance(data.get("sessions"), int) else 0
        seen = {digest(t, self.salt) for t in tools}
        merged = known | seen
        if len(merged) > MAX_TOOLS:
            return None
        flagged = REASON_NEW_TOOL if sessions >= self.min_sessions and seen - known else None
        this = digest(session_id, self.salt)
        if this not in recent:
            sessions += 1
            recent = [*recent, this][-MAX_RECENT_SESSIONS:]
        self.store.put_state(name, (json.dumps({"sessions": sessions, "recent": recent,
                                                "tools": sorted(merged)}) + "\n").encode())
        return flagged


def from_policy(policy: Any, store: Any) -> ToolBaseline | None:
    cfg = ((policy.raw.get("behaviour") or {}).get("baseline") or {})
    if cfg.get("enabled") is not True or store is None:
        return None
    floor = cfg.get("min_sessions", DEFAULT_MIN_SESSIONS)
    if not isinstance(floor, int) or isinstance(floor, bool) \
            or not 1 <= floor <= MAX_RECENT_SESSIONS:
        raise ValueError("behaviour.baseline.min_sessions must be a whole number from 1 to "
                         f"{MAX_RECENT_SESSIONS}")
    return ToolBaseline(store, policy.hash_salt, floor)
