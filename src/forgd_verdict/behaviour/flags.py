"""Per-session flags: a post-hoc check's verdict that a session should be
stopped, and the verdict server's read of it.

A flag is a state object named by a salted digest of the session id,
holding the reason code, which check set it and when. The Compliance
scanner writes one when the judge or the tool baseline flags a session.
The verdict server reads it, through a cache, for each frame of a session
and, with `behaviour.flags.enabled`, reports `flag:session-flagged` at
`behaviour.flags.severity`; at `block` the session's frames are denied
from the first one read after the flag is written. A flag found is cached
for `CACHE_S`, an absent one for `MISS_CACHE_S`, so a flag takes effect
within `MISS_CACHE_S` of its write.

A flag object is not removed when it expires; a storage lifecycle rule on
`state/session-flag-` removes old ones (docs/SERVER.md).

The verdict server sees the inference hook's `session_id`, and the
Compliance API its own session ids. A flag takes effect where the two are
the same value, which for Claude Code they are expected to be; nothing
checks it.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from ..models import Finding, digest

DETECTOR = "flag:session-flagged"
STATE_PREFIX = "session-flag-"
SOURCE_JUDGE = "judge"
SOURCE_BASELINE = "baseline"
DEFAULT_TTL_HOURS = 24
# How long the verdict server keeps a flag it found, and an absence.
CACHE_S = 60.0
MISS_CACHE_S = 5.0
MAX_CACHED = 10_000
# At most one warning per this many seconds for failed reads.
WARN_EVERY_S = 60.0

log = logging.getLogger(__name__)


def state_name(session_id: str, salt: str) -> str:
    return f"{STATE_PREFIX}{digest(session_id, salt or 'session-flags')}.json"


def write_flag(store: Any, session_id: str, salt: str, reason: str, source: str,
               now: datetime | None = None) -> None:
    moment = now or datetime.now(UTC)
    body = {"reason": reason, "source": source, "at": moment.strftime("%Y-%m-%dT%H:%M:%SZ")}
    store.put_state(state_name(session_id, salt), (json.dumps(body) + "\n").encode())


def fetch_flag(store: Any, session_id: str, salt: str, ttl_hours: int,
               now: datetime | None = None) -> dict[str, str] | None:
    """The flag on `session_id` when it is younger than `ttl_hours`, else
    None. A store read that fails raises."""
    blob = store.get_state(state_name(session_id, salt))
    try:
        flag = json.loads(blob) if blob else None
    except (ValueError, RecursionError):
        return None
    if not isinstance(flag, dict) or not isinstance(flag.get("reason"), str):
        return None
    return flag if live(flag, ttl_hours, now) else None


def live(flag: dict, ttl_hours: int, now: datetime | None = None) -> bool:
    """Whether `flag` is younger than `ttl_hours`."""
    try:
        at = datetime.strptime(str(flag.get("at")), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return False
    return (now or datetime.now(UTC)) - at <= timedelta(hours=ttl_hours)


def read_flag(store: Any, session_id: str, salt: str, ttl_hours: int,
              now: datetime | None = None) -> dict[str, str] | None:
    """`fetch_flag`, with a failed read as None."""
    try:
        return fetch_flag(store, session_id, salt, ttl_hours, now)
    except Exception:  # noqa: BLE001 - an unread flag stops nothing
        return None


class FlagReader:
    """The verdict server's view of the flags, cached per session."""

    def __init__(self, store: Any, salt: str, severity: str = "warn",
                 ttl_hours: int = DEFAULT_TTL_HOURS,
                 clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.store = store
        self.salt = salt
        self.severity = severity
        self.ttl_hours = ttl_hours
        self._clock = clock
        self._wall = wall
        self._cache: OrderedDict[str, tuple[float, dict | None]] = OrderedDict()
        self._lock = threading.Lock()
        self._warned_at: float | None = None
        self.read_errors = 0

    def finding(self, session_id: Any) -> Finding | None:
        """`flag:session-flagged` for a flagged session, else None."""
        if not isinstance(session_id, str) or not session_id:
            return None
        now = self._clock()
        with self._lock:
            hit = self._cache.get(session_id)
        if hit is not None and now - hit[0] < (CACHE_S if hit[1] else MISS_CACHE_S) \
                and (hit[1] is None or live(hit[1], self.ttl_hours, self._wall())):
            flag = hit[1]
        else:
            try:
                flag = fetch_flag(self.store, session_id, self.salt, self.ttl_hours,
                                  self._wall())
            except Exception as exc:  # noqa: BLE001 - an unread flag stops nothing
                flag = None
                self._warn(now, exc)
            with self._lock:
                self._cache[session_id] = (now, flag)
                self._cache.move_to_end(session_id)
                while len(self._cache) > MAX_CACHED:
                    self._cache.popitem(last=False)
        if flag is None:
            return None
        return Finding(detector=DETECTOR, severity=self.severity, locator="session",
                       excerpt_hash=digest(f"{flag.get('source')}:{flag['reason']}",
                                           self.salt))

    def _warn(self, now: float, exc: Exception) -> None:
        with self._lock:
            self.read_errors += 1
            if self._warned_at is not None and now - self._warned_at < WARN_EVERY_S:
                return
            self._warned_at = now
            count = self.read_errors
        log.warning("session flag check failed", extra={"fields": {
            "error": type(exc).__name__, "failed_reads": count}})


def reader_from_policy(policy: Any, store: Any) -> FlagReader | None:
    cfg = ((policy.raw.get("behaviour") or {}).get("flags") or {})
    if cfg.get("enabled") is not True or store is None:
        return None
    severity = str(cfg.get("severity") or "warn")
    ttl = cfg.get("ttl_hours", DEFAULT_TTL_HOURS)
    if severity not in ("warn", "block") or not isinstance(ttl, int) or not 1 <= ttl <= 720:
        raise ValueError("behaviour.flags.severity must be warn or block, and ttl_hours a "
                         "whole number of hours from 1 to 720")
    return FlagReader(store, policy.hash_salt, severity, ttl)
