"""Verdict replay by webhook-id.

Anthropic retries exactly once, 100ms later, only on connection failure, and
the retry carries the same webhook-id and the same signature. If the first
attempt reached us and we simply lost the response, the retry must get the
same verdict without paying for a second scan.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any


class VerdictStore:
    def __init__(self, ttl_s: float = 900.0, max_entries: int = 10000):
        self._ttl = ttl_s
        self._max = max_entries
        self._data: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0

    def get(self, webhook_id: str | None) -> dict[str, Any] | None:
        if not webhook_id:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._data.get(webhook_id)
            if entry is None:
                return None
            expires, verdict = entry
            if expires <= now:
                del self._data[webhook_id]
                return None
            self._data.move_to_end(webhook_id)
            self.hits += 1
            return verdict

    def put(self, webhook_id: str | None, verdict: dict[str, Any]) -> None:
        if not webhook_id:
            return
        with self._lock:
            self._data[webhook_id] = (time.monotonic() + self._ttl, verdict)
            self._data.move_to_end(webhook_id)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
