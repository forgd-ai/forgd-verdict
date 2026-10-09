"""Latency and verdict counters, sliced by source.application.

Answers the question the live shadow run exists to answer: how much latency
does each Claude surface actually pay, and which surfaces show up at all.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Any

RESERVOIR = 4096
UNKNOWN_SOURCE = "unknown"
# Distinct source.application values kept apart, UNKNOWN_SOURCE included.
# Each holds three reservoirs, so a sender cycling the value would otherwise
# grow the process without bound; values past the cap are counted under
# UNKNOWN_SOURCE and in `source_apps_folded`.
MAX_SOURCE_APPS = 64


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * (pct / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=RESERVOIR))
        self._scan: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=RESERVOIR))
        self._bytes: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=RESERVOIR))
        self._counts: dict[tuple[str, str], int] = defaultdict(int)
        self._flags: dict[str, int] = defaultdict(int)

    def record(
        self,
        source_app: str,
        total_ms: float,
        scan_ms: float,
        body_bytes: int,
        action: str,
        *,
        cache_hit: bool = False,
        budget_exceeded: bool = False,
        findings: int = 0,
        tiers_dropped: bool = False,
        oversize_unscanned: bool = False,
    ) -> None:
        with self._lock:
            if source_app not in self._total and len(self._total) >= MAX_SOURCE_APPS - 1 \
                    and source_app != UNKNOWN_SOURCE:
                source_app = UNKNOWN_SOURCE
                self._flags["source_apps_folded"] += 1
            self._total[source_app].append(total_ms)
            self._scan[source_app].append(scan_ms)
            self._bytes[source_app].append(float(body_bytes))
            self._counts[(source_app, action)] += 1
            self._flags["requests"] += 1
            self._flags["findings"] += findings
            if cache_hit:
                self._flags["cache_hits"] += 1
            else:
                self._flags["cache_misses"] += 1
            if budget_exceeded:
                self._flags["budget_exceeded"] += 1
            if tiers_dropped:
                self._flags["tiers_dropped"] += 1
            if oversize_unscanned:
                self._flags["oversize_unscanned"] += 1

    def bump(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._flags[name] += amount

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            apps = sorted(set(self._total) | {a for a, _ in self._counts})
            by_app = {}
            for app in apps:
                total = list(self._total.get(app, ()))
                scan = list(self._scan.get(app, ()))
                size = list(self._bytes.get(app, ()))
                by_app[app] = {
                    "requests": sum(v for (a, _), v in self._counts.items() if a == app),
                    "allow": self._counts.get((app, "allow"), 0),
                    "deny": self._counts.get((app, "deny"), 0),
                    "total_ms": {
                        "p50": round(_percentile(total, 50), 3),
                        "p95": round(_percentile(total, 95), 3),
                        "p99": round(_percentile(total, 99), 3),
                        "max": round(max(total), 3) if total else 0.0,
                    },
                    "scan_ms": {
                        "p50": round(_percentile(scan, 50), 3),
                        "p95": round(_percentile(scan, 95), 3),
                        "p99": round(_percentile(scan, 99), 3),
                    },
                    "body_bytes": {
                        "p50": int(_percentile(size, 50)),
                        "p95": int(_percentile(size, 95)),
                        "max": int(max(size)) if size else 0,
                    },
                }
            return {"by_source_application": by_app, "counters": dict(self._flags)}
