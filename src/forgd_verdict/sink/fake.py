"""A sink that keeps what it was given, for tests.

Ships in the package rather than in the test tree on purpose: it is the
reference implementation of the protocol, and the conformance suite runs
against it beside the real one. With a single real sink the protocol and
the implementation drift into each other silently -- a second
implementation is what keeps the seam honest.

It also declares deliberately AWKWARD limits, so the core's chunking is
exercised by something that is not OTLP's comfortable 1 MB / 1000.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .base import RedactedEvent


class FakeSink:
    type = "fake"

    def __init__(self, *, max_events: int = 3, max_bytes: int = 4096,
                 ordered: bool = False, fail_times: int = 0) -> None:
        self.batches: list[list[RedactedEvent]] = []
        self._max_events = max_events
        self._max_bytes = max_bytes
        self._ordered = ordered
        self._fail_times = fail_times
        self.closed = False

    @property
    def max_batch_bytes(self) -> int:
        return self._max_bytes

    @property
    def max_batch_events(self) -> int:
        return self._max_events

    @property
    def requires_ordering(self) -> bool:
        return self._ordered

    @property
    def events(self) -> list[RedactedEvent]:
        return [e for b in self.batches for e in b]

    def send(self, events: Sequence[RedactedEvent]) -> int:
        if self._fail_times > 0:
            self._fail_times -= 1
            raise RuntimeError("downstream is having a day")
        self.batches.append(list(events))
        return len(events)

    def describe(self) -> dict[str, Any]:
        return {"type": self.type, "name": "fake", "batches": len(self.batches)}

    def close(self) -> None:
        self.closed = True
