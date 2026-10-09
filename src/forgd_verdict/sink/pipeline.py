"""Queue, chunk, retry, drop. The part that must never reach Anthropic.

A non-200 from the collector is an export failure, and sustained failures
trip Anthropic's circuit breaker -- so a Splunk outage must not become
telemetry loss from Claude. This queue is bounded and drops with a counter
rather than blocking the ingest path, the same posture `StoreSink` takes.

Chunking lives here rather than in each exporter because the limits differ
per destination -- HEC around 1 MB, CloudWatch 1 MB and 10k events, Datadog
5 MB -- and three exporters re-chunking is three chances to get it wrong.
The sink declares its limits; the core respects them.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Sequence

from ..applog import exc_fields
from ..plugins import describe_for_log
from .base import RedactedEvent, Sink

_log = logging.getLogger("forgd_verdict.sink")

# The `byte_size` of the events one queue holds, beside its `max_queue`
# events: an event's values can each be up to MAX_VALUE_CHARS.
MAX_QUEUE_BYTES = 64 * 1024 * 1024


def chunk(events: Sequence[RedactedEvent], sink: Sink
          ) -> list[list[RedactedEvent]]:
    """Split a batch against the limits the sink declares.

    A single event larger than the byte limit is still emitted, alone: the
    alternative is silently dropping the biggest events, which are exactly
    the ones most likely to carry something worth seeing.
    """
    out: list[list[RedactedEvent]] = []
    current: list[RedactedEvent] = []
    size = 0
    for e in events:
        n = e.byte_size()
        too_many = len(current) + 1 > sink.max_batch_events
        too_big = current and size + n > sink.max_batch_bytes
        if too_many or too_big:
            out.append(current)
            current, size = [], 0
        current.append(e)
        size += n
    if current:
        out.append(current)
    return out


class SinkPipeline:
    """One sink, one bounded queue, one worker.

    Deliberately not shared across sinks: a slow Splunk must not stall a
    fast blob sink, and a drop counter that cannot say WHICH destination
    dropped is not worth reading.
    """

    def __init__(self, sink: Sink, *, max_queue: int = 10_000,
                 max_queue_bytes: int = MAX_QUEUE_BYTES,
                 max_retries: int = 2, flush_interval_s: float = 2.0,
                 background: bool = True) -> None:
        self.sink = sink
        self.max_queue = max_queue
        self.max_queue_bytes = max_queue_bytes
        self.max_retries = max_retries
        self._q: deque[list[RedactedEvent]] = deque()
        # Events in `_q` and their `byte_size`, and each batch's
        # `byte_size` in `_q_bytes`, changed under `_lock` with every append
        # and pop.
        self._queued_n = 0
        self._queued_bytes = 0
        self._q_bytes: deque[int] = deque()
        self._lock = threading.Lock()
        # Counters are touched by the worker and read by /stats, so they
        # move under the same lock as the queue rather than being
        # incremented wherever they happen to change.
        self.queued = 0
        self.sent = 0
        self.dropped = 0
        self.retries = 0
        # PER INSTANCE. As a class attribute this serialised every sink
        # in the process, so a slow Splunk would stall a fast blob sink --
        # the one thing a queue per destination exists to prevent.
        self._sending = threading.Lock()
        self._closing = threading.Event()
        self._closed = False
        self._wake = threading.Event()
        self._worker: threading.Thread | None = None
        # A BACKGROUND worker, not a flush on the ingest path. Flushing
        # inline made every export wait on the customer's SIEM: with
        # timeout_s of 10 and two retries that is up to 30 s holding the
        # OTLP response open, which is a delivery failure to Anthropic and
        # trips the circuit breaker -- the precise outcome this queue was
        # built to prevent, reintroduced by where it was called.
        if background:
            self._worker = threading.Thread(
                target=self._run, name=f"sink-{id(self)}", daemon=True)
            self._flush_interval = flush_interval_s
            self._worker.start()

    def _run(self) -> None:  # pragma: no cover - timing
        while not self._closing.is_set():
            self._wake.wait(self._flush_interval)
            self._wake.clear()
            try:
                self.flush()
            except Exception as exc:
                _log.warning("sink worker flush failed", extra={"fields": exc_fields(exc)})

    def offer(self, events: Sequence[RedactedEvent]) -> int:
        """Never blocks and never raises into the caller.

        The caller is the OTLP ingest path, which owes Anthropic a 200. A
        full queue drops the OLDEST batch: the newest telemetry is the
        useful telemetry when something is on fire, and keeping the oldest
        would mean a recovered sink flushes an hour of history before
        anything current.
        """
        if not events:
            return 0
        batches = chunk(events, self.sink)
        sizes = [sum(e.byte_size() for e in b) for b in batches]
        with self._lock:
            if self._closed:
                # Nothing will send it. Counted rather than queued, so an
                # offer that arrives after shutdown -- a late redaction pass
                # finishing -- is a number and not a silent loss.
                self.dropped += len(events)
                return 0
            for b, n in zip(batches, sizes, strict=True):
                # A batch bigger than either whole bound is dropped and
                # counted without evicting anything.
                if len(b) > self.max_queue or n > self.max_queue_bytes:
                    self.dropped += len(b)
                    continue
                while self._q and (self._queued_n + len(b) > self.max_queue
                                   or self._queued_bytes + n > self.max_queue_bytes):
                    evicted = self._q.popleft()
                    self._queued_n -= len(evicted)
                    self._queued_bytes -= self._q_bytes.popleft()
                    self.dropped += len(evicted)
                self._q.append(b)
                self._q_bytes.append(n)
                self._queued_n += len(b)
                self._queued_bytes += n
            self.queued = self._queued_n
        self._wake.set()
        return len(batches)

    def flush(self) -> int:
        """Send what is queued. Retry a failed chunk, then drop it.

        Each pass pops, in order, as many whole queued batches as fit one
        send within the sink's event and byte limits (always at least one),
        and sends them re-chunked. Batches not yet popped stay counted in
        the queue, so they can still be evicted.

        Serialised per pipeline: the worker and `close()` can both call
        this, and a sink sent to from two threads at once is a sink whose
        ordering guarantee -- the one CloudWatch needs -- is not one.
        """
        sent = 0
        with self._sending:
            try:
                while True:
                    with self._lock:
                        if not self._q:
                            break
                        events = self._pop_merged()
                    for batch in chunk(events, self.sink):
                        sent += self._send(batch)
            finally:
                self._end_flush()
        with self._lock:
            self.queued = self._queued_n
        return sent

    def _end_flush(self) -> None:
        """Call the sink's optional `end_flush`, which the built-in sinks use
        to close their connection. A sink without one is left as it is."""
        end_flush = getattr(self.sink, "end_flush", None)
        if end_flush is None:
            return
        try:
            end_flush()
        except Exception as exc:
            _log.warning("sink end_flush failed", extra={"fields": {
                "sink": _sink_label(self.sink), **exc_fields(exc)}})

    def _pop_merged(self) -> list[RedactedEvent]:
        """Whole batches from the head of the queue whose events fit one
        send, at least one. Called under `_lock`."""
        events = list(self._q.popleft())
        size = self._q_bytes.popleft()
        while self._q:
            head = self._q[0]
            n = self._q_bytes[0]
            if (len(events) + len(head) > self.sink.max_batch_events
                    or size + n > self.sink.max_batch_bytes):
                break
            events.extend(self._q.popleft())
            self._q_bytes.popleft()
            size += n
        self._queued_n -= len(events)
        self._queued_bytes -= size
        return events

    def _send(self, batch: list[RedactedEvent]) -> int:
        attempt = 0
        while True:
            try:
                n = self.sink.send(batch)
                with self._lock:
                    self.sent += len(batch)
                return n
            except Exception as exc:
                attempt += 1
                if attempt > self.max_retries:
                    with self._lock:
                        self.dropped += len(batch)
                    # WARNING and not exception: a downstream outage is an
                    # operational fact about someone else's system, and a
                    # stack trace per batch buries it.
                    fields: dict[str, object] = {
                        "sink": _sink_label(self.sink),
                        "events": len(batch),
                        "dropped_total": self.dropped,
                        **exc_fields(exc),
                    }
                    status = getattr(exc, "status", None)
                    if type(status) is int:
                        fields["status"] = status
                    _log.warning("sink batch dropped", extra={"fields": fields})
                    return 0
                with self._lock:
                    self.retries += 1

    def stats(self) -> dict[str, object]:
        with self._lock:
            # Read under the lock. The worker moves all four, and a
            # dashboard showing `dropped` from one moment and `sent` from
            # another is a dashboard whose arithmetic does not add up.
            self.queued = self._queued_n
            return {
                "sink": describe_for_log(self.sink),
                "queued": self.queued,
                "sent": self.sent,
                "dropped": self.dropped,
                "retries": self.retries,
            }

    def close(self) -> None:
        self._closing.set()
        self._wake.set()
        if self._worker is not None:
            self._worker.join(timeout=5)
        self.flush()
        with self._lock:
            self._closed = True
        # Anything offered between the flush and the flag.
        self.flush()
        self.sink.close()


def _sink_label(sink: Sink) -> object:
    desc = describe_for_log(sink)
    return desc.get("name", desc.get("plugin"))
