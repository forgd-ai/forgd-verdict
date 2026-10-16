"""Adapter 1's durable findings sink.

Before this existed, verdict history was ephemeral: the timing CSV lives on
container-local disk that dies with the replica, `/metrics` is in-process,
and the log stream is a rolling buffer with no configured destination. A
whole shadow run produced data that was thrown away, which made the
would-have-denied rate impossible to compute.

Same background-writer shape as TimingCSV and FrameArchive, with one extra
requirement: a storage outage must never become a webhook failure. So the
queue is bounded, puts never block, and every exception inside the writer is
swallowed and counted. Dropping records is strictly better than adding
latency to a verdict.

The collector constructs it with `hold_failed=True`. An OTLP exporter does
not resend a batch it got a 200 for, and does resend one it got a 503 for,
so there the writer keeps a failed batch and retries it until it is written,
and the sink refuses new records while it holds one.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any

from ..models import Finding
from .base import FindingRow, VerdictRecord, verdict_from_log_row

_log = logging.getLogger("forgd_verdict")


# How often an idle writer checks whether `close` has been called.
_CLOSE_POLL_S = 0.5


class _FlushRequest:
    """Queued by `flush`. The writer sets `done` once every record queued
    before it has been through `_flush`."""

    def __init__(self) -> None:
        self.done = threading.Event()


class StoreSink:
    def __init__(
        self,
        store: Any | None,
        salt: str = "",
        batch_size: int = 50,
        # 60s, not 5s. At low traffic a short interval writes one record per
        # object, and the dashboard pays one HTTP GET per object on every
        # page load -- 45 records became 45 requests. The cost of batching is
        # up to this much telemetry lost on an ungraceful kill; close() is
        # called on lifespan shutdown, so a normal revision roll still
        # flushes. Telemetry is the right thing to risk here.
        flush_interval_s: float = 60.0,
        max_queue: int = 5000,
        # Two, not more. A pod that starts before its credential is ready
        # recovers within seconds; a real outage is not fixed by trying
        # harder, and holding a batch while the queue behind it fills would
        # drop NEWER records to save older ones.
        max_retries: int = 2,
        close_timeout_s: float = 10.0,
        hold_failed: bool = False,
        hold_retry_s: float = 1.0,
        hold_retry_max_s: float = 30.0,
    ):
        self.store = store
        self.salt = salt
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.written = 0
        self.dropped = 0
        self.errors = 0
        self.flushes = 0
        self.last_flush_ms = 0.0
        self.retries = 0
        self.max_retries = max_retries
        self.close_timeout_s = close_timeout_s
        self.hold_failed = hold_failed
        self.hold_retry_s = hold_retry_s
        self.hold_retry_max_s = hold_retry_max_s
        # The unwritten part of a failed batch, under `hold_failed`. Written
        # only by the writer thread; non-empty means the sink is degraded.
        self._held: list[VerdictRecord] = []
        self._held_attempts = 0
        # Flush requests answered once the held batch is written.
        self._held_flushes: list[_FlushRequest] = []
        self._closing = threading.Event()
        # Held across the accepting check and the put in `_enqueue` and
        # `submit_records`, across every put in `_requeue`, and while
        # `close` sets `_closing`, so a record is either refused or in the
        # queue before `close` counts what is left, and the free space
        # `submit_records` reads cannot shrink before it puts.
        self._accept_lock = threading.Lock()
        self._inflight = 0
        # Records the writer has taken off the queue and not yet handed to
        # `_flush`. Written only by the writer thread.
        self._batched = 0
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        if store is not None:
            self._thread = threading.Thread(target=self._run, name="forgd-store", daemon=True)
            self._thread.start()

    @property
    def enabled(self) -> bool:
        return self.store is not None

    @property
    def degraded(self) -> bool:
        """True while the writer holds a batch it failed to write. Only
        `hold_failed` holds one."""
        return bool(self._held)

    def submit(self, row: dict[str, Any], findings: list[Finding] | None = None) -> None:
        """Enqueue one verdict. Never blocks, never raises."""
        if self.store is None:
            return
        try:
            record = verdict_from_log_row(row, self.salt)
            record.findings = [FindingRow.from_finding(f) for f in (findings or [])]
            self._enqueue(record)
        except queue.Full:
            self.dropped += 1
        except Exception:  # noqa: BLE001 - the verdict path must not care
            self.errors += 1

    def submit_record(self, record: VerdictRecord) -> bool:
        """Enqueue an already-built record. True if it was accepted.

        Adapter 4 builds its own records rather than deriving them from a
        log row, and unlike the verdict path it WANTS to know about a full
        queue: an OTLP exporter retries on 503 and is itself the buffer, so
        refusing is how the batch survives. Adapter 1 cannot do that -- a
        non-200 there is a webhook failure -- which is why `submit` drops
        and this returns.
        """
        if self.store is None:
            return True
        try:
            self._enqueue(record)
            return True
        except queue.Full:
            self.dropped += 1
            return False
        except Exception:  # noqa: BLE001
            self.errors += 1
            return False

    def submit_records(self, records: list[VerdictRecord]) -> bool:
        """Enqueue all of `records` or none of them. True if they were
        accepted; a refusal counts every record in `dropped`, except one
        while `degraded`, which the caller is expected to send again."""
        if self.store is None or not records:
            return True
        with self._accept_lock:
            if self._held:
                return False
            free = (self._queue.maxsize - self._queue.qsize()
                    if self._queue.maxsize > 0 else len(records))
            if self._closing.is_set() or not self._thread.is_alive() or free < len(records):
                self.dropped += len(records)
                return False
            for record in records:
                self._queue.put_nowait(record)
        return True

    def flush(self, timeout_s: float | None = None) -> bool:
        """Write every record accepted before this call, waiting at most
        `timeout_s` (default `close_timeout_s`). True when the writer got
        through them in time. A batch that failed is retried as in normal
        running and still counts as got through, except under `hold_failed`,
        where it counts once it is written."""
        if self._thread is None:
            return True
        deadline = time.monotonic() + (self.close_timeout_s if timeout_s is None
                                       else timeout_s)
        request = _FlushRequest()
        while True:
            with self._accept_lock:
                if self._closing.is_set() or not self._thread.is_alive():
                    return self._queue.empty()
                try:
                    self._queue.put_nowait(request)
                    break
                except queue.Full:
                    pass  # retried below until the deadline
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return request.done.wait(max(0.0, deadline - time.monotonic()))

    def _enqueue(self, record: VerdictRecord) -> None:
        """`put_nowait`, raising `queue.Full` once the sink is closing or its
        writer thread has exited, when nothing would write the record, and
        while it is `degraded`."""
        with self._accept_lock:
            if self._closing.is_set() or not self._thread.is_alive() or self._held:
                raise queue.Full
            self._queue.put_nowait(record)

    def _run(self) -> None:
        batch: list[VerdictRecord] = []
        last_flush = time.monotonic()
        while True:
            if self._closing.is_set():
                self._drain(batch)
                return
            if self._held:
                self._closing.wait(self._hold_delay())
                if not self._closing.is_set():
                    self._flush(list(self._held))
                    if not self._held:
                        self._answer_held_flushes()
                continue
            timeout = max(0.1, self.flush_interval_s - (time.monotonic() - last_flush))
            try:
                item = self._queue.get(timeout=min(timeout, _CLOSE_POLL_S))
            except queue.Empty:
                item = None
            if isinstance(item, _FlushRequest):
                self._flush(batch)
                batch = []
                last_flush = time.monotonic()
                if self._held:
                    self._held_flushes.append(item)
                else:
                    item.done.set()
                continue
            if item is not None:
                batch.append(item)
                self._batched = len(batch)
            due = len(batch) >= self.batch_size or (
                batch and time.monotonic() - last_flush >= self.flush_interval_s
            )
            if due:
                self._flush(batch)
                batch = []
                last_flush = time.monotonic()

    def _drain(self, batch: list[VerdictRecord]) -> None:
        """Write a held batch, `batch` and everything still queued, in
        batches. A failed batch is requeued and retried `max_retries` times,
        held or not."""
        batch = self._held + batch
        self._held = []
        self._answer_held_flushes()
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, _FlushRequest):
                item.done.set()
                continue
            batch.append(item)
            self._batched = len(batch)
            if len(batch) >= self.batch_size:
                self._flush(batch)
                batch = []
        self._flush(batch)

    def _requeue(self, batch: list[VerdictRecord]) -> None:
        """Put a failed batch back, oldest first, without blocking.

        put_nowait rather than put: the writer thread must never block, and
        a queue that has filled while this batch was in flight is already
        telling us to shed load. Records that will not fit are counted as
        dropped here rather than silently vanishing.
        """
        with self._accept_lock:
            for record in batch:
                try:
                    self._queue.put_nowait(record)
                except queue.Full:
                    self.dropped += 1

    def _answer_held_flushes(self) -> None:
        for request in self._held_flushes:
            request.done.set()
        self._held_flushes = []

    def _hold_delay(self) -> float:
        """Seconds before the next attempt at the held batch: `hold_retry_s`,
        doubling per failed attempt, at most `hold_retry_max_s`. The exponent
        is capped because `2.0 ** 1024` raises OverflowError."""
        exponent = min(max(0, self._held_attempts - 1), 30)
        return min(self.hold_retry_max_s, self.hold_retry_s * 2 ** exponent)

    def _write(self, batch: list[VerdictRecord]) -> None:
        """`write_verdicts`, counting what it wrote."""
        self.written += self.store.write_verdicts(batch)

    def _write_holding(self, batch: list[VerdictRecord]) -> None:
        """Write `batch` one (source, org, day) group at a time, which is one
        store object each, so that a failure part-way holds only the groups
        not written and a retry does not write the others again."""
        groups: dict[tuple, list[VerdictRecord]] = {}
        for record in batch:
            groups.setdefault((record.source, record.org, record.day), []).append(record)
        pending = list(groups.values())
        while pending:
            try:
                self._write(pending[0])
            except Exception:
                self._held = _flatten(pending)
                raise
            pending.pop(0)
            if self._held:
                self._held = _flatten(pending)

    def _flush(self, batch: list[VerdictRecord]) -> None:
        if not batch:
            return
        started = time.monotonic()
        self._inflight = len(batch)
        self._batched = 0
        holding = self.hold_failed and not self._closing.is_set()
        try:
            if holding:
                self._write_holding(batch)
                if self._held_attempts:
                    _log.warning("store flush recovered",
                                 extra={"fields": {"records": len(batch),
                                                   "attempts": self._held_attempts}})
                self._held_attempts = 0
            else:
                self._write(batch)
            self.retries = 0
        except Exception as exc:  # noqa: BLE001 - a storage outage is not a webhook failure
            self.errors += 1
            if holding:
                self._held_attempts += 1
                _log.warning(
                    "store flush failed",
                    extra={"fields": {
                        "error": type(exc).__name__,
                        "records": len(batch),
                        "held": len(self._held),
                        "attempt": self._held_attempts,
                        "dropped_total": self.dropped,
                    }},
                )
                return
            # RETRY before dropping, so a transient error does not cost
            # findings permanently. A typical one is a pod that starts
            # serving before its federated token is available, which would
            # drop whatever arrives in the first seconds of every roll.
            #
            # Bounded, because the queue is the buffer and an unbounded
            # retry against a real outage would hold a batch while the
            # queue behind it fills and drops newer records instead.
            if self.retries < self.max_retries:
                self.retries += 1
                self._requeue(batch)
            else:
                self.retries = 0
                self.dropped += len(batch)
            # Logged. "a storage outage is not a webhook failure" is why it
            # is swallowed; logged so that a `dropped`/`errors` count has an
            # explanation. The type and message only -- a record carries
            # hashes, but an exception from a storage client can carry a
            # URL with a token in it.
            _log.warning(
                "store flush failed",
                extra={"fields": {
                    "error": type(exc).__name__,
                    "records": len(batch),
                    "retry": self.retries,
                    "dropped_total": self.dropped,
                }},
            )
        finally:
            self._inflight = 0
            # A slow backend is worth surfacing: the first deployment had a
            # writer thread stall indefinitely on credential acquisition,
            # which showed up as records queued and nothing written, with no
            # error anywhere. /metrics now carries the evidence.
            self.last_flush_ms = round((time.monotonic() - started) * 1000, 1)
            self.flushes += 1

    def stats(self) -> dict[str, Any]:
        """`pending` is every accepted record not yet written: `queued`,
        plus `batched` in the writer's hands, plus `inflight` in a write or
        `held` after a failed one. A retry of the held batch is in flight
        too, which is why it is the larger of the two and not their sum."""
        queued = self._queue.qsize() if self.store is not None else 0
        batched, inflight, held = self._batched, self._inflight, len(self._held)
        return {
            "enabled": self.enabled,
            "written": self.written,
            "dropped": self.dropped,
            "errors": self.errors,
            "queued": queued,
            "batched": batched,
            "inflight": inflight,
            "held": held,
            "degraded": bool(held),
            "pending": queued + batched + max(inflight, held),
            "flushes": self.flushes,
            "last_flush_ms": self.last_flush_ms,
        }

    def close(self) -> None:
        """Write what is queued, waiting at most `close_timeout_s`.

        Rows still queued, held or in flight when the wait ends are counted in
        `dropped` and logged, whether the writer is still running or has
        exited without writing them.
        """
        if self._thread is None:
            return
        with self._accept_lock:
            if self._closing.is_set():
                return
            self._closing.set()
        self._thread.join(timeout=self.close_timeout_s)
        lost = self._queue.qsize() + max(self._inflight, len(self._held))
        if not lost:
            return
        self.dropped += lost
        _log.warning(
            "store sink closed before its queue was written",
            extra={"fields": {"records": lost, "dropped_total": self.dropped}},
        )


def _flatten(groups: list[list[VerdictRecord]]) -> list[VerdictRecord]:
    """`groups` flattened, in order."""
    return [record for group in groups for record in group]
