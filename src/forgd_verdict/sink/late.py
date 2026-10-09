"""Redaction tiers too slow for the ingest path, run after the export is acked.

The collector owes Anthropic a 200 inside the exporter's timeout, and
Presidio costs 16 ms at 1 KB and 8.4 s at 223 KB with the NER entities on.
Running it inline would put that cost on the one path with a deadline, so
the `otel` profile leaves T2 off -- and a sink could then only mask what T0,
T1 and the checksums find. Names, emails, phone numbers and addresses left
verbatim.

This stage sits between the collector and a sink's pipeline. The ingest
path hands it the RAW records and the findings the cheap tiers already
produced, and returns at once. A worker thread runs the slow tiers over the
same scan units, merges what they find, redacts, and offers the result to
the sink's pipeline -- which then chunks, retries and drops exactly as
before.

Two properties are the point, and both are tested:

* **The ingest path never waits on it.** `offer` appends to a bounded queue
  and returns; a full queue drops the OLDEST job with a counter, the same
  posture as `SinkPipeline`.
* **A slow tier that fails does not forward the value.** An exception from
  a late detector is reported to `redact_groups` as a skipped tier, and a
  skipped tier the sink redacts masks every attribute whole. The raw value
  is never sent because T2 could not look at it.

The queue holds raw content until the worker reaches it. It is in memory
only, bounded by `max_queue` records, and never written anywhere -- the same
content the request held a moment earlier, held for longer.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from ..applog import exc_fields
from ..models import Finding
from ..otel.extract import record_units_by_key
from ..otel.payload import OtelRecord
from .redact import RedactGroup, RedactionPlan, index_findings, redact_groups

_log = logging.getLogger("forgd_verdict.sink")

# The characters of record names, keys and values one queue holds, beside
# its `max_queue` records: a record's values can each be up to
# MAX_VALUE_CHARS.
MAX_QUEUE_BYTES = 64 * 1024 * 1024

# How long `close` waits for a pass already running. Under the collector's
# 60 s terminationGracePeriod, with room for the pipeline to flush after.
CLOSE_TIMEOUT_S = 30.0


@dataclass
class LateGroup:
    records: Sequence[OtelRecord]
    findings: list[Finding]
    surface: str
    skipped: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class LateJob:
    """One export's groups for one sink."""

    groups: Sequence[LateGroup]
    org: str
    observed_at: str

    @property
    def size(self) -> int:
        return sum(len(g.records) for g in self.groups)

    def byte_size(self) -> int:
        """The characters of the job's record names, keys and values."""
        return sum(len(r.name or "") + sum(len(str(k)) + len(str(v)) for d in
                                           (r.attributes, r.resource) for k, v in d.items())
                   for g in self.groups for r in g.records)


def _split(job: LateJob, bound: int) -> list[LateJob]:
    """`job` as consecutive jobs of whole groups, each holding at most
    `bound` records unless one group alone is larger."""
    if job.size <= bound:
        return [job]
    parts: list[list[LateGroup]] = [[]]
    size = 0
    for group in job.groups:
        n = len(group.records)
        if parts[-1] and size + n > bound:
            parts.append([])
            size = 0
        parts[-1].append(group)
        size += n
    return [replace(job, groups=groups) for groups in parts]


def needs_late(plan: RedactionPlan, late_detectors: Sequence[Any]) -> bool:
    """Does this sink redact anything only a late tier produces?"""
    for d in late_detectors:
        prefix = getattr(d, "finding_prefix", d.name)
        if any(w == prefix or w.split(":", 1)[0] == prefix for w in plan.detectors):
            return True
    return False


class LateRedactor:
    """One sink's slow-tier stage: bounded queue, one worker."""

    def __init__(self, *, plan: RedactionPlan, config, offer: Callable,
                 cheap_detectors: Sequence[Any], late_detectors: Sequence[Any],
                 max_queue: int = 10_000, max_queue_bytes: int = MAX_QUEUE_BYTES,
                 background: bool = True,
                 flush_interval_s: float = 1.0) -> None:
        self.plan = plan
        self.config = config
        self._offer = offer
        self._cheap = list(cheap_detectors)
        self._late = list(late_detectors)
        # The backstop in `redact.py` re-scans masked text against every
        # tier the sink redacts, so it has to be handed the late ones too
        # -- or a Presidio offset that missed would never be noticed.
        self._all = self._cheap + self._late
        self.max_queue = max_queue
        self.max_queue_bytes = max_queue_bytes
        self._q: deque[LateJob] = deque()
        # Records in `_q` and their `byte_size`, and each job's `byte_size`
        # in `_q_bytes`, changed under `_lock` with every append, pop and
        # clear.
        self._queued_n = 0
        self._queued_bytes = 0
        self._q_bytes: deque[int] = deque()
        self._lock = threading.Lock()
        self.processed = 0
        self.dropped = 0
        self.failed = 0
        # Records the worker has popped and not yet handed on. Counted so a
        # pass still running when `close` gives up is reported as dropped
        # rather than vanishing.
        self._inflight = 0
        self._accepting = True
        self._closing = threading.Event()
        self._wake = threading.Event()
        self._worker: threading.Thread | None = None
        if background:
            self._flush_interval = flush_interval_s
            self._worker = threading.Thread(
                target=self._run, name=f"sink-late-{config.name}", daemon=True)
            self._worker.start()

    # -- ingest side --------------------------------------------------------

    def offer(self, job: LateJob) -> None:
        """Never blocks and never raises into the ingest path.

        Takes a copy of the records. The worker reads them after this
        returns, and a caller that changed an attribute in between would
        have the worker redact something the inline findings do not
        describe -- and a cheap-tier match added then is never masked,
        because the late pass only reruns the slow tiers.

        A job over `max_queue` records is queued as several jobs, split at
        group boundaries, each within the bound.
        """
        for part in _split(job, self.max_queue):
            self._offer_one(part)

    def _offer_one(self, job: LateJob) -> None:
        n = job.size
        if not n:
            return
        job = replace(job, groups=[
            replace(g, records=[
                replace(r, attributes=dict(r.attributes), resource=dict(r.resource))
                for r in g.records])
            for g in job.groups])
        size = job.byte_size()
        with self._lock:
            if not self._accepting:
                self.dropped += n
                return
            if n > self.max_queue or size > self.max_queue_bytes:
                # Bigger than either whole bound: dropped and counted
                # without evicting anything, as in SinkPipeline.
                self.dropped += n
                return
            while self._q and (self._queued_n + n > self.max_queue
                               or self._queued_bytes + size > self.max_queue_bytes):
                evicted = self._q.popleft().size
                self._queued_n -= evicted
                self._queued_bytes -= self._q_bytes.popleft()
                self.dropped += evicted
            self._q.append(job)
            self._q_bytes.append(size)
            self._queued_n += n
            self._queued_bytes += size
        self._wake.set()

    # -- worker side --------------------------------------------------------

    def _run(self) -> None:  # pragma: no cover - timing
        while not self._closing.is_set():
            self._wake.wait(self._flush_interval)
            self._wake.clear()
            try:
                self.drain()
            except Exception as exc:
                _log.warning("late redaction pass failed", extra={"fields": exc_fields(exc)})

    def drain(self) -> int:
        done = 0
        while True:
            with self._lock:
                if not self._q:
                    return done
                job = self._q.popleft()
                self._queued_n -= job.size
                self._queued_bytes -= self._q_bytes.popleft()
                self._inflight = job.size
            try:
                self._process(job)
            finally:
                with self._lock:
                    self._inflight = 0
            done += job.size

    def _process(self, job: LateJob) -> None:
        groups = [self._scan(g) for g in job.groups]
        events = redact_groups(groups, self.plan, self.config, org=job.org,
                               observed_at=job.observed_at, detectors=self._all)
        self._offer(events)
        with self._lock:
            self.processed += job.size

    def _scan(self, group: LateGroup) -> RedactGroup:
        """`group` with what the late tiers find in it added."""
        findings = list(group.findings)
        skipped = list(group.skipped)
        late_skipped = []
        units = [unit for index, record in enumerate(group.records)
                 for _, unit in record_units_by_key(record, index)]
        for det in self._late:
            try:
                findings.extend(det.scan(units))
            except Exception as exc:
                # Recorded as skipped, which is what makes it fail closed:
                # `redact_groups` masks every attribute whole when a tier
                # the sink redacts did not run. Logged without the text.
                with self._lock:
                    self.failed += 1
                skipped.append(det.name)
                late_skipped.append(det.name)
                _log.warning("late redaction tier failed; masking whole values",
                             extra={"fields": {"sink": self.config.name,
                                               "detector": det.name,
                                               "error": type(exc).__name__}})
        return RedactGroup(group.records, index_findings(findings), group.surface,
                           tuple(skipped), tuple(late_skipped))

    def stats(self) -> dict[str, object]:
        with self._lock:
            return {
                "late_tiers": [d.name for d in self._late],
                "queued": self._queued_n,
                "processed": self.processed,
                "dropped": self.dropped,
                "failed": self.failed,
            }

    def close(self, timeout_s: float = CLOSE_TIMEOUT_S) -> None:
        """Stop accepting, finish what is queued, then return.

        Must return before the sink's pipeline closes: the worker hands its
        result to the pipeline, and a pipeline closed under it strands the
        events. If a pass outlives `timeout_s`, what it holds and what is
        still queued are counted as dropped. The pipeline refuses offers
        once closed, so a pass that finishes later is counted there too.
        """
        with self._lock:
            self._accepting = False
        self._closing.set()
        self._wake.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout_s)
            if self._worker.is_alive():
                with self._lock:
                    lost = self._inflight + self._queued_n
                    self.dropped += lost
                    self._q.clear()
                    self._q_bytes.clear()
                    self._queued_n = 0
                    self._queued_bytes = 0
                _log.warning("late redaction still running at shutdown",
                             extra={"fields": {"sink": self.config.name,
                                               "dropped": lost}})
                return
        self.drain()
