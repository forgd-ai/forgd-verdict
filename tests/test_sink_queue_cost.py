"""What one offer to a sink queue costs, counted against how full it is."""

from __future__ import annotations

import random
from collections import deque

import pytest

from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink.base import RedactedEvent, SinkConfig
from forgd_verdict.sink.factory import emitted_ids
from forgd_verdict.sink.fake import FakeSink
from forgd_verdict.sink.late import LateGroup, LateJob, LateRedactor
from forgd_verdict.sink.pipeline import SinkPipeline
from forgd_verdict.sink.redact import RedactionPlan

ORG = "00000000-0000-0000-0000-000000000001"


class CountingDeque(deque):
    """A deque counting the items handed out by iterating it."""

    reads = 0

    def __iter__(self):
        for item in super().__iter__():
            self.reads += 1
            yield item


def _event(i: int) -> RedactedEvent:
    return RedactedEvent(kind="log", name="evt", observed_at="t", surface="s", org=ORG,
                         attributes={"n": str(i)}, resource={}, redactions={})


def _pipeline(max_queue: int, *, max_events: int = 1, fail_times: int = 0) -> SinkPipeline:
    sink = FakeSink(max_events=max_events, max_bytes=10_000_000, fail_times=fail_times)
    p = SinkPipeline(sink, max_queue=max_queue, max_retries=0, background=False)
    p._q = CountingDeque(p._q)
    return p


def _late(max_queue: int) -> tuple[LateRedactor, list]:
    cfg = SinkConfig(name="siem", endpoint="https://collector.test")
    t0 = T0RegexDetector()
    offered: list = []
    late = LateRedactor(plan=RedactionPlan.build(cfg, emitted_ids([t0])), config=cfg,
                        offer=offered.extend, cheap_detectors=[t0], late_detectors=[],
                        max_queue=max_queue, background=False)
    late._q = CountingDeque(late._q)
    return late, offered


def _job(*sizes: int) -> LateJob:
    return LateJob([LateGroup([OtelRecord(kind="log", name="evt",
                                          attributes={"note": f"plain {i}"})
                               for i in range(n)], [], "s") for n in sizes], ORG, "t")


def _pipeline_reads_per_offer(size: int, offers: int = 20) -> float:
    p = _pipeline(size)
    for i in range(size):
        p.offer([_event(i)])
    p._q.reads = 0
    for i in range(offers):
        p.offer([_event(i)])
    p.stats()
    return p._q.reads / offers


def _late_reads_per_offer(size: int, offers: int = 20) -> float:
    late, _ = _late(size)
    for _ in range(size):
        late.offer(_job(1))
    late._q.reads = 0
    for _ in range(offers):
        late.offer(_job(1))
    late.stats()
    return late._q.reads / offers


def test_a_pipeline_offer_does_not_read_the_whole_queue():
    small, large = _pipeline_reads_per_offer(1_000), _pipeline_reads_per_offer(10_000)
    assert small == large, f"queue 1k: {small} reads/offer  10k: {large}"


def test_a_late_offer_does_not_read_the_whole_queue():
    small, large = _late_reads_per_offer(1_000), _late_reads_per_offer(10_000)
    assert small == large, f"queue 1k: {small} reads/offer  10k: {large}"


def test_an_oversized_batch_leaves_the_pipeline_queue_intact():
    p = _pipeline(5, max_events=100)
    for i in range(3):
        p.offer([_event(i)])
    p.offer([_event(i) for i in range(10)])
    assert len(p._q) == 3
    assert p.stats()["queued"] == 3 and p.dropped == 10


def test_an_oversized_group_leaves_the_late_queue_intact():
    late, _ = _late(5)
    for _ in range(3):
        late.offer(_job(1))
    late.offer(_job(10))
    s = late.stats()
    assert len(late._q) == 3
    assert s["queued"] == 3 and s["dropped"] == 10


@pytest.mark.parametrize("seed", range(5))
def test_the_pipeline_count_matches_its_queue(seed):
    rng = random.Random(seed)
    p = _pipeline(20, max_events=rng.choice((1, 3, 50)), fail_times=rng.randint(0, 5))

    def check():
        assert p._queued_n == sum(len(b) for b in list(deque.__iter__(p._q)))

    for _ in range(300):
        op = rng.random()
        if op < 0.6:
            p.offer([_event(i) for i in range(rng.choice((1, 2, 5, 30)))])
        elif op < 0.8:
            p.flush()
        else:
            p.stats()
        check()
    p.close()
    check()
    p.offer([_event(0)])
    check()


@pytest.mark.parametrize("seed", range(5))
def test_the_late_count_matches_its_queue(seed):
    rng = random.Random(seed)
    late, _ = _late(12)

    def check():
        assert late._queued_n == sum(j.size for j in list(deque.__iter__(late._q)))

    for _ in range(200):
        op = rng.random()
        if op < 0.6:
            late.offer(_job(*[rng.choice((1, 2, 4, 15)) for _ in range(rng.randint(1, 6))]))
        elif op < 0.8:
            late.drain()
        else:
            late.stats()
        check()
    late.close()
    check()
    late.offer(_job(1))
    check()


def _sizes(batch) -> int:
    return sum(e.byte_size() for e in batch)


def test_a_flush_merges_queued_batches_within_both_limits():
    one = _event(0).byte_size()
    p = _pipeline(1_000, max_events=100)
    p.sink._max_bytes = 3 * one + one // 2
    for i in range(20):
        p.offer([_event(i)])
    big = RedactedEvent(kind="log", name="evt", observed_at="t", surface="s", org=ORG,
                        attributes={"n": "x" * (10 * one)}, resource={}, redactions={})
    p.offer([big])
    for i in range(20, 24):
        p.offer([_event(i)])
    p.flush()
    batches = p.sink.batches
    assert len(batches) < 25
    for b in batches:
        assert len(b) <= p.sink.max_batch_events
        assert _sizes(b) <= p.sink.max_batch_bytes or b == [big]
    assert [big] in batches
    assert sum(len(b) for b in batches) == 25 and p.sent == 25


def test_merged_sends_keep_the_offer_order():
    p = _pipeline(1_000, max_events=7)
    for i in range(100):
        p.offer([_event(i)])
    p.flush()
    assert len(p.sink.batches) == 15
    assert [int(e.attributes["n"]) for e in p.sink.events] == list(range(100))


def test_a_failed_merged_send_drops_exactly_its_own_events():
    p = _pipeline(1_000, max_events=7, fail_times=1)
    for i in range(100):
        p.offer([_event(i)])
    p.flush()
    s = p.stats()
    assert p.dropped == 7
    assert [int(e.attributes["n"]) for e in p.sink.events] == list(range(7, 100))
    assert s["sent"] + s["dropped"] + s["queued"] == 100
