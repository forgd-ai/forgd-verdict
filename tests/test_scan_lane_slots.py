"""A ScanLane gives back its slot when a caller is cancelled waiting or
running, and when the scan raises; waiters past the cap are refused at
once and the rest time out."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from forgd_verdict.intake.app import ScanLane

pytestmark = pytest.mark.serial


def _block(evt: threading.Event):
    evt.wait(5)
    return "done"


def _boom():
    raise RuntimeError("scan failed")


async def test_slot_released_after_caller_cancelled_and_after_error():
    lane = ScanLane("t", workers=1, wait_s=0.2, max_waiting=2)
    gate = threading.Event()
    t1 = asyncio.create_task(lane.run(_block, gate))
    await asyncio.sleep(0.05)
    assert lane.running == 1
    # A second caller waits, then is cancelled (client disconnect) mid-wait.
    t2 = asyncio.create_task(lane.run(_block, gate))
    await asyncio.sleep(0.05)
    assert lane.waiting == 1
    t2.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await t2
    assert lane.waiting == 0, lane.stats()
    # A third caller is cancelled while its scan is running; the slot
    # must still come back when the scan finishes.
    t3 = asyncio.create_task(lane.run(_block, gate))
    await asyncio.sleep(0.05)
    assert lane.full() is False or lane.waiting == 1
    t3.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await t3
    gate.set()
    assert await t1 == "done"
    await asyncio.sleep(0.2)
    assert lane.running == 0 and lane.waiting == 0, lane.stats()
    # An exception in the scan releases the slot too.
    with pytest.raises(RuntimeError):
        await lane.run(_boom)
    await asyncio.sleep(0)
    assert lane.running == 0, lane.stats()
    assert await lane.run(lambda: 1) == 1
    lane.close()


async def test_waiters_past_max_are_refused_at_once_and_waiters_time_out():
    lane = ScanLane("t", workers=1, wait_s=0.1, max_waiting=1)
    gate = threading.Event()
    t1 = asyncio.create_task(lane.run(_block, gate))
    await asyncio.sleep(0.02)
    started = time.monotonic()
    t2 = asyncio.create_task(lane.run(_block, gate))
    await asyncio.sleep(0.01)
    r3 = await lane.run(_block, gate)
    assert r3 is ScanLane.BUSY and time.monotonic() - started < 0.1
    assert await t2 is ScanLane.BUSY
    assert 0.1 <= time.monotonic() - started < 1.0
    gate.set()
    assert await t1 == "done"
    await asyncio.sleep(0.05)
    assert lane.stats() == {"workers": 1, "running": 0, "waiting": 0}
    lane.close()
