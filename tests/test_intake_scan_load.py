"""Real scans of large bodies do not push a small /scan past the hook's
remote timeout, and do not run more than the large lane allows."""

from __future__ import annotations

import asyncio
import json
import resource
import sys
import time

import pytest
from conftest import ASGIClient
from test_intake_scan_lanes import HEADERS, _app, _small

from forgd_verdict.hook.cli import REMOTE_TIMEOUT_MS

pytestmark = pytest.mark.serial


def _big() -> bytes:
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read",
                       "tool_input": {"file_path": "/x",
                                      "blob": "a " * (1048576 - 1024)}}).encode()


async def test_small_scans_stay_under_the_remote_timeout_during_large_ones():
    app = _app()
    client = ASGIClient(app)
    big = _big()

    async def large():
        status, _ = await client.post("/scan", big, HEADERS)
        return status, time.perf_counter()

    async def smalls():
        await asyncio.sleep(0.2)
        out = []
        for _ in range(5):
            t = time.perf_counter()
            status, _ = await client.post("/scan", _small(), HEADERS)
            out.append((status, time.perf_counter() - t, time.perf_counter()))
        return out

    try:
        # Warm: the first scan after a start builds the detector set.
        await client.post("/scan", _small(), HEADERS)
        *bigs, small = await asyncio.gather(*[large() for _ in range(4)], smalls())
        assert sorted(s for s, _ in bigs).count(200) >= 1
        assert {s for s, _ in bigs} <= {200, 503}
        assert all(s == 200 for s, _, _ in small)
        # A small scan that arrives while a large one runs answers before it;
        # on a 2-CPU runner the large scan's thread holds the GIL, so the
        # absolute bound is a multiple of the hook's timeout.
        assert small[0][2] < min(done for s, done in bigs if s == 200)
        assert max(t for _, t, _ in small) < 3 * REMOTE_TIMEOUT_MS / 1000
    finally:
        app.close()


async def test_sixteen_concurrent_large_scans_run_one_at_a_time():
    app = _app()
    client = ASGIClient(app)
    big = _big()
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    try:
        results = await asyncio.gather(*[client.post("/scan", big, HEADERS)
                                         for _ in range(16)])
        statuses = [s for s, _ in results]
        assert statuses.count(503) >= 14
        assert app.stats()["counts"]["scan_busy_large"] == statuses.count(503)
        grown = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
        unit = 1 if sys.platform == "darwin" else 1024
        assert grown * unit < 256 * 1024 * 1024
    finally:
        app.close()
