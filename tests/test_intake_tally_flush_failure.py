"""A tally flush that fails at any step keeps every allow it drained.

The flush drains the tally, guards the rows and queues them on the sink.
Each step can fail: the guard raises, the sink raises, or the sink refuses
the batch. In every case the allows are counted back in and written by the
next flush that succeeds.
"""

from __future__ import annotations

import contextlib

import pytest
from test_intake_fleet import org_env  # noqa: F401
from test_intake_tally import _all, _app, _prompt, _scan

from forgd_verdict.store.tally import weight


def _stored(app) -> int:
    return sum(weight(r) for r in _all(app.store))


def _fail_once(monkeypatch, obj, name, failure):
    real = getattr(obj, name)
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return failure()
        return real(*args, **kwargs)

    monkeypatch.setattr(obj, name, flaky)
    return calls


def _raise():
    raise RuntimeError("unavailable this once")


async def _ten_then_fail_then_five(app, monkeypatch, obj, name, failure):
    for _ in range(10):
        await _scan(app, _prompt(1))
    assert app.tally.pending() == (1, 10)
    calls = _fail_once(monkeypatch, obj, name, failure)
    with contextlib.suppress(RuntimeError):
        app._flush_tally()
    assert calls["n"] == 1
    assert app.tally.pending() == (1, 10)
    for _ in range(5):
        await _scan(app, _prompt(1))
    app.flush()
    return _stored(app)


async def test_a_guard_that_raises_keeps_the_drained_allows(tmp_path, monkeypatch):
    app = _app(tmp_path)
    try:
        assert await _ten_then_fail_then_five(app, monkeypatch, app, "_guard", _raise) == 15
    finally:
        app.close()


async def test_a_sink_that_raises_keeps_the_drained_allows(tmp_path, monkeypatch):
    app = _app(tmp_path)
    try:
        assert await _ten_then_fail_then_five(
            app, monkeypatch, app.sink, "submit_records", _raise) == 15
    finally:
        app.close()


async def test_a_sink_that_refuses_keeps_the_drained_allows(tmp_path, monkeypatch):
    app = _app(tmp_path)
    try:
        assert await _ten_then_fail_then_five(
            app, monkeypatch, app.sink, "submit_records", lambda: False) == 15
        assert app._counts.get("tally_requeued", 0) >= 1
    finally:
        app.close()


async def test_a_guard_that_fails_mid_rows_keeps_every_allow(tmp_path, monkeypatch):
    """The guard raising after it has looked at some rows, with several
    rows drained, still puts every row back."""
    app = _app(tmp_path)
    try:
        for session in range(1, 5):
            for _ in range(3):
                await _scan(app, _prompt(session))
        assert app.tally.pending() == (4, 12)
        real = app._guard

        class Partial:
            def __init__(self):
                self.inner = real()

            def records(self, rows):
                self.inner.records(rows[:2])
                raise RuntimeError("guard failed part way")

        _fail_once(monkeypatch, app, "_guard", Partial)
        with pytest.raises(RuntimeError):
            app._flush_tally()
        assert app.tally.pending() == (4, 12)
        app.flush()
        assert _stored(app) == 12
    finally:
        app.close()
