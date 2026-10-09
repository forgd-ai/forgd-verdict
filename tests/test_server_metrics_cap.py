"""The verdict server's per-source metrics hold a bounded number of keys."""

from __future__ import annotations

from forgd_verdict.server import metrics
from forgd_verdict.server.metrics import MAX_SOURCE_APPS, UNKNOWN_SOURCE, Metrics


def _record(m: Metrics, app: str) -> None:
    m.record(app, 1.0, 0.5, 10, "allow")


def test_distinct_sources_past_the_cap_fold_into_unknown():
    m = Metrics()
    for i in range(MAX_SOURCE_APPS * 3):
        _record(m, f"app-{i}")
    snap = m.snapshot()
    by_app = snap["by_source_application"]
    assert len(by_app) == MAX_SOURCE_APPS
    assert UNKNOWN_SOURCE in by_app
    kept = MAX_SOURCE_APPS - 1
    assert by_app[UNKNOWN_SOURCE]["requests"] == MAX_SOURCE_APPS * 3 - kept
    assert snap["counters"]["source_apps_folded"] == MAX_SOURCE_APPS * 3 - kept
    assert len(m._total) <= MAX_SOURCE_APPS


def test_a_source_already_kept_keeps_its_own_key(monkeypatch):
    monkeypatch.setattr(metrics, "MAX_SOURCE_APPS", 3)
    m = Metrics()
    for app in ("claude-ai", "cowork", "new-1", "claude-ai", "new-2"):
        _record(m, app)
    snap = m.snapshot()
    by_app = snap["by_source_application"]
    assert set(by_app) == {"claude-ai", "cowork", UNKNOWN_SOURCE}
    assert by_app["claude-ai"]["requests"] == 2
    assert by_app[UNKNOWN_SOURCE]["requests"] == 2


def test_unknown_itself_is_never_folded(monkeypatch):
    monkeypatch.setattr(metrics, "MAX_SOURCE_APPS", 2)
    m = Metrics()
    for app in ("claude-ai", "x", UNKNOWN_SOURCE):
        _record(m, app)
    snap = m.snapshot()
    assert snap["counters"]["source_apps_folded"] == 1
