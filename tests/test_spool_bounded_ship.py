"""No spool file is retried forever, and none is deleted unaccepted.

The intake takes at most `max_body_bytes` per request. A spool file is
bounded at append so each one ships whole within it; a refusal that cannot change on a retry sidelines the
file instead of parking it for the next drain."""

from __future__ import annotations

import io
import json
import urllib.error

import pytest
from conftest import ASGIClient

from forgd_verdict.hook.ship import ship_to_endpoint
from forgd_verdict.intake.app import DEFAULT_MAX_BODY, MAX_RECORDS, Intake
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store import spool as spool_mod
from forgd_verdict.store.base import SOURCE_CODE_HOOK, VerdictRecord
from forgd_verdict.store.spool import FAILED_SUFFIX, REJECTED_SUFFIX, Spool, drain

TOKEN = "intake-token-for-alice-0123456789"


def _rec(i=0) -> VerdictRecord:
    return VerdictRecord(source=SOURCE_CODE_HOOK, observed_at="2026-10-06T10:00:00Z",
                         action="allow", request_id=f"UserPromptSubmit:prompt:r{i}")


# -- the spool bounds each file ----------------------------------------------


def test_a_day_past_the_file_cap_rotates_and_keeps_every_record(tmp_path, monkeypatch):
    monkeypatch.setattr(spool_mod, "MAX_FILE_BYTES", 4096)
    spool = Spool(tmp_path)
    for i in range(40):
        appended = spool.append(_rec(i))
        assert appended
    files = sorted(tmp_path.glob("*.jsonl"))
    assert len(files) > 1
    line = len(_rec(0).to_json()) + 1
    assert all(f.stat().st_size <= 4096 + 2 * line for f in files)
    claimed = spool.claim()
    ids = sorted(r.request_id for p in claimed for r in Spool.read(p))
    assert ids == sorted(f"UserPromptSubmit:prompt:r{i}" for i in range(40))


def test_the_default_file_cap_fits_the_intakes_default_bounds():
    smallest = len(VerdictRecord(source=SOURCE_CODE_HOOK).to_json()) + 1
    assert spool_mod.MAX_FILE_BYTES // smallest <= MAX_RECORDS
    assert spool_mod.MAX_FILE_BYTES < DEFAULT_MAX_BODY


# -- a permanent refusal sidelines, a transient one parks -----------------------


def _answering(monkeypatch, status, body=b"{}"):
    def fake(req, timeout, ca_file=None):
        if 200 <= status < 300:
            class Resp(io.BytesIO):
                def __enter__(self): return self
                def __exit__(self, *a): return False
            r = Resp(body)
            r.status = status
            return r
        raise urllib.error.HTTPError(req.full_url, status, "x", {}, io.BytesIO(body))
    monkeypatch.setattr("forgd_verdict.hook.ship.open_url", fake)


@pytest.mark.parametrize("status", [400, 413])
def test_a_permanent_refusal_is_sidelined_not_retried(tmp_path, monkeypatch, status):
    spool = Spool(tmp_path)
    spool.append(_rec())
    _answering(monkeypatch, status, json.dumps({"error": "x"}).encode())
    ship = ship_to_endpoint("https://x/intake", "tok")
    first = drain(spool, ship)
    assert first["rejected"] == 1 and first["failed"] == 0
    assert list(tmp_path.glob(f"*{REJECTED_SUFFIX}"))
    assert drain(spool, ship)["batches"] == 0


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_a_transient_refusal_is_parked_and_retried(tmp_path, monkeypatch, status):
    spool = Spool(tmp_path)
    spool.append(_rec())
    _answering(monkeypatch, status)
    ship = ship_to_endpoint("https://x/intake", "tok")
    assert drain(spool, ship)["failed"] == 1
    assert list(tmp_path.glob(f"*{FAILED_SUFFIX}"))
    assert drain(spool, ship)["batches"] == 1


# -- the intake's own bound ------------------------------------------------------


def _intake(tmp_path, **intake):
    return Intake(Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "alice-laptop", "token": TOKEN}], **intake},
        "privacy": {"hash_salt": "s"}, "detectors": {"gitleaks": {"enabled": False}}})),
        store=LocalFileStore(tmp_path / "store", instance="t"))


def _route_to(monkeypatch, app):
    """ship.py's HTTP call, answered by `app` in-process."""
    import asyncio

    def fake(req, timeout, ca_file=None):
        status, out = asyncio.new_event_loop().run_until_complete(ASGIClient(app).post(
            req.selector, req.data, {k.lower(): v for k, v in req.header_items()}))
        body = json.dumps(out).encode()
        if not 200 <= status < 300:
            raise urllib.error.HTTPError(req.full_url, status, "x", {}, io.BytesIO(body))
        resp = io.BytesIO(body)
        resp.status = status
        return resp
    monkeypatch.setattr("forgd_verdict.hook.ship.open_url", fake)


async def test_a_store_outage_keeps_the_spool_file(tmp_path, monkeypatch):
    """End to end: the intake answers 503 and the laptop keeps the batch."""
    import concurrent.futures

    class Broken(LocalFileStore):
        def write_verdicts(self, records):
            raise OSError("store unavailable")

    app = Intake(Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "alice-laptop", "token": TOKEN}]},
        "privacy": {"hash_salt": "s"}, "detectors": {"gitleaks": {"enabled": False}}})),
        store=Broken(tmp_path / "store", instance="t"))
    spool = Spool(tmp_path / "spool")
    for i in range(3):
        spool.append(_rec(i))
    _route_to(monkeypatch, app)
    try:
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            result = pool.submit(drain, spool, ship_to_endpoint("https://x/intake", TOKEN)).result()
    finally:
        app.close()
    assert result["failed"] == 3 and result["rejected"] == 0 and result["shipped"] == 0
    assert not list((tmp_path / "spool").glob(f"*{REJECTED_SUFFIX}"))
    kept = [r for p in spool.claim() for r in Spool.read(p)]
    assert len(kept) == 3


async def test_a_rotated_spool_ships_in_full(tmp_path, monkeypatch):
    """End to end: rotated files each fit, so all of them are accepted."""
    monkeypatch.setattr(spool_mod, "MAX_FILE_BYTES", 3 * 600)
    app = _intake(tmp_path)
    spool = Spool(tmp_path / "spool")
    for i in range(30):
        spool.append(_rec(i))

    def ship(records):
        import asyncio

        body = ("\n".join(r.to_json() for r in records) + "\n").encode()
        status, out = asyncio.new_event_loop().run_until_complete(ASGIClient(app).post(
            "/intake", body, {"authorization": f"Bearer {TOKEN}",
                              "content-type": "application/x-ndjson"}))
        app.flush()
        return status == 200 and out["accepted"] == len(records)

    try:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            result = pool.submit(drain, spool, ship).result()
        stored = list(app.store.read_verdicts("1990-01-01T00:00:00Z", None))
    finally:
        app.close()
    assert result["shipped"] == 30 and result["failed"] == 0
    # Clean allows are stored as tally rows, each standing for several.
    from forgd_verdict.store.tally import weight

    assert sum(weight(r) for r in stored) == 30
