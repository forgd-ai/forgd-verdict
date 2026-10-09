"""The collector reads a gzip-compressed export, within a bound on the
decompressed size.

OTLP exporters may send `Content-Encoding: gzip`; answered 400, such an
export was dropped and never scanned.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import zlib

import pytest
from conftest import ASGIClient
from test_otel_collector import SEEDED, auth, code_batch, make_policy, stored
from test_otel_payload import RESOURCE, logs_protobuf

from forgd_verdict.otel.app import Collector
from forgd_verdict.store.local import LocalFileStore


@pytest.fixture
def collector(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    c = Collector(make_policy(max_body_bytes=1_000_000),
                  store=LocalFileStore(tmp_path / "f", instance="t"))
    yield c
    c.close()


def _post(app, path, body, headers):
    return asyncio.run(ASGIClient(app).post(path, body, headers))


def _gz(body) -> dict:
    return auth({"content-encoding": "gzip"})


def _found(collector) -> bool:
    return any(r.findings_count for r in stored(collector))


def test_a_gzip_json_export_is_scanned(collector):
    status, _ = _post(collector, "/v1/logs", gzip.compress(code_batch()), _gz(None))
    assert status == 200
    assert _found(collector)


def test_a_gzip_protobuf_export_is_scanned(collector):
    body = logs_protobuf([{"attributes": {"event.name": "claude_code.user_prompt",
                                          "prompt": f"deploy with {SEEDED}",
                                          "session.id": "s-1"}, "body": ""}], RESOURCE)
    headers = {**_gz(None), "content-type": "application/x-protobuf"}
    status, _ = _post(collector, "/v1/logs", gzip.compress(body), headers)
    assert status == 200
    assert _found(collector)


def test_every_member_of_a_multi_member_gzip_is_read(collector):
    batch = code_batch()
    cut = batch.index(SEEDED.encode()) + 6
    body = gzip.compress(batch[:cut]) + gzip.compress(batch[cut:])
    status, _ = _post(collector, "/v1/logs", body, _gz(None))
    assert status == 200
    assert _found(collector)


def test_the_encoding_name_is_case_insensitive(collector):
    status, _ = _post(collector, "/v1/logs", gzip.compress(code_batch()),
                      auth({"content-encoding": " GZip "}))
    assert status == 200


def test_identity_is_read_as_is(collector):
    status, _ = _post(collector, "/v1/logs", code_batch(),
                      auth({"content-encoding": "identity"}))
    assert status == 200


def test_a_body_that_decompresses_past_the_bound_is_413(collector):
    bomb = gzip.compress(b"{" + b" " * 50_000_000 + b"}")
    assert len(bomb) < 1_000_000
    status, body = _post(collector, "/v1/logs", bomb, _gz(None))
    assert status == 413, body


def test_a_bomb_split_across_members_is_413(collector):
    member = gzip.compress(b" " * 900_000)
    status, _ = _post(collector, "/v1/logs", member * 3, _gz(None))
    assert status == 413


def test_corrupt_gzip_is_400(collector):
    body = gzip.compress(code_batch())
    status, _ = _post(collector, "/v1/logs", body[:20] + b"\x00" * 30, _gz(None))
    assert status == 400


def test_trailing_garbage_after_a_member_is_400(collector):
    status, _ = _post(collector, "/v1/logs", gzip.compress(code_batch()) + b"junk",
                      _gz(None))
    assert status == 400


def test_raw_deflate_labelled_gzip_is_400(collector):
    status, _ = _post(collector, "/v1/logs", zlib.compress(code_batch()), _gz(None))
    assert status == 400


@pytest.mark.parametrize("encoding", ["br", "zstd", "deflate", "gzip, gzip", "x-gzip2"])
def test_an_encoding_not_supported_is_415(collector, encoding):
    status, body = _post(collector, "/v1/logs", gzip.compress(code_batch()),
                         auth({"content-encoding": encoding}))
    assert status == 415
    assert "gzip" in json.dumps(body)


def test_gzip_metrics_are_accepted(collector):
    body = json.dumps({"resourceMetrics": [{"scopeMetrics": [{"metrics": [
        {"name": "claude_code.cost.usage"}]}]}]}).encode()
    status, _ = _post(collector, "/v1/metrics", gzip.compress(body), _gz(None))
    assert status == 200
    assert "claude_code.cost.usage" in collector._metrics_seen
