"""Valid JSON in a shape OTLP does not have is a 400, never a 500.

An exporter retries a 5xx forever, so an AttributeError out of the decoder
turned one malformed export into an endless retry.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import random

import pytest
from conftest import ASGIClient
from test_otel_collector import auth, make_policy

from forgd_verdict.otel.app import Collector
from forgd_verdict.otel.payload import DecodedTooLarge, DecodeError, TooManyRecords, decode
from forgd_verdict.store.local import LocalFileStore


def _rec(value) -> dict:
    return {"resourceLogs": [{"scopeLogs": [{"logRecords": [
        {"attributes": [{"key": "prompt", "value": value}]}]}]}]}


SHAPES = {
    "resourceLogs[int]": {"resourceLogs": [5]},
    "resourceLogs[str]": {"resourceLogs": ["x"]},
    "resource_logs[list]": {"resource_logs": [[1]]},
    "scopeLogs[int]": {"resourceLogs": [{"scopeLogs": [7]}]},
    "logRecords[str]": {"resourceLogs": [{"scopeLogs": [{"logRecords": ["rec"]}]}]},
    "logRecords[list]": {"resourceLogs": [{"scopeLogs": [{"logRecords": [[1, 2]]}]}]},
    "attributes str": {"resourceLogs": [{"scopeLogs": [{"logRecords": [
        {"attributes": "a"}]}]}]},
    "arrayValue str": _rec({"arrayValue": "oops"}),
    "arrayValue list": _rec({"arrayValue": [1]}),
    "kvlistValue int": _rec({"kvlistValue": 3}),
    "kvlistValue values str": _rec({"kvlistValue": {"values": "v"}}),
    "arrayValue.values dict": _rec({"arrayValue": {"values": {"a": 1}}}),
    "nested arrayValue str": _rec({"arrayValue": {"values": [{"arrayValue": "x"}]}}),
    "body arrayValue int": {"resourceLogs": [{"scopeLogs": [{"logRecords": [
        {"body": {"arrayValue": 1}}]}]}]},
    "resource str": {"resourceLogs": [{"resource": "r", "scopeLogs": []}]},
    "resource attributes int": {"resourceLogs": [{"resource": {"attributes": 3}}]},
    "resourceSpans[int]": {"resourceSpans": [5]},
    "scopeSpans[str]": {"resourceSpans": [{"scopeSpans": ["s"]}]},
    "spans[str]": {"resourceSpans": [{"scopeSpans": [{"spans": ["s"]}]}]},
    "span events[int]": {"resourceSpans": [{"scopeSpans": [{"spans": [{"events": [1]}]}]}]},
    "span events str": {"resourceSpans": [{"scopeSpans": [{"spans": [{"events": "e"}]}]}]},
    "span name dict": {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": {"a": 1}}]}]}]},
}


def _signal(doc) -> str:
    return "traces" if "resourceSpans" in doc else "logs"


@pytest.mark.parametrize("name", list(SHAPES))
def test_decode_raises_only_decode_error(name):
    doc = SHAPES[name]
    with contextlib.suppress(DecodeError):
        decode(json.dumps(doc).encode(), "application/json", _signal(doc))


def test_the_collector_answers_every_shape_without_a_5xx(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    app = Collector(make_policy(), store=LocalFileStore(tmp_path / "f", instance="t"))

    async def go():
        client = ASGIClient(app)
        out = {}
        for name, doc in SHAPES.items():
            status, _ = await client.post(f"/v1/{_signal(doc)}", json.dumps(doc).encode(),
                                          auth())
            out[name] = status
        return out

    try:
        statuses = asyncio.run(go())
    finally:
        app.close()
    assert {n: s for n, s in statuses.items() if s >= 500} == {}


_REFUSALS = (DecodeError, TooManyRecords, DecodedTooLarge)


def test_random_json_shapes_raise_only_decode_errors():
    rng = random.Random(10)
    leaves = [None, 1, "s", [], {}, [1], {"a": 1}, True, 1.5]
    keys = ["resourceLogs", "scopeLogs", "logRecords", "attributes", "key", "value",
            "arrayValue", "kvlistValue", "values", "body", "resource", "resourceSpans",
            "scopeSpans", "spans", "events", "name", "stringValue"]

    def node(depth):
        roll = rng.random()
        if depth > 4 or roll < 0.3:
            return rng.choice(leaves)
        if roll < 0.6:
            return [node(depth + 1) for _ in range(rng.randint(0, 3))]
        return {rng.choice(keys): node(depth + 1) for _ in range(rng.randint(0, 3))}

    for _ in range(3000):
        body = json.dumps({"resourceLogs": node(0), "resourceSpans": node(0)}).encode()
        for signal in ("logs", "traces"):
            with contextlib.suppress(*_REFUSALS):
                decode(body, "application/json", signal)


def test_mutated_protobuf_raises_only_decode_errors():
    from test_otel_payload import logs_protobuf

    rng = random.Random(11)
    base = logs_protobuf([{"attributes": {"event.name": "x", "prompt": "hello"},
                           "body": "b"}], {"service.name": "s"})
    for _ in range(3000):
        body = bytearray(base)
        for _ in range(rng.randint(1, 4)):
            body[rng.randrange(len(body))] = rng.randrange(256)
        for signal in ("logs", "traces"):
            with contextlib.suppress(*_REFUSALS):
                decode(bytes(body), "application/x-protobuf", signal)
