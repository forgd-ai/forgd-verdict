"""The verdict server's pre-auth body budget: bodies read before their
signature is verified hold at most `server.preauth_body_budget_bytes`
between them, a request past it is answered 503 without its body being
read, and every request returns its share on every exit."""

from __future__ import annotations

import asyncio
import json
import logging
import time

import pytest
from conftest import WHSEC, frame, make_policy, sign

from forgd_verdict.server import __main__ as entry
from forgd_verdict.server.app import VerdictServer

BODY = json.dumps(frame()).encode()
MAX = 4096


def _server(**server) -> VerdictServer:
    cfg = {"mode": "enforce", "secrets": [WHSEC], "csv_path": None,
           "max_body_bytes": MAX, "preauth_body_budget_bytes": 2 * MAX,
           "metrics_token": "m" * 32, **server}
    logger = logging.getLogger("forgd_verdict_test.preauth_budget")
    return VerdictServer(make_policy(detectors={"gitleaks": {"enabled": False,
                                                             "severity": "block"}},
                                     server=cfg), logger=logger)


def _forged(content_length: int | None = None) -> dict[str, str]:
    """Headers that pass the precheck and fail the signature."""
    headers = {"webhook-id": "msg_forged", "webhook-timestamp": str(int(time.time())),
               "webhook-signature": "v1,AAAA", "content-type": "application/json"}
    if content_length is not None:
        headers["content-length"] = str(content_length)
    return headers


def _scope(headers: dict[str, str]) -> dict:
    return {"type": "http", "method": "POST", "path": "/hook", "query_string": b"",
            "headers": [(k.encode("latin-1"), v.encode("latin-1"))
                        for k, v in headers.items()]}


class Body:
    """An ASGI `receive` over `chunks`, counting the messages handed out. A
    None chunk is a client disconnect. `then` runs before each message is
    returned."""

    def __init__(self, *chunks: bytes, then=None):
        self.chunks = list(chunks)
        self.reads = 0
        self.then = then

    async def __call__(self) -> dict:
        if not self.chunks:
            return {"type": "http.disconnect"}
        self.reads += 1
        if self.then is not None:
            await self.then(self.reads)
        chunk = self.chunks.pop(0)
        if chunk is None:
            return {"type": "http.disconnect"}
        return {"type": "http.request", "body": chunk, "more_body": bool(self.chunks)}


async def _drive(server: VerdictServer, headers: dict[str, str], receive) -> tuple[int, dict, dict]:
    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    await server(_scope(headers), receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return (start["status"], json.loads(payload),
            {k.decode(): v.decode() for k, v in start["headers"]})


# -- refused before the body is read ------------------------------------------


async def test_an_exhausted_budget_is_503_with_retry_after_and_no_body_read():
    server = _server()
    held = server.preauth.hold()
    assert held.take(server.preauth.limit)
    receive = Body(b"x" * 10)
    status, body, headers = await _drive(server, _forged(), receive)
    assert (status, body) == (503, {"error": "busy"})
    assert headers["retry-after"] == "1"
    assert receive.reads == 0
    assert server.metrics.snapshot()["counters"]["preauth_budget_exhausted"] == 1
    held.release()
    assert server.preauth.in_use == 0


async def test_a_declared_length_with_no_room_is_refused_unread():
    server = _server()
    held = server.preauth.hold()
    assert held.take(server.preauth.limit - 100)
    receive = Body(b"x" * 200)
    status, body, _ = await _drive(server, _forged(content_length=200), receive)
    assert (status, body) == (503, {"error": "busy"})
    assert receive.reads == 0
    held.release()


async def test_a_declared_length_over_max_body_is_413_unread():
    server = _server()
    receive = Body(b"x" * 10)
    status, body, _ = await _drive(server, _forged(content_length=MAX + 1), receive)
    assert (status, body) == (413, {"error": "payload_too_large"})
    assert receive.reads == 0


async def test_a_request_failing_the_precheck_takes_nothing_from_the_budget():
    server = _server()
    receive = Body(b"x" * 10)
    headers = _forged()
    del headers["webhook-signature"]
    status, _, _ = await _drive(server, headers, receive)
    assert status == 401
    assert receive.reads == 0
    assert server.preauth.peak == 0


# -- a signed request while others hold part of the budget ----------------------


async def test_a_signed_request_is_served_while_the_budget_is_partly_used():
    server = _server()
    held = server.preauth.hold()
    assert held.take(server.preauth.limit - len(BODY))
    status, body, _ = await _drive(server, sign(BODY), Body(BODY))
    assert status == 200
    assert body["action"] == "allow"
    assert server.preauth.in_use == server.preauth.limit - len(BODY)
    held.release()
    assert server.preauth.in_use == 0


async def test_a_signed_body_split_into_chunks_verifies_as_one():
    server = _server()
    parts = [BODY[i:i + 7] for i in range(0, len(BODY), 7)]
    status, body, _ = await _drive(server, sign(BODY), Body(*parts))
    assert status == 200 and body["action"] == "allow"
    assert server.preauth.peak == len(BODY)


async def test_the_budget_filling_mid_body_is_503_and_the_rest_is_not_read():
    server = _server()
    other = server.preauth.hold()

    async def fill(n: int) -> None:
        if n == 2:
            assert other.take(server.preauth.limit - server.preauth.in_use)

    receive = Body(b"a" * 100, b"b" * 100, b"c" * 100, then=fill)
    status, body, _ = await _drive(server, _forged(), receive)
    assert (status, body) == (503, {"error": "busy"})
    assert receive.reads == 2
    assert server.preauth.in_use == other.held
    other.release()
    assert server.preauth.in_use == 0


# -- the share is returned on every exit -----------------------------------------


async def test_released_after_a_signed_request():
    server = _server()
    await _drive(server, sign(BODY), Body(BODY))
    assert server.preauth.in_use == 0 and server.preauth.peak == len(BODY)


async def test_released_after_a_bad_signature():
    server = _server()
    status, _, _ = await _drive(server, _forged(), Body(b"x" * 300))
    assert status == 401
    assert server.preauth.in_use == 0 and server.preauth.peak == 300


async def test_released_after_a_body_over_max_body_mid_read():
    server = _server()
    status, _, _ = await _drive(server, _forged(), Body(b"x" * MAX, b"y"))
    assert status == 413
    assert server.preauth.in_use == 0


async def test_released_after_a_client_disconnect_mid_body():
    server = _server()
    status, _, _ = await _drive(server, _forged(), Body(b"x" * 500, None))
    assert status == 401
    assert server.preauth.in_use == 0 and server.preauth.peak == 500


async def test_released_when_receive_raises_mid_body():
    server = _server()

    async def boom(n: int) -> None:
        if n == 2:
            raise ConnectionResetError("peer went away")

    with pytest.raises(ConnectionResetError):
        await _drive(server, _forged(), Body(b"x" * 500, b"y" * 500, then=boom))
    assert server.preauth.in_use == 0 and server.preauth.peak == 500


async def test_released_when_the_request_task_is_cancelled_mid_body():
    server = _server()
    started = asyncio.Event()

    async def stall(n: int) -> None:
        if n == 2:
            started.set()
            await asyncio.Event().wait()

    task = asyncio.ensure_future(
        _drive(server, _forged(), Body(b"x" * 500, b"y" * 500, then=stall)))
    await started.wait()
    assert server.preauth.in_use == 500
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await task
    assert server.preauth.in_use == 0


async def test_a_body_that_does_not_arrive_in_time_is_503_and_released():
    server = _server(body_read_timeout_s=0.01)

    async def stall(n: int) -> None:
        if n == 2:
            await asyncio.Event().wait()

    status, body, headers = await _drive(server, _forged(),
                                         Body(b"x" * 500, b"y", then=stall))
    assert (status, body) == (503, {"error": "body_timeout"})
    assert headers["retry-after"] == "1"
    assert server.preauth.in_use == 0
    assert server.metrics.snapshot()["counters"]["body_timeout"] == 1


async def test_concurrent_unauthenticated_bodies_never_exceed_the_budget():
    server = _server(preauth_body_budget_bytes=MAX)
    gate = asyncio.Event()
    peak_seen = []

    async def wait_for_gate(n: int) -> None:
        peak_seen.append(server.preauth.in_use)
        if n == 2:
            await gate.wait()

    receives = [Body(b"x" * 1000, b"", then=wait_for_gate) for _ in range(10)]
    tasks = [asyncio.ensure_future(_drive(server, _forged(), r)) for r in receives]
    while not all(t.done() or r.reads >= 2 for t, r in zip(tasks, receives, strict=True)):
        await asyncio.sleep(0)
    gate.set()
    statuses = sorted(s for s, _, _ in await asyncio.gather(*tasks))
    assert max(peak_seen) <= MAX
    assert server.preauth.peak <= MAX
    assert server.preauth.in_use == 0
    assert statuses.count(401) == 4 and statuses.count(503) == 6


# -- what an operator sees --------------------------------------------------------


async def test_metrics_report_the_budget():
    server = _server()
    await _drive(server, _forged(), Body(b"x" * 300))
    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "method": "GET", "path": "/metrics", "query_string": b"",
             "headers": [(b"authorization", ("Bearer " + "m" * 32).encode())]}
    await server(scope, receive, send)
    snap = json.loads(b"".join(m.get("body", b"") for m in sent
                               if m["type"] == "http.response.body"))
    assert snap["preauth_body"] == {"budget_bytes": 2 * MAX, "in_use_bytes": 0,
                                    "peak_bytes": 300}


# -- the settings ------------------------------------------------------------------


def test_the_shipped_defaults():
    policy = make_policy()
    assert policy.max_body_bytes == 64 * 1024 * 1024
    assert policy.preauth_body_budget_bytes == 256 * 1024 * 1024
    assert policy.body_read_timeout_s == 15
    assert policy.limit_concurrency == 1024


def test_a_budget_below_max_body_is_refused():
    policy = make_policy(server={"max_body_bytes": 1000, "preauth_body_budget_bytes": 999})
    with pytest.raises(ValueError, match="preauth_body_budget_bytes"):
        _ = policy.preauth_body_budget_bytes


@pytest.mark.parametrize("key", ["max_body_bytes", "preauth_body_budget_bytes",
                                 "limit_concurrency"])
@pytest.mark.parametrize("value", [0, -1, None, True, "1024", 1.5])
def test_a_size_setting_that_is_not_a_positive_integer_is_refused(key, value):
    policy = make_policy(server={key: value})
    with pytest.raises(ValueError, match=f"server.{key}"):
        getattr(policy, key)


@pytest.mark.parametrize("value", [0, -1, None, "soon", float("inf"), float("nan")])
def test_a_body_read_timeout_that_is_not_positive_is_refused(value):
    policy = make_policy(server={"body_read_timeout_s": value})
    with pytest.raises(ValueError, match="body_read_timeout_s"):
        _ = policy.body_read_timeout_s


def test_the_server_refuses_to_build_with_a_bad_budget():
    with pytest.raises(ValueError, match="preauth_body_budget_bytes"):
        _server(preauth_body_budget_bytes=MAX - 1)


def _main(tmp_path, monkeypatch, server_yaml: str):
    import sys

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("privacy:\n  allow_unsalted: true\nserver:\n" + server_yaml)
    seen: dict = {}

    class FakeUvicorn:
        @staticmethod
        def run(*args, **kwargs):
            seen.update(kwargs)

    monkeypatch.setenv("FORGD_VERDICT_POLICY", "")
    monkeypatch.setitem(sys.modules, "uvicorn", FakeUvicorn)
    return entry.main(["--policy", str(policy_file)]), seen


def test_serve_passes_limit_concurrency_to_uvicorn(tmp_path, monkeypatch):
    code, seen = _main(tmp_path, monkeypatch, "  limit_concurrency: 77\n")
    assert code == 0
    assert seen["limit_concurrency"] == 77


def test_serve_uses_the_default_limit_concurrency(tmp_path, monkeypatch):
    code, seen = _main(tmp_path, monkeypatch, "  port: 8000\n")
    assert code == 0
    assert seen["limit_concurrency"] == 1024


@pytest.mark.parametrize("server_yaml", ["  limit_concurrency: 0\n",
                                         "  preauth_body_budget_bytes: 1\n",
                                         "  body_read_timeout_s: 0\n"])
def test_serve_refuses_to_start_on_a_bad_body_setting(tmp_path, monkeypatch, capsys,
                                                      server_yaml):
    code, seen = _main(tmp_path, monkeypatch, server_yaml)
    assert code == 2 and not seen
    assert "refusing to start the verdict server" in capsys.readouterr().err
