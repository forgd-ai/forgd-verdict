"""The Compliance client's transport: a dropped connection, a short read, a
read timeout or an unparsable 200 is retried, and when the retries run out
it is a ComplianceError carrying the exception's type name and nothing
read from the wire."""

from __future__ import annotations

import json
import socket
import threading
import time
import traceback

import pytest
from test_compliance import SEEDED_CURSOR, SESSION, _ingest_with, transcript

from forgd_verdict.compliance.client import ComplianceClient, ComplianceError
from forgd_verdict.managed.client import ManagedAgentsClient

KEY = "sk-ant-" + "api01-SYNTHETIC-not-a-key"  # gitleaks:allow
SENTINEL = "SENTINEL-transcript-text-7f3a"
OK_BODY = b'{"data": [], "next_page": null}'
CLIENTS = [ComplianceClient, ManagedAgentsClient]


class RawServer:
    """A loopback server that hands each connection to `behaviour(server,
    conn, attempt, path)`, one thread per connection. `http.server` cannot
    send a short body or drop a connection before the status line."""

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.release = threading.Event()
        self.paths: list[str] = []
        self._lock = threading.Lock()
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.base = f"http://127.0.0.1:{self._sock.getsockname()[1]}"
        threading.Thread(target=self._accept_loop, daemon=True).start()

    @property
    def attempts(self) -> int:
        return len(self.paths)

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                request += chunk
            path = request.split(b" ", 2)[1].decode().split("?")[0]
            with self._lock:
                self.paths.append(path)
                attempt = len(self.paths)
            self.behaviour(self, conn, attempt, path)
        except OSError:
            # The client times out or retries and closes its end while this
            # thread is still reading or sending.
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.release.set()
        self._sock.close()


def respond(conn, status: int, body: bytes, headers: dict[str, str] | None = None,
            declared_length: int | None = None) -> None:
    head = [f"HTTP/1.1 {status} X",
            f"content-length: {len(body) if declared_length is None else declared_length}",
            "connection: close"]
    head += [f"{name}: {value}" for name, value in (headers or {}).items()]
    conn.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + body)


def ok(server, conn, attempt, path):
    respond(conn, 200, OK_BODY)


def disconnect(server, conn, attempt, path):
    pass


def truncated(server, conn, attempt, path):
    respond(conn, 200, b'{"data": "' + SENTINEL.encode(), declared_length=4096)


def stall(server, conn, attempt, path):
    server.release.wait(10)


FAILURES = {
    "RemoteDisconnected": disconnect,
    "IncompleteRead": truncated,
    "TimeoutError": stall,
}


def first_then_ok(failure):
    def behaviour(server, conn, attempt, path):
        (failure if attempt == 1 else ok)(server, conn, attempt, path)
    return behaviour


@pytest.fixture
def sleeps(monkeypatch):
    """Backoff delays the client asked for. The rate limiter's sub-second
    pacing is left out."""
    delays: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda seconds: delays.append(seconds))
    return delays


@pytest.fixture
def serve():
    servers: list[RawServer] = []

    def start(behaviour) -> RawServer:
        server = RawServer(behaviour)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def make_client(client_class, server, max_retries=4):
    return client_class(api_key=KEY, base_url=server.base, timeout_s=1.0,
                        per_minute=10**9, max_retries=max_retries)


def backoffs(delays):
    return [delay for delay in delays if delay >= 0.5]


# -- new behaviour ------------------------------------------------------------

@pytest.mark.parametrize("client_class", CLIENTS)
@pytest.mark.parametrize("kind", sorted(FAILURES))
def test_a_transient_failure_is_retried(client_class, kind, serve, sleeps):
    server = serve(first_then_ok(FAILURES[kind]))
    assert make_client(client_class, server).get("/v1/x") == json.loads(OK_BODY)
    assert server.attempts == 2
    assert backoffs(sleeps) == [1]


@pytest.mark.parametrize("client_class", CLIENTS)
@pytest.mark.parametrize("kind", sorted(FAILURES))
def test_exhausted_retries_name_the_failure_and_chain_nothing(client_class, kind, serve,
                                                               sleeps):
    server = serve(FAILURES[kind])
    with pytest.raises(ComplianceError) as caught:
        make_client(client_class, server, max_retries=1).get("/v1/x")
    err = caught.value
    assert (err.status, err.body) == (0, kind)
    assert err.__cause__ is None and err.__context__ is None
    assert server.attempts == 2


@pytest.mark.parametrize("client_class", CLIENTS)
def test_a_200_that_is_not_json_is_retried_then_refused(client_class, serve, sleeps):
    server = serve(lambda s, conn, attempt, path: respond(conn, 200, b"<html>proxy</html>"))
    with pytest.raises(ComplianceError) as caught:
        make_client(client_class, server, max_retries=1).get("/v1/x")
    assert (caught.value.status, caught.value.body) == (0, "JSONDecodeError")
    assert caught.value.__context__ is None
    assert server.attempts == 2


@pytest.mark.parametrize("client_class", CLIENTS)
def test_a_200_that_is_not_a_json_object_is_refused_without_retry(client_class, serve,
                                                                   sleeps):
    server = serve(lambda s, conn, attempt, path: respond(conn, 200, b"[1, 2]"))
    with pytest.raises(ComplianceError) as caught:
        make_client(client_class, server).get("/v1/x")
    assert caught.value.status == 0
    assert server.attempts == 1


@pytest.mark.parametrize("client_class", CLIENTS)
def test_a_5xx_whose_body_is_cut_off_is_still_retried(client_class, serve, sleeps):
    def behaviour(server, conn, attempt, path):
        if attempt == 1:
            respond(conn, 503, b"partial", declared_length=4096)
        else:
            ok(server, conn, attempt, path)
    server = serve(behaviour)
    assert make_client(client_class, server).get("/v1/x") == json.loads(OK_BODY)
    assert server.attempts == 2


# -- existing behaviour, pinned -----------------------------------------------

@pytest.mark.parametrize("client_class", CLIENTS)
def test_a_503_is_retried(client_class, serve, sleeps):
    def behaviour(server, conn, attempt, path):
        if attempt == 1:
            respond(conn, 503, b"")
        else:
            ok(server, conn, attempt, path)
    server = serve(behaviour)
    assert make_client(client_class, server).get("/v1/x") == json.loads(OK_BODY)
    assert server.attempts == 2


@pytest.mark.parametrize("client_class", CLIENTS)
def test_a_429_waits_for_retry_after(client_class, serve, sleeps):
    def behaviour(server, conn, attempt, path):
        if attempt == 1:
            respond(conn, 429, b"", headers={"retry-after": "7"})
        else:
            ok(server, conn, attempt, path)
    server = serve(behaviour)
    make_client(client_class, server).get("/v1/x")
    assert backoffs(sleeps) == [7]


@pytest.mark.parametrize("client_class", CLIENTS)
def test_a_400_is_not_retried(client_class, serve, sleeps):
    server = serve(lambda s, conn, attempt, path: respond(conn, 400, b"{}"))
    with pytest.raises(ComplianceError) as caught:
        make_client(client_class, server).get("/v1/x")
    assert caught.value.status == 400
    assert server.attempts == 1


# -- privacy ------------------------------------------------------------------

@pytest.mark.parametrize("behaviour", [
    truncated,
    lambda s, conn, attempt, path: respond(conn, 200, f"<p>{SENTINEL}</p>".encode()),
], ids=["short-read", "not-json"])
def test_nothing_read_from_the_wire_reaches_the_error(behaviour, serve, sleeps, caplog):
    server = serve(behaviour)
    with caplog.at_level("DEBUG"), pytest.raises(ComplianceError) as caught:
        make_client(ComplianceClient, server, max_retries=1).get("/v1/x")
    err = caught.value
    rendered = [str(err), repr(err), err.body, "".join(traceback.format_exception(err)),
                caplog.text]
    assert not [text for text in rendered if SENTINEL in text]


# -- the scanner ----------------------------------------------------------------

def test_a_session_whose_fetch_keeps_dropping_costs_that_session_only(
        tmp_path, monkeypatch, serve, sleeps):
    sessions = [dict(SESSION, id=f"clls_{index}") for index in range(3)]
    listing = "/v1/compliance/apps/sessions/local"

    def behaviour(server, conn, attempt, path):
        if path == listing:
            respond(conn, 200, json.dumps({"data": sessions, "next_page": None}).encode())
        elif path == f"{listing}/clls_1/messages":
            disconnect(server, conn, attempt, path)
        else:
            respond(conn, 200, json.dumps({"data": transcript(), "next_page": None}).encode())

    server = serve(behaviour)
    client = make_client(ComplianceClient, server, max_retries=1)
    summary, state, store = _ingest_with(tmp_path, monkeypatch, client)
    assert summary["orgs_failed"] == 0
    assert summary["sessions_scanned"] == 2
    assert summary["sessions_failed"] == 1
    assert {record.session_id for record in store.read_verdicts()} == {"clls_0", "clls_2"}
    assert server.paths.count(f"{listing}/clls_1/messages") == 2
    assert state["cursor:sessions:local"] == SEEDED_CURSOR
