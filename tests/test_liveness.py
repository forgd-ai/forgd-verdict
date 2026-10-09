"""`/livez` and the gitleaksd state in `/healthz`, against a live socket.

Each role is built from the shipped policy.yaml with `FORGD_GITLEAKS_SOCKET`
set, the way the entrypoint runs it. The daemon is a real process on a real
Unix socket: a stand-in that answers `GET /healthz` as gitleaksd does, and
the built sidecar as well when `FORGD_GITLEAKSD_BIN` points at one.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from conftest import ASGIClient

from forgd_verdict.detectors.gitleaks import BASELINE_CONFIG, HEALTHZ_TIMEOUT_S, LIVEZ_TIMEOUT_S
from forgd_verdict.intake.app import Intake
from forgd_verdict.otel.app import Collector
from forgd_verdict.policy import Policy, load_policy
from forgd_verdict.server.app import VerdictServer

REPO = Path(__file__).resolve().parents[1]
DAEMON_BIN = os.environ.get("FORGD_GITLEAKSD_BIN")

# Answers GET /healthz with 200, or with `hang` accepts and never replies.
STAND_IN = r"""
import http.server, socketserver, sys, time
sock, mode = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if mode == "hang":
            time.sleep(60)
        self.send_response(200 if self.path == "/healthz" else 404)
        self.send_header("content-length", "0")
        self.end_headers()
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        body = b"[]" if self.path == "/scan" else b""
        self.send_response(200 if self.path == "/scan" else 404)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    def get_request(self):
        conn, _ = self.socket.accept()
        return conn, ("uds", 0)
S(sock, H).serve_forever()
"""


def _start(argv: list[str], sock: Path) -> subprocess.Popen:
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(200):
        if sock.exists():
            return proc
        time.sleep(0.05)
    proc.kill()
    raise AssertionError(f"daemon never created {sock}")


def _daemon_argv(kind: str, sock: Path) -> list[str]:
    if kind == "gitleaksd":
        return [DAEMON_BIN, "--socket", str(sock), "--config", str(BASELINE_CONFIG)]
    return [sys.executable, "-c", STAND_IN, str(sock), kind]


@pytest.fixture
def sock_dir():
    # Not tmp_path: macOS caps a Unix socket path at 104 bytes.
    d = tempfile.mkdtemp(prefix="gl", dir="/tmp")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "store"))
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")


def _policy() -> Policy:
    return load_policy(str(REPO / "policy.yaml"))


def _server():
    return VerdictServer(_policy(), store=None)


def _collector():
    return Collector(_policy(), store=None)


def _intake():
    return Intake(_policy(), store=None)


ROLES = pytest.mark.parametrize(
    "build", [_server, _collector, _intake], ids=["verdict", "collector", "intake"])

DAEMONS = pytest.mark.parametrize("kind", [
    "stand-in",
    pytest.param("gitleaksd", marks=pytest.mark.skipif(
        not (DAEMON_BIN and Path(DAEMON_BIN).is_file()),
        reason="set FORGD_GITLEAKSD_BIN to a built sidecar/gitleaksd binary")),
])


async def _get(app, path: str):
    status, body = await ASGIClient(app).get(path)
    return status, json.loads(body) if isinstance(body, (bytes, str)) else body


@ROLES
@DAEMONS
async def test_livez_fails_when_the_daemon_dies_and_healthz_stays_up(
        build, kind, sock_dir, monkeypatch):
    sock = sock_dir / "gl.sock"
    proc = _start(_daemon_argv("serve" if kind == "stand-in" else kind, sock), sock)
    try:
        monkeypatch.setenv("FORGD_GITLEAKS_SOCKET", str(sock))
        app = build()

        assert await _get(app, "/livez") == (200, {"status": "ok", "gitleaksd": "ok"})
        status, body = await _get(app, "/healthz")
        assert (status, body["gitleaksd"]) == (200, "ok")

        proc.kill()
        proc.wait(timeout=10)

        assert await _get(app, "/livez") == (503, {"status": "down", "gitleaksd": "down"})
        status, body = await _get(app, "/healthz")
        assert (status, body["status"], body["gitleaksd"]) == (200, "ok", "down")
        status, body = await _get(app, "/health")
        assert (status, body["gitleaksd"]) == (200, "down")
    finally:
        proc.kill()
        proc.wait(timeout=10)


@ROLES
async def test_livez_passes_with_no_socket_configured(build, monkeypatch):
    monkeypatch.delenv("FORGD_GITLEAKS_SOCKET", raising=False)
    app = build()
    assert await _get(app, "/livez") == (
        200, {"status": "ok", "gitleaksd": "not_configured"})
    status, body = await _get(app, "/healthz")
    assert (status, body["gitleaksd"]) == (200, "not_configured")


# A route on each role that answers without touching the daemon.
OTHER_ROUTE = {"verdict": "/metrics", "collector": "/stats", "intake": "/nothing-here"}
# The module each role's app imports `daemon_state` into.
APP_MODULE = {"verdict": "forgd_verdict.server.app", "collector": "forgd_verdict.otel.app",
              "intake": "forgd_verdict.intake.app"}


@pytest.mark.parametrize("role,build", [
    ("verdict", _server), ("collector", _collector), ("intake", _intake)])
async def test_a_hung_daemon_does_not_hold_the_event_loop(
        role, build, sock_dir, monkeypatch):
    sock = sock_dir / "gl.sock"
    monkeypatch.delenv("FORGD_GITLEAKS_SOCKET", raising=False)
    app = build()
    module = importlib.import_module(APP_MODULE[role])
    timeouts: list[float] = []
    real_state = module.daemon_state

    async def daemon_state(sockets, timeout_s):
        timeouts.append(timeout_s)
        return await real_state(sockets, timeout_s)

    proc = _start(_daemon_argv("hang", sock), sock)
    try:
        # Built with no daemon, then pointed at the hung one: building with
        # it configured would fail the startup reachability check.
        app.gitleaks_sockets = [str(sock)]
        started = time.monotonic()
        probe = asyncio.create_task(_get(app, "/livez"))
        await asyncio.sleep(0.1)

        status, _ = await ASGIClient(app).get(OTHER_ROUTE[role])
        assert status in (401, 404)
        assert not probe.done()

        assert await probe == (503, {"status": "down", "gitleaksd": "down"})
        assert time.monotonic() - started < LIVEZ_TIMEOUT_S * 3

        monkeypatch.setattr(module, "daemon_state", daemon_state)
        status, body = await _get(app, "/healthz")
        assert (status, body["gitleaksd"]) == (200, "down")
        assert timeouts == [HEALTHZ_TIMEOUT_S]
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_a_disabled_gitleaks_tier_has_no_daemon_to_probe(monkeypatch):
    monkeypatch.setenv("FORGD_GITLEAKS_SOCKET", "/tmp/unused.sock")
    raw = json.loads(json.dumps(_policy().raw, default=str))
    raw["server"]["detectors"]["gitleaks"]["enabled"] = False
    assert Policy(raw=raw).for_profile("server").gitleaks_daemon() is None
    assert _policy().for_profile("server").gitleaks_daemon() == "/tmp/unused.sock"


async def test_a_busy_default_pool_does_not_fail_livez(sock_dir, monkeypatch):
    """Full scans run on asyncio's default pool. With it saturated, a ping
    queued behind them could not start inside its timeout, and /livez
    reported a healthy daemon down under exactly the load being served."""
    import concurrent.futures

    sock = sock_dir / "gl.sock"
    proc = _start(_daemon_argv("serve", sock), sock)
    loop = asyncio.get_running_loop()
    busy = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(busy)
    try:
        monkeypatch.setenv("FORGD_GITLEAKS_SOCKET", str(sock))
        app = _server()
        blockers = [loop.run_in_executor(None, time.sleep, LIVEZ_TIMEOUT_S * 3) for _ in range(3)]
        assert await _get(app, "/livez") == (200, {"status": "ok", "gitleaksd": "ok"})
        await asyncio.gather(*blockers)
    finally:
        busy.shutdown(wait=False)
        proc.kill()
        proc.wait(timeout=10)


async def test_the_collector_answers_livez_while_a_batch_is_scanned(tmp_path, monkeypatch):
    """A batch was scanned on the event loop, holding /livez and /health for
    its whole length: long enough to be restarted mid-export."""
    from test_otel_collector import auth, code_batch, make_policy

    from forgd_verdict.otel.collect import collect as real
    from forgd_verdict.store.local import LocalFileStore

    monkeypatch.delenv("FORGD_GITLEAKS_SOCKET", raising=False)
    answered = threading.Event()

    def slow_collect(*a, **kw):
        # Holds the batch until /livez has answered. On the event loop this
        # would hold /livez too, until the wait gave up.
        answered.wait(10)
        return real(*a, **kw)

    monkeypatch.setattr("forgd_verdict.otel.app.collect", slow_collect)
    app = Collector(make_policy(), store=LocalFileStore(tmp_path / "findings", instance="t"))
    client = ASGIClient(app)
    export = asyncio.create_task(client.post("/v1/logs", code_batch(), auth()))
    await asyncio.sleep(0.1)
    status, _ = await client.get("/livez")
    assert status == 200
    assert not export.done()
    answered.set()
    status, _ = await export
    assert status == 200
    app.close()
