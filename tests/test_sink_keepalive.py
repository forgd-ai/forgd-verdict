"""The OTLP and Azure Monitor sinks reuse one connection within a flush.

A real loopback HTTP/1.1 server counts accepted TCP connections. The Azure
sink requires https, so its server presents a self-signed certificate that
the test trusts through SSL_CERT_FILE; the sink's own TLS settings are
untouched. The Azure credential is a stub.
"""

from __future__ import annotations

import datetime
import ipaddress
import ssl
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from forgd_verdict.sink.azmonitor import AzureMonitorSink
from forgd_verdict.sink.base import RedactedEvent, SinkConfig, safe_endpoint
from forgd_verdict.sink.otlp import OtlpSink, SinkSendFailed
from forgd_verdict.sink.pipeline import SinkPipeline

PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy",
              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD")
BODY_TEXT = b"UPSTREAM-RESPONSE-BODY"
STREAM = "/dataCollectionRules/dcr-0123456789abcdef/streams/Custom-Verdict_CL"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        server = self.server
        with server.lock:
            server.requests.append((self.command, self.path, len(body)))
        self.send_response(server.status)
        self.send_header("Content-Length", str(len(BODY_TEXT)))
        self.end_headers()
        self.wfile.write(BODY_TEXT)
        if server.drop_idle:
            self.close_connection = True

    def do_CONNECT(self):
        with self.server.lock:
            self.server.requests.append((self.command, self.path, 0))
        self.send_response(403)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.close_connection = True

    def log_message(self, *args):
        return None


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, context: ssl.SSLContext | None = None):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.lock = threading.Lock()
        self.requests: list[tuple[str, str, int]] = []
        self.opened = 0
        self.active = 0
        self.status = 200
        self.drop_idle = False
        if context is not None:
            self.socket = context.wrap_socket(self.socket, server_side=True)
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self.server_address[1]

    def process_request(self, request, client_address):
        with self.lock:
            self.opened += 1
            self.active += 1
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        super().shutdown_request(request)
        with self.lock:
            self.active -= 1

    def stop(self):
        self.shutdown()
        self.server_close()

    def wait_idle(self, timeout_s: float = 5.0) -> int:
        deadline = time.monotonic() + timeout_s
        while self.active and time.monotonic() < deadline:
            time.sleep(0.02)
        return self.active


def _self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context, cert_path


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for var in PROXY_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    # `urlopen` builds its opener, and reads the proxy environment, once.
    monkeypatch.setattr(urllib.request, "_opener", None)


@pytest.fixture
def otlp_server():
    server = _Server()
    yield server
    server.stop()


@pytest.fixture
def azure_server(tmp_path, monkeypatch):
    context, cert_path = _self_signed(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_path))
    server = _Server(context)
    yield server
    server.stop()


def _otlp(server) -> OtlpSink:
    return OtlpSink(SinkConfig(name="otlp", endpoint=f"http://127.0.0.1:{server.port}"))


def _azure(server) -> AzureMonitorSink:
    config = SinkConfig(name="azmon", type="azure-monitor",
                        endpoint=f"https://localhost:{server.port}{STREAM}")
    return AzureMonitorSink(config, token_provider=lambda: ("stub-token", time.time() + 3600))


SINKS = {"otlp": ("otlp_server", _otlp), "azure-monitor": ("azure_server", _azure)}


@pytest.fixture(params=sorted(SINKS))
def built(request):
    fixture, make = SINKS[request.param]
    server = request.getfixturevalue(fixture)
    return server, make(server)


def _events(n: int = 3, size: int = 600_000) -> list[RedactedEvent]:
    return [RedactedEvent(kind="log", name=f"e{i}", observed_at="2026-10-05T00:00:00Z",
                          surface="claude-code", org="o", attributes={"body": "x" * size})
            for i in range(n)]


def test_one_flush_of_three_sends_opens_one_connection(built):
    server, sink = built
    pipe = SinkPipeline(sink, background=False)
    assert pipe.offer(_events()) == 3

    pipe.flush()

    assert len(server.requests) == 3
    assert server.opened == 1
    assert pipe.stats()["sent"] == 3 and sink.failed == 0
    pipe.close()


def test_two_flushes_open_at_most_two_connections_and_close_leaves_none(built):
    server, sink = built
    pipe = SinkPipeline(sink, background=False)
    for _ in range(2):
        pipe.offer(_events())
        pipe.flush()

    pipe.close()

    assert len(server.requests) == 6
    assert server.opened <= 2
    assert server.wait_idle() == 0


def test_a_flush_leaves_no_connection_open(built):
    server, sink = built
    pipe = SinkPipeline(sink, background=False)
    pipe.offer(_events())

    pipe.flush()

    assert server.opened == 1
    assert server.wait_idle() == 0
    pipe.close()


def test_sends_from_several_threads_share_the_connection(built):
    server, sink = built
    threads = [threading.Thread(target=sink.send, args=(_events(1, 100),)) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(server.requests) == 8
    assert (sink.sent, sink.failed) == (8, 0)
    assert server.opened == 1
    sink.close()


def test_a_connection_the_server_dropped_is_reopened_without_a_failure(built):
    server, sink = built
    server.drop_idle = True
    pipe = SinkPipeline(sink, background=False)
    pipe.offer(_events())

    pipe.flush()

    assert len(server.requests) == 3
    stats = pipe.stats()
    assert (stats["sent"], stats["dropped"], stats["retries"]) == (3, 0, 0)
    assert sink.failed == 0
    pipe.close()


@pytest.mark.parametrize("status", [302, 400, 403, 404, 500, 503])
def test_a_non_2xx_names_the_endpoint_and_status_and_drops_the_connection(built, status):
    server, sink = built
    server.status = status

    with pytest.raises(SinkSendFailed) as caught:
        sink.send(_events(1, 100))

    message = str(caught.value)
    assert message.startswith(f"{safe_endpoint(sink._url)} returned {status}")
    if sink.type == "otlp" or status != 403:
        assert message == f"{safe_endpoint(sink._url)} returned {status}"
    assert BODY_TEXT.decode() not in message
    assert caught.value.status == status
    assert sink.failed == 1

    server.status = 200
    assert sink.send(_events(1, 100)) == 1
    assert server.opened == 2
    sink.close()


def test_a_certificate_outside_the_default_trust_store_is_refused(tmp_path, monkeypatch):
    context, _ = _self_signed(tmp_path)
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    server = _Server(context)
    try:
        with pytest.raises(SinkSendFailed) as caught:
            _azure(server).send(_events(1, 100))
        assert "unreachable" in str(caught.value)
        assert server.requests == []
    finally:
        server.stop()


def test_an_http_proxy_from_the_environment_carries_the_otlp_send(monkeypatch):
    proxy = _Server()
    try:
        for var in ("no_proxy",):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.port}")
        sink = OtlpSink(SinkConfig(name="otlp", endpoint="http://collector.invalid:4318"))

        assert sink.send(_events(1, 100)) == 1

        assert [(m, p) for m, p, _ in proxy.requests] == [
            ("POST", "http://collector.invalid:4318/v1/logs")]
    finally:
        proxy.stop()


def test_an_https_proxy_from_the_environment_tunnels_the_azure_send(monkeypatch):
    proxy = _Server()
    try:
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.setenv("https_proxy", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{proxy.port}")
        config = SinkConfig(name="azmon", type="azure-monitor",
                            endpoint=f"https://dcr-abc.eastus-1.ingest.monitor.azure.com{STREAM}")
        sink = AzureMonitorSink(config, token_provider=lambda: ("stub-token", time.time() + 3600))

        with pytest.raises(SinkSendFailed):
            sink.send(_events(1, 100))

        assert [(m, p) for m, p, _ in proxy.requests] == [
            ("CONNECT", "dcr-abc.eastus-1.ingest.monitor.azure.com:443")]
    finally:
        proxy.stop()


def test_no_proxy_sends_direct_and_keeps_the_connection(otlp_server, monkeypatch):
    proxy = _Server()
    try:
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("no_proxy", "127.0.0.1")
        pipe = SinkPipeline(_otlp(otlp_server), background=False)
        pipe.offer(_events())

        pipe.flush()
        pipe.close()

        assert proxy.requests == []
        assert len(otlp_server.requests) == 3
        assert otlp_server.opened == 1
    finally:
        proxy.stop()


@pytest.mark.parametrize("stale", [
    ConnectionAbortedError, ssl.SSLEOFError, ssl.SSLZeroReturnError,
    ConnectionResetError, BrokenPipeError,
])
def test_a_reused_connection_that_fails_as_stale_is_reopened_once(stale):
    """Reusing a connection the peer closed raises one of these; over TLS it is
    an SSL EOF. The transport reconnects once instead of failing the send."""
    from forgd_verdict.sink.transport import HttpTransport

    class _Conn:
        def __init__(self, fail):
            self.fail = fail

        def request(self, *a, **kw):
            if self.fail:
                raise stale()

        def getresponse(self):
            class _Resp:
                status, will_close = 200, False

                def read(self):
                    return b""
            return _Resp()

        def close(self):
            pass

    made = []

    def connect(*a):
        conn = _Conn(fail=False)
        made.append(conn)
        return conn

    t = HttpTransport("https://collector.example/v1/logs", 5, connect=connect)
    t._conn = _Conn(fail=True)        # a reused connection the peer has closed
    assert t.post(b"{}", {}) == 200
    assert len(made) == 1             # one fresh connection, no second attempt
