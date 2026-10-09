"""POSTs from a built-in sink, over one kept-alive connection.

`HttpTransport.post` sends on one `http.client` connection, opened on first
use and reused until `close`. A sink closes it at the end of each flush
(`end_flush`) and in its own `close`.

When the proxy environment applies to the endpoint, the POST goes through
urllib instead, exactly as `urlopen` would send it, and opens a connection
per send. Whether a proxy applies is read once, when the transport is
built, from the same `ProxyHandler` that send uses.
"""

from __future__ import annotations

import http.client
import ssl
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

from ..safehttp import credential_opener

# A reused connection the server closed while it was idle fails with one of
# these before any response arrives, so `post` resends the request once on
# a new connection. The same errors also follow a request the server has
# already processed, when it closed or its response was lost before it
# arrived, so on a reset the batch can be delivered twice.
# What reusing a connection the server already closed raises: over TLS a
# closed peer surfaces as an SSL EOF rather than a reset.
_STALE = (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError,
          ConnectionAbortedError, ssl.SSLEOFError, ssl.SSLZeroReturnError)

# The User-Agent urllib sends.
USER_AGENT = f"Python-urllib/{urllib.request.__version__}"

Connect = Callable[[str, str, "int | None", float], http.client.HTTPConnection]


def open_connection(scheme: str, host: str, port: int | None, timeout: float
                    ) -> http.client.HTTPConnection:
    """A new connection. https uses `http.client`'s default context, the one
    `urlopen` uses: `ssl.create_default_context()`, which verifies the
    certificate and the host name."""
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=timeout)
    return http.client.HTTPConnection(host, port, timeout=timeout)


class HttpTransport:
    """POST to one URL. Safe to call from several threads; sends are
    serialised on the one connection."""

    def __init__(self, url: str, timeout_s: float, *, connect: Connect | None = None) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("a sink endpoint must be an http or https URL with a host")
        self._url = url
        self._scheme = parts.scheme
        self._host = parts.hostname
        self._port = parts.port
        self._target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        self._timeout = timeout_s
        self._connect = connect or open_connection
        proxies = urllib.request.ProxyHandler()
        self._proxied = (self._scheme in proxies.proxies
                         and not urllib.request.proxy_bypass(parts.netloc))
        self._opener = credential_opener(proxies) if self._proxied else None
        self._conn: http.client.HTTPConnection | None = None
        self._lock = threading.Lock()

    @property
    def proxied(self) -> bool:
        """Whether sends go through a proxy from the environment."""
        return self._proxied

    def post(self, body: bytes, headers: Mapping[str, str]) -> int:
        """POST `body` and return the response status, having read the whole
        response. A transport failure raises OSError (urllib's URLError
        included) or `http.client.HTTPException`."""
        headers = {"User-Agent": USER_AGENT, **headers}
        if self._opener is not None:
            return self._post_proxied(body, headers)
        with self._lock:
            reconnected = False
            while True:
                fresh = self._conn is None
                if fresh:
                    self._conn = self._connect(self._scheme, self._host, self._port,
                                               self._timeout)
                conn = self._conn
                try:
                    conn.request("POST", self._target, body=body, headers=headers)
                    resp = conn.getresponse()
                except _STALE:
                    self._discard()
                    if fresh or reconnected:
                        raise
                    reconnected = True
                    continue
                except BaseException:
                    self._discard()
                    raise
                try:
                    resp.read()
                except BaseException:
                    self._discard()
                    raise
                if resp.will_close or not 200 <= resp.status < 300:
                    self._discard()
                return resp.status

    def _post_proxied(self, body: bytes, headers: Mapping[str, str]) -> int:
        req = urllib.request.Request(self._url, data=body, method="POST",
                                     headers=dict(headers))
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:  # type: ignore[union-attr]
                resp.read()
                return resp.status
        except urllib.error.HTTPError as exc:
            exc.close()
            return exc.code

    def _discard(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            conn.close()

    def close(self) -> None:
        """Close the kept connection, if there is one."""
        with self._lock:
            self._discard()
