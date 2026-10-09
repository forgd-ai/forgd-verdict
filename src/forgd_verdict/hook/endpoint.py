"""Outbound requests from the hook, and where they may go.

A Claude Code project's `.claude/settings.json` `env` block reaches the
hook's environment, so nothing here takes a destination, a proxy or a trust
store from the environment unless the policy file allows it:

- `destination` refuses a `$VAR` placeholder for an endpoint, store or token
  unless the policy sets `hook.project_overrides: true`.
- `refusal` accepts https://, and http:// to loopback only.
- The opener uses no proxy, and trusts `hook.ca_file` or OpenSSL's built-in
  CA locations, never `SSL_CERT_FILE` or `SSL_CERT_DIR`.
- The opener refuses every redirect. urllib follows a 301, 302 or 303 on a
  POST by re-issuing it as a GET to the new location, and the hook would
  read that location's answer as the verdict.
"""

from __future__ import annotations

import ipaddress
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def destination(hook: Mapping[str, Any], key: str) -> str | None:
    """`hook[key]` with a `$VAR` placeholder resolved, or None."""
    value = hook.get(key)
    if not isinstance(value, str) or not value:
        return None
    if not value.startswith("$"):
        return value
    if hook.get("project_overrides") is not True:
        print(f"forgd-verdict: hook.{key} is the placeholder {value}, which a "
              "project's environment can set; it is used only with "
              "hook.project_overrides: true", file=sys.stderr)
        return None
    return os.environ.get(value[1:]) or None


def _loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def refusal(url: str) -> str | None:
    """Why the hook will not send to `url`, or None when it will."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return None
    if parts.scheme == "http" and _loopback(parts.hostname):
        return None
    return "it is not an https:// URL (http:// is accepted for loopback only)"


def tls_context(ca_file: str | None = None) -> ssl.SSLContext:
    """A verifying client context that ignores SSL_CERT_FILE and SSL_CERT_DIR.

    Raises ValueError for a `ca_file` that is not an absolute path: a
    relative one resolves inside whichever project the hook runs in.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca_file:
        if not os.path.isabs(ca_file):
            raise ValueError(f"hook.ca_file must be an absolute path, got {ca_file!r}")
        context.load_verify_locations(cafile=ca_file)
        return context
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile if os.path.isfile(paths.openssl_cafile or "") else None
    capath = paths.openssl_capath if os.path.isdir(paths.openssl_capath or "") else None
    if cafile or capath:
        context.load_verify_locations(cafile=cafile, capath=capath)
    return context


def open_url(request: urllib.request.Request, timeout: float,
             ca_file: str | None = None) -> Any:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=tls_context(ca_file)),
        _RefuseRedirect,
    )
    return opener.open(request, timeout=timeout)
