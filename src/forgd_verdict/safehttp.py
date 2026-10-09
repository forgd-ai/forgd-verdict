"""Outbound HTTP for requests that carry a credential.

urllib's default opener follows a redirect to any host and re-sends the
original headers, an `x-api-key` or `Authorization` among them. The
opener here answers every redirect with the 3xx itself, as an HTTPError.
"""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """Raises the redirect response as an HTTPError instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def credential_opener(*handlers: Any) -> urllib.request.OpenerDirector:
    """An opener that follows no redirect. Proxies from the environment
    are honoured as by `urlopen`."""
    return urllib.request.build_opener(*handlers, RefuseRedirect)


def loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def cleartext_refusal(url: str) -> str | None:
    """Why `url` would carry a credential in the clear, or None when it would
    not: https:// with a host, or http:// to a loopback host."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
    except ValueError:
        return "it is not a URL"
    if parts.scheme == "https" and host:
        return None
    if parts.scheme == "http" and loopback(host):
        return None
    return "it is not an https:// URL (http:// is accepted for loopback only)"


def scheme_refusal(url: str) -> str | None:
    """Why a credential will not be sent to `url`, or None when it will:
    `cleartext_refusal`, and no userinfo."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "it is not a URL"
    if parts.username is not None or parts.password is not None:
        return "it carries userinfo"
    return cleartext_refusal(url)


def segment(value: Any) -> str:
    """`value` as one percent-encoded URL path segment. ValueError for an
    empty value, `.` or `..`, which no encoding keeps inside its segment."""
    text = str(value)
    if text in ("", ".", ".."):
        raise ValueError("an identifier is empty, '.' or '..'")
    return urllib.parse.quote(text, safe="")
