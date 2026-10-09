"""Standard Webhooks signature verification for Inference hooks.

Verified against platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint
on 2026-09-17:

  signed payload = f"{webhook-id}.{webhook-timestamp}." + <raw body bytes>
  signature      = "v1," + base64(HMAC-SHA256(key, payload))
  key            = standard-base64-decode(secret without the "whsec_" prefix)
  header         = one or more space-separated "v1,<base64>" candidates
  tolerance      = 300s either side

Two failure modes the docs call out and this module avoids:
  * hashing a re-encoded body instead of the raw bytes;
  * URL-safe base64 decoding the secret, which derives the wrong key whenever
    the secret contains `+` or `/` (most of the time).

Rotation is an immediate cutover on Anthropic's side, but stragglers signed
with the previous secret arrive for about a minute, so more than one secret
can be active here at once.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

TOLERANCE_SECONDS = 300


@dataclass(frozen=True)
class SignatureResult:
    ok: bool
    reason: str = ""
    webhook_id: str | None = None


def lower_headers(headers: Mapping[str, str] | Sequence[tuple[bytes, bytes]]) -> dict[str, str]:
    """Normalize either a mapping or an ASGI header list to lowercase keys.

    Anthropic sends lowercase names; proxies may re-case them. On duplicate
    names the first value wins, matching the documented C# guidance.
    """
    out: dict[str, str] = {}
    if isinstance(headers, Mapping):
        items = [(str(k), str(v)) for k, v in headers.items()]
    else:
        items = [
            (k.decode("latin-1"), v.decode("latin-1")) for k, v in headers
        ]
    for name, value in items:
        key = name.lower()
        if key not in out:
            out[key] = value
    return out


# HMAC-SHA256 takes any length, including zero, so nothing in the crypto
# refuses a degenerate key. Anthropic's signing secrets are 32 bytes; this
# is a floor well under that and well over anything a truncated paste
# produces.
MIN_SECRET_BYTES = 16


def decode_secret(secret: str) -> bytes | None:
    """Decode a `whsec_`-prefixed signing secret to raw key bytes.

    The secret is revealed exactly once in claude.ai and copy-pasted by hand,
    so it routinely arrives with a trailing newline or a stray space from the
    clipboard or a shell heredoc. `validate=True` rejects those outright, and
    the resulting failure is indistinguishable from a wrong secret -- every
    request 401s with `no_usable_secret` and nothing says why. Strip first.
    """
    cleaned = secret.strip()
    raw = cleaned[len("whsec_") :] if cleaned.startswith("whsec_") else cleaned
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return None
    # A truncated paste that happens to land on a base64 boundary decoded
    # to a few bytes, or none, and counted as usable:
    #
    #   'whsec_'      -> b''              len=0   usable_secrets=1
    #   'whsec_AAAA'  -> b'\x00\x00\x00'  len=3   usable_secrets=1
    #
    # and anyone who knew the configuration forged signatures with an
    # empty HMAC key. The non-base64 case already 401s; this one did not.
    if len(decoded) < MIN_SECRET_BYTES:
        return None
    return decoded


def usable_secrets(secrets: Sequence[str]) -> int:
    """How many configured secrets actually decode to a key."""
    return sum(1 for s in secrets if decode_secret(s) is not None)


# Unix seconds: ASCII digits only, at most 12 of them.
_TIMESTAMP = re.compile(r"[0-9]{1,12}")


def precheck(
    headers: Mapping[str, str],
    *,
    now: float | None = None,
    tolerance_s: int = TOLERANCE_SECONDS,
) -> SignatureResult:
    """The checks that need only the headers: all three `webhook-*` headers
    are present and the timestamp parses and is within tolerance.

    The server runs this before reading the body, so a request that cannot
    pass `verify` costs no body read.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    message_id = lowered.get("webhook-id")
    timestamp = lowered.get("webhook-timestamp")
    signatures = lowered.get("webhook-signature")
    if not message_id or not timestamp or not signatures:
        return SignatureResult(False, "unsigned")

    if not _TIMESTAMP.fullmatch(timestamp):
        return SignatureResult(False, "bad_timestamp", message_id)
    current = time.time() if now is None else now
    try:
        stale = abs(current - int(timestamp)) > tolerance_s
    except (ValueError, OverflowError):
        return SignatureResult(False, "bad_timestamp", message_id)
    if stale:
        return SignatureResult(False, "stale_timestamp", message_id)
    return SignatureResult(True, "ok", message_id)


def verify(
    secrets: Sequence[str],
    headers: Mapping[str, str],
    body: bytes,
    *,
    now: float | None = None,
    tolerance_s: int = TOLERANCE_SECONDS,
) -> SignatureResult:
    """Verify a signed request against any of the configured secrets."""
    pre = precheck(headers, now=now, tolerance_s=tolerance_s)
    if not pre.ok:
        return pre
    lowered = {k.lower(): v for k, v in headers.items()}
    message_id = lowered["webhook-id"]
    timestamp = lowered["webhook-timestamp"]
    signatures = lowered["webhook-signature"]

    candidates = [c.encode("utf-8") for c in signatures.split() if c]
    if not candidates:
        return SignatureResult(False, "no_candidates", message_id)

    prefix = f"{message_id}.{timestamp}.".encode()
    matched = False
    usable_secret = False
    for secret in secrets:
        key = decode_secret(secret)
        if key is None:
            continue  # misconfigured secret: skip rather than crash
        usable_secret = True
        # The body is fed separately so the signed payload is never built
        # as a second copy of it.
        mac = hmac.new(key, prefix, hashlib.sha256)
        mac.update(body)
        expected = b"v1," + base64.b64encode(mac.digest())
        for candidate in candidates:
            # compare_digest is constant time and safe on unequal lengths.
            if hmac.compare_digest(expected, candidate):
                matched = True

    if not usable_secret:
        return SignatureResult(False, "no_usable_secret", message_id)
    if not matched:
        return SignatureResult(False, "mismatch", message_id)
    return SignatureResult(True, "ok", message_id)
