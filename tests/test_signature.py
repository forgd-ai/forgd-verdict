"""Signature vectors. Every case the docs call out, plus rotation overlap."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

from conftest import WHSEC, WHSEC_PREVIOUS, sign

from forgd_verdict.server.signature import lower_headers, verify

BODY = b'{"type":"prompt","request_id":"req_1"}'


def test_valid_signature():
    headers = sign(BODY)
    assert verify([WHSEC], headers, BODY).ok


def test_wrong_secret_rejected():
    headers = sign(BODY, secret=WHSEC_PREVIOUS)
    result = verify([WHSEC], headers, BODY)
    assert not result.ok and result.reason == "mismatch"


def test_rotated_secret_pair_accepts_both():
    """Rotation is an immediate cutover but stragglers arrive for ~1 minute."""
    pair = [WHSEC, WHSEC_PREVIOUS]
    assert verify(pair, sign(BODY, secret=WHSEC), BODY).ok
    assert verify(pair, sign(BODY, secret=WHSEC_PREVIOUS), BODY).ok


def test_expired_timestamp_rejected():
    headers = sign(BODY, ts=int(time.time()) - 301)
    result = verify([WHSEC], headers, BODY)
    assert not result.ok and result.reason == "stale_timestamp"


def test_future_timestamp_rejected():
    headers = sign(BODY, ts=int(time.time()) + 301)
    assert verify([WHSEC], headers, BODY).reason == "stale_timestamp"


def test_timestamp_inside_tolerance_accepted():
    for offset in (-299, 0, 299):
        headers = sign(BODY, ts=int(time.time()) + offset)
        assert verify([WHSEC], headers, BODY).ok, offset


def test_multi_candidate_header_any_match_wins():
    """`webhook-signature` may carry several space-separated v1,<b64> values."""
    good = sign(BODY)["webhook-signature"]
    headers = sign(BODY)
    headers["webhook-signature"] = f"v1,AAAA {good} v1,BBBB"
    assert verify([WHSEC], headers, BODY).ok


def test_unsigned_request_rejected():
    result = verify([WHSEC], {"content-type": "application/json"}, BODY)
    assert not result.ok and result.reason == "unsigned"


def test_body_must_be_raw_bytes():
    """Re-encoding the body before hashing is the classic bug."""
    headers = sign(BODY)
    reencoded = b'{"request_id": "req_1", "type": "prompt"}'  # same JSON, new bytes
    assert not verify([WHSEC], headers, reencoded).ok


def test_secret_uses_standard_not_urlsafe_base64():
    """A secret containing + or / must decode with the standard alphabet."""
    # Key bytes whose standard base64 contains both + and /, the two
    # characters a URL-safe decoder gets wrong.
    encoded = "+/" * 16
    key = base64.b64decode(encoded)
    secret = f"whsec_{encoded}"
    headers = sign(BODY, secret=secret)
    assert verify([secret], headers, BODY).ok
    # A URL-safe decode of the same string yields different key bytes.
    urlsafe_key = base64.urlsafe_b64decode(encoded.replace("+", "-").replace("/", "_"))
    if urlsafe_key != key:
        ts = headers["webhook-timestamp"]
        payload = f"req_test.{ts}.".encode() + BODY
        bad = base64.b64encode(
            hmac.new(urlsafe_key, payload, hashlib.sha256).digest()
        ).decode()
        assert bad != headers["webhook-signature"].split(",", 1)[1]


def test_malformed_secret_does_not_crash():
    result = verify(["whsec_not!valid!base64"], sign(BODY), BODY)
    assert not result.ok and result.reason == "no_usable_secret"


def test_non_numeric_timestamp_rejected():
    headers = sign(BODY)
    headers["webhook-timestamp"] = "not-a-number"
    assert verify([WHSEC], headers, BODY).reason == "bad_timestamp"


def test_header_lookup_is_case_insensitive():
    """Anthropic sends lowercase; proxies may re-case."""
    headers = {k.upper(): v for k, v in sign(BODY).items()}
    assert verify([WHSEC], lower_headers(headers), BODY).ok


def test_lower_headers_accepts_asgi_pairs():
    pairs = [(b"Webhook-Id", b"req_1"), (b"WEBHOOK-ID", b"req_2")]
    assert lower_headers(pairs)["webhook-id"] == "req_1"  # first wins


def test_secret_with_trailing_whitespace_still_works():
    """The secret is shown once and pasted by hand, so it arrives with a
    trailing newline more often than not. b64decode(validate=True) rejects
    that, and the failure is indistinguishable from a wrong secret."""
    headers = sign(BODY)
    for mangled in (WHSEC + "\n", " " + WHSEC, WHSEC + "  \n", f"\t{WHSEC}\n"):
        assert verify([mangled], headers, BODY).ok, repr(mangled)


def test_usable_secrets_distinguishes_configured_from_valid():
    from forgd_verdict.server.signature import decode_secret, usable_secrets

    assert usable_secrets([WHSEC, WHSEC_PREVIOUS]) == 2
    # The exact placeholder the bootstrap script installs.
    assert usable_secrets(["placeholder-not-yet-issued"]) == 0
    assert usable_secrets([WHSEC, "placeholder-not-yet-issued"]) == 1
    assert decode_secret("placeholder-not-yet-issued") is None
    assert decode_secret(WHSEC) is not None
    assert len(decode_secret(WHSEC)) > 0


def test_truncated_paste_is_reported_as_unusable():
    """Half a secret is a common clipboard accident."""
    from forgd_verdict.server.signature import usable_secrets

    assert usable_secrets([WHSEC[: len(WHSEC) // 2]]) == 0


# -- a degenerate signing key --------------------------------------------


def test_a_degenerate_base64_body_is_not_a_usable_key():
    """HMAC-SHA256 takes any length including zero, so nothing in the
    crypto refuses a degenerate key, and both startup branches stayed
    quiet while the log reported `secrets_usable: 1`:

        'whsec_'      -> b''              len=0
        'whsec_AAAA'  -> b'\\x00\\x00\\x00'  len=3

    Anyone who knew the configuration forged signatures with an empty
    HMAC key. The non-base64 case already 401s; this one did not.
    """
    from forgd_verdict.server.signature import decode_secret, usable_secrets

    for weak in ("whsec_", "whsec_AAAA", "whsec_AA=="):
        assert decode_secret(weak) is None, weak
    assert usable_secrets(["whsec_", "whsec_AAAA"]) == 0


def test_a_real_secret_still_decodes():
    from forgd_verdict.server.signature import (
        MIN_SECRET_BYTES,
        decode_secret,
        usable_secrets,
    )

    good = "whsec_" + base64.b64encode(b"k" * 32).decode()
    assert len(decode_secret(good)) >= MIN_SECRET_BYTES
    assert usable_secrets([good]) == 1
