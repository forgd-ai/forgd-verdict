"""Ed25519 signatures over runtime-override records.

Keys are the raw 32-byte Ed25519 keys in URL-safe base64 without padding.
The dashboard holds the private key in `FORGD_OVERRIDES_SIGNING_KEY`, and
no other role may; every reader holds one or more public keys,
comma-separated, in `FORGD_OVERRIDES_VERIFY_KEY`. `ENV_OVERRIDES` places the
public keys at `overrides.verify_keys`. `overrides.signing_key` may only be
a `$NAME` reference and defaults to `$FORGD_OVERRIDES_SIGNING_KEY`, so the
private key never sits in the policy dict.

A signature covers the record's canonical JSON with the `signature` field
removed: sorted keys, no insignificant whitespace, UTF-8, and no value that
JSON cannot represent natively.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .models import env_or_literal

SIGNATURE_FIELD = "signature"
ALG = "Ed25519"
KEY_BYTES = 32
SIGNATURE_BYTES = 64

ENV_SIGNING_KEY = "FORGD_OVERRIDES_SIGNING_KEY"
ENV_VERIFY_KEY = "FORGD_OVERRIDES_VERIFY_KEY"

_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_REFERENCE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
# The roles that may hold the signing key.
SIGNING_ROLES = ("dashboard", "cli")


class KeyConfigError(ValueError):
    """A configured key is malformed. The message never contains the key."""


class SignatureError(ValueError):
    """A record's signature is missing, malformed, or does not verify."""


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode(text: str, what: str, length: int, exc: type[ValueError]) -> bytes:
    """Strict URL-safe base64: unpadded, canonical, exactly `length` bytes."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text):
        raise exc(f"{what} is not unpadded URL-safe base64")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as err:
        raise exc(f"{what} is not unpadded URL-safe base64") from err
    if len(raw) != length:
        raise exc(f"{what} decodes to {len(raw)} bytes, not {length}")
    # Rejects encodings whose unused trailing bits are set, so each key and
    # signature has exactly one text form.
    if encode(raw) != text:
        raise exc(f"{what} is not the canonical encoding")
    return raw


def key_id(public: Ed25519PublicKey) -> str:
    """The first 16 hex digits of the SHA-256 of the raw public key."""
    return hashlib.sha256(_public_raw(public)).hexdigest()[:16]


def _public_raw(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


def parse_signing_key(text: str) -> Ed25519PrivateKey:
    raw = _decode(text.strip(), ENV_SIGNING_KEY, KEY_BYTES, KeyConfigError)
    return Ed25519PrivateKey.from_private_bytes(raw)


def parse_verify_key(text: str) -> Ed25519PublicKey:
    raw = _decode(text.strip(), ENV_VERIFY_KEY, KEY_BYTES, KeyConfigError)
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as err:
        raise KeyConfigError(f"{ENV_VERIFY_KEY} is not an Ed25519 public key") from err


def parse_verify_keys(value: str | Iterable[str] | None) -> tuple[Ed25519PublicKey, ...]:
    """Public keys from a comma-separated string or a list of strings.

    Empty or None gives no keys. An empty entry or a repeated key is an error.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return ()
    items = value.split(",") if isinstance(value, str) else list(value)
    keys: list[Ed25519PublicKey] = []
    seen: set[str] = set()
    for n, item in enumerate(items, 1):
        if not isinstance(item, str) or not item.strip():
            raise KeyConfigError(f"{ENV_VERIFY_KEY} entry {n} is empty")
        key = parse_verify_key(item)
        kid = key_id(key)
        if kid in seen:
            raise KeyConfigError(f"{ENV_VERIFY_KEY} lists key {kid} twice")
        seen.add(kid)
        keys.append(key)
    return tuple(keys)


@dataclass(frozen=True)
class SigningConfig:
    signing_key: Ed25519PrivateKey | None
    verify_keys: tuple[Ed25519PublicKey, ...]

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(key_id(k) for k in self.verify_keys)


def _section(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    section = raw.get("overrides") or {}
    if not isinstance(section, Mapping):
        raise KeyConfigError("overrides must be a mapping")
    return section


def verify_keys_from_policy(raw: Mapping[str, Any]) -> tuple[Ed25519PublicKey, ...]:
    """The public keys at `overrides.verify_keys`; the signing key is not read."""
    verify = _section(raw).get("verify_keys")
    if isinstance(verify, str) and verify.startswith("$"):
        verify = env_or_literal(verify)
    return parse_verify_keys(verify)


def _signing_reference(raw: Mapping[str, Any]) -> str:
    """`overrides.signing_key`, or `$FORGD_OVERRIDES_SIGNING_KEY` when it is
    absent or empty. KeyConfigError for anything but a `$NAME` reference."""
    ref = _section(raw).get("signing_key")
    if ref is None or ref == "":
        return f"${ENV_SIGNING_KEY}"
    if not (isinstance(ref, str) and _REFERENCE.fullmatch(ref)):
        raise KeyConfigError(
            "overrides.signing_key must be a $NAME environment reference, such as "
            f"${ENV_SIGNING_KEY}: a private key written into the policy is refused")
    return ref


def signing_key_configured(raw: Mapping[str, Any]) -> bool:
    """Whether this process is given a signing key: FORGD_OVERRIDES_SIGNING_KEY
    is set, `overrides.signing_key` is anything but a reference, or the
    variable it references is set."""
    if os.environ.get(ENV_SIGNING_KEY):
        return True
    try:
        return bool(env_or_literal(_signing_reference(raw)))
    except KeyConfigError:
        return True


def refuse_signing_key(raw: Mapping[str, Any], role: str) -> None:
    """RuntimeError when `role` may not hold the signing key and is given one."""
    if role not in SIGNING_ROLES and signing_key_configured(raw):
        raise RuntimeError(
            f"refusing to start the {role} role: it is given a runtime-overrides signing "
            f"key ({ENV_SIGNING_KEY} or overrides.signing_key). Only the dashboard signs "
            "runtime-override records, and any other service holding the key could "
            "forge them. Remove it from this service's environment and policy; see "
            '"Signing keys" in docs/OVERRIDES.md')


def from_policy(raw: Mapping[str, Any]) -> SigningConfig:
    """The keys under `overrides` in a raw policy dict.

    The signing key is read from the variable `overrides.signing_key` names
    (`_signing_reference`); a literal there is refused. A signing key is
    refused when no verify key is listed or its public half is not among
    them: every record it signed would fail verification on the readers.
    """
    text = env_or_literal(_signing_reference(raw))
    signing = parse_signing_key(text) if text else None
    publics = verify_keys_from_policy(raw)
    if signing is not None and not publics:
        raise KeyConfigError(
            f"{ENV_SIGNING_KEY} is set but {ENV_VERIFY_KEY} lists no key; readers would "
            "reject every record it signs")
    if signing is not None:
        own = key_id(signing.public_key())
        if own not in {key_id(k) for k in publics}:
            raise KeyConfigError(
                f"{ENV_SIGNING_KEY} has key id {own}, which {ENV_VERIFY_KEY} does not "
                "list; readers would reject every record it signs")
    return SigningConfig(signing, publics)


def canonical(record: Mapping[str, Any]) -> bytes:
    """The bytes a signature covers: `record` less its `signature` field."""
    body = {k: v for k, v in record.items() if k != SIGNATURE_FIELD}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sign(record: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    """A copy of `record` with a `signature` field over the rest of it."""
    sig = key.sign(canonical(record))
    return {**{k: v for k, v in record.items() if k != SIGNATURE_FIELD},
            SIGNATURE_FIELD: {"alg": ALG, "kid": key_id(key.public_key()), "sig": encode(sig)}}


def verify(record: Mapping[str, Any], keys: Iterable[Ed25519PublicKey]) -> str:
    """The key id that verifies `record`'s signature; SignatureError otherwise."""
    field = record.get(SIGNATURE_FIELD)
    if not isinstance(field, Mapping):
        raise SignatureError("record has no signature")
    if field.get("alg") != ALG:
        raise SignatureError(f"signature alg is {field.get('alg')!r}, not {ALG}")
    kid = field.get("kid")
    by_id = {key_id(k): k for k in keys}
    if not isinstance(kid, str) or kid not in by_id:
        raise SignatureError(f"signature key id {kid!r} is not a configured verify key")
    sig = _decode(field.get("sig"), "signature", SIGNATURE_BYTES, SignatureError)
    try:
        body = canonical(record)
    except (TypeError, ValueError) as err:
        raise SignatureError("record is not canonical JSON") from err
    try:
        by_id[kid].verify(sig, body)
    except InvalidSignature as err:
        raise SignatureError(f"signature does not verify under key {kid}") from err
    return kid


@dataclass(frozen=True)
class KeyPair:
    private: str
    public: str
    kid: str


def generate() -> KeyPair:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return KeyPair(encode(private), encode(_public_raw(key.public_key())),
                   key_id(key.public_key()))


def write_private_key(path: str, private: str) -> None:
    """Create `path` with mode 0600 and write the key. Refuses an existing file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        # The umask filters the creation mode; this sets it exactly.
        os.fchmod(fd, 0o600)
        os.write(fd, (private + "\n").encode("ascii"))
    finally:
        os.close(fd)
