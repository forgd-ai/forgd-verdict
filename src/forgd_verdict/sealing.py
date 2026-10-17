"""Matched values sealed under a key in a cloud KMS.

With `privacy.sealing` enabled, each finding a detector reports with its
matched value carries that value sealed: AES-256-GCM under a fresh data
key, and the data key encrypted with RSA-OAEP-SHA-256 to the public half of
an asymmetric key in Azure Key Vault, AWS KMS or Cloud KMS. Sealing needs
only the public key, so every adapter seals locally, the hook on a laptop
included, and none of them makes a KMS call. The private key never leaves
the KMS: `forgd-verdict unseal` asks the KMS to decrypt the data key, under
the operator's own cloud login, and opens the value locally.

A sealed value is one string:

    fvs1.<fingerprint>.<f|t>.<wrapped key>.<nonce>.<ciphertext>

`fingerprint` is the first 16 hex characters of the sha256 of the public
key's SubjectPublicKeyInfo, which names the key that can open it; `t` marks
a value cut to `max_chars`. The last three parts are unpadded base64url.
The version, fingerprint, flag and detector are the GCM associated data, so
a sealed value moved to a finding from another detector does not open.

Sealing is randomised: the same value sealed twice gives two strings. The
finding's `excerpt_hash` stays the field that deduplicates and joins.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import env_or_literal

VERSION = "fvs1"
KMS_KINDS = ("azure", "aws", "gcp")
# The sizes all three KMSs offer at or above 3072 bits. A larger key would
# wrap to more than SEALED allows.
RSA_BITS = (3072, 4096)
MAX_CHARS_DEFAULT = 256
MAX_CHARS_LIMIT = 1024
# RSA-3072 and RSA-4096 wrap to 384 and 512 bytes, 512 and 683 characters of
# base64url. A value of at most 1024 characters is at most 4096 bytes of
# UTF-8; with the 16-byte tag, the body is 22 to 5483 characters.
SEALED_MAX_CHARS = 6208
SEALED = re.compile(
    r"fvs1\.[0-9a-f]{16}\.[ft]\.(?:[A-Za-z0-9_-]{512}|[A-Za-z0-9_-]{683})"
    r"\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,5483}")
# A key by version, as each KMS names it.
KEY_ID = {
    "azure": re.compile(r"https://[a-zA-Z0-9.-]+/keys/[a-zA-Z0-9-]+/[0-9a-zA-Z]+"),
    "aws": re.compile(r"arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/"
                      r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                      r"|mrk-[0-9a-f]{32})"),
    "gcp": re.compile(r"projects/[^/\s]+/locations/[^/\s]+/keyRings/[^/\s]+"
                      r"/cryptoKeys/[^/\s]+/cryptoKeyVersions/[0-9]+"),
}
_KEY_ID_FORM = {
    "azure": "a Key Vault key URL ending in its version",
    "aws": "a KMS key ARN",
    "gcp": "a Cloud KMS name ending in /cryptoKeyVersions/<n>",
}

_KEYS = frozenset({"enabled", "key", "orgs", "retired", "max_chars"})
_KEY_KEYS = frozenset({"kms", "id", "public_key"})
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


class SealingInvalid(ValueError):
    """`privacy.sealing` is set in a shape that cannot seal."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


@dataclass(frozen=True)
class SealingKey:
    """One KMS key: where it lives and its public half."""

    kms: str
    id: str
    public_key: rsa.RSAPublicKey = field(repr=False, compare=False)
    fingerprint: str = ""

    @classmethod
    def parse(cls, raw: Any, where: str) -> SealingKey:
        if not isinstance(raw, Mapping):
            raise SealingInvalid(f"{where} must be a mapping with kms, id and public_key")
        unknown = sorted(set(raw) - _KEY_KEYS)
        if unknown:
            raise SealingInvalid(f"{where} has {', '.join(map(str, unknown))}; "
                                 "it takes kms, id and public_key")
        kms = raw.get("kms")
        if kms not in KMS_KINDS:
            raise SealingInvalid(f"{where}.kms must be one of {', '.join(KMS_KINDS)}, "
                                 f"got {kms!r}")
        key_id = env_or_literal(raw.get("id")) if isinstance(raw.get("id"), str) else None
        if not key_id:
            raise SealingInvalid(f"{where}.id is required: the KMS key, by version, that "
                                 "decrypts what this key seals")
        if not KEY_ID[kms].fullmatch(key_id):
            raise SealingInvalid(f"{where}.id is not {_KEY_ID_FORM[kms]}")
        pem = (env_or_literal(raw.get("public_key"))
               if isinstance(raw.get("public_key"), str) else None)
        if not pem:
            raise SealingInvalid(f"{where}.public_key is required: the key's public "
                                 "half, PEM")
        try:
            public_key = serialization.load_pem_public_key(pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError, TypeError) as exc:
            raise SealingInvalid(f"{where}.public_key is not a PEM public key") from exc
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise SealingInvalid(f"{where}.public_key must be an RSA key")
        if public_key.key_size not in RSA_BITS:
            raise SealingInvalid(f"{where}.public_key is RSA-{public_key.key_size}; "
                                 "sealing takes RSA-3072 or RSA-4096")
        return cls(kms, key_id, public_key, fingerprint(public_key))


def _associated(fp: str, flag: str, detector: str) -> bytes:
    return f"{VERSION}.{fp}.{flag}.{detector}".encode("utf-8", "surrogatepass")


@dataclass(frozen=True)
class Sealer:
    """Seals values to one key."""

    key: SealingKey
    max_chars: int = MAX_CHARS_DEFAULT

    def seal(self, value: str, detector: str) -> str:
        flag = "t" if len(value) > self.max_chars else "f"
        data_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        body = AESGCM(data_key).encrypt(
            nonce, value[:self.max_chars].encode("utf-8", "surrogatepass"),
            _associated(self.key.fingerprint, flag, detector))
        wrapped = self.key.public_key.encrypt(data_key, _OAEP)
        return ".".join((VERSION, self.key.fingerprint, flag,
                         _b64(wrapped), _b64(nonce), _b64(body)))


@dataclass(frozen=True)
class Sealing:
    """`privacy.sealing`, parsed: the deployment's key, any per-org keys,
    and retired keys that are kept only so `unseal` can find them."""

    default: Sealer
    orgs: Mapping[str, Sealer] = field(default_factory=dict)
    retired: tuple[SealingKey, ...] = ()

    def for_org(self, org_id: str | None) -> Sealer:
        """The sealer for `org_id`'s findings: its own key if it has one,
        otherwise the deployment's."""
        if org_id and org_id in self.orgs:
            return self.orgs[org_id]
        return self.default

    def current_keys(self) -> list[SealingKey]:
        """The keys new findings are sealed to: `key` and the org keys."""
        return [self.default.key, *(s.key for s in self.orgs.values())]

    def all_keys(self) -> list[SealingKey]:
        return [*self.current_keys(), *self.retired]

    def key_for(self, fp: str) -> SealingKey | None:
        return next((k for k in self.all_keys() if k.fingerprint == fp), None)


def parse(raw: Any) -> Sealing | None:
    """`privacy.sealing` as a Sealing, or None when it is absent or
    `enabled` is not true. SealingInvalid on any other shape."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise SealingInvalid("privacy.sealing must be a mapping")
    unknown = sorted(set(raw) - _KEYS)
    if unknown:
        raise SealingInvalid(f"privacy.sealing has {', '.join(map(str, unknown))}; it "
                             f"takes {', '.join(sorted(_KEYS))}")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise SealingInvalid(f"privacy.sealing.enabled must be true or false, got {enabled!r}")
    if not enabled:
        return None
    max_chars = raw.get("max_chars", MAX_CHARS_DEFAULT)
    if (isinstance(max_chars, bool) or not isinstance(max_chars, int)
            or not 1 <= max_chars <= MAX_CHARS_LIMIT):
        raise SealingInvalid(f"privacy.sealing.max_chars must be a whole number from 1 to "
                             f"{MAX_CHARS_LIMIT}, got {max_chars!r}")
    if raw.get("key") is None:
        raise SealingInvalid("privacy.sealing.enabled is true but privacy.sealing.key is "
                             "not set: sealing needs a KMS key")
    default = Sealer(SealingKey.parse(raw["key"], "privacy.sealing.key"), max_chars)
    orgs_raw = raw.get("orgs") or {}
    if not isinstance(orgs_raw, Mapping):
        raise SealingInvalid("privacy.sealing.orgs must map an org id to a key")
    orgs: dict[str, Sealer] = {}
    for name, key in orgs_raw.items():
        org_id = env_or_literal(name) if isinstance(name, str) else None
        if not org_id:
            raise SealingInvalid(f"privacy.sealing.orgs has a key {name!r} that does not "
                                 "resolve to an org id")
        if org_id in orgs:
            raise SealingInvalid(f"privacy.sealing.orgs has two keys for one org id, the "
                                 f"second at {name!r}")
        orgs[org_id] = Sealer(SealingKey.parse(key, f"privacy.sealing.orgs.{name}"),
                              max_chars)
    retired_raw = raw.get("retired") or []
    if not isinstance(retired_raw, list):
        raise SealingInvalid("privacy.sealing.retired must be a list of keys")
    retired = tuple(SealingKey.parse(k, f"privacy.sealing.retired[{i}]")
                    for i, k in enumerate(retired_raw))
    return Sealing(default, orgs, retired)


@dataclass(frozen=True)
class Parts:
    fingerprint: str
    truncated: bool
    wrapped: bytes
    nonce: bytes
    body: bytes


def split(token: str) -> Parts:
    """The parts of a sealed value. ValueError when it is not one."""
    if not isinstance(token, str) or not SEALED.fullmatch(token):
        raise ValueError("not a sealed value")
    _, fp, flag, wrapped, nonce, body = token.split(".")
    return Parts(fp, flag == "t", _unb64(wrapped), _unb64(nonce), _unb64(body))


def open_sealed(token: str, detector: str, unwrap: Callable[[bytes], bytes]
                ) -> tuple[str, bool]:
    """The value sealed in `token` and whether it was cut short. `unwrap`
    decrypts the RSA-OAEP-SHA-256 data key; it is the KMS call.
    ValueError when the value does not open, which includes a `detector`
    other than the one it was sealed for."""
    from cryptography.exceptions import InvalidTag

    parts = split(token)
    data_key = unwrap(parts.wrapped)
    if len(data_key) != 32:
        raise ValueError("the KMS returned a data key of the wrong length")
    flag = "t" if parts.truncated else "f"
    try:
        value = AESGCM(data_key).decrypt(parts.nonce, parts.body,
                                         _associated(parts.fingerprint, flag, detector))
    except InvalidTag as exc:
        raise ValueError("the sealed value does not open for this detector") from exc
    return value.decode("utf-8", "surrogatepass"), parts.truncated
