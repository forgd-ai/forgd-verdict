"""`intake.devices`: a laptop proves which device it is with a certificate
its organization's CA issued, by signing each request.

The hook signs a small claim set naming the route, the time and the
SHA-256 of the request body, as a compact JWS whose `x5c` header carries
the device certificate and any intermediates. The header is

    Authorization: ForgdDevice <JWS>

The intake checks the chain against the entry's CA anchors, the allowed
EKU, the validity dates, the signature and the time before it reads the
body, and the body's hash once it has read it. The device id comes from
the certificate, never from a header the sender chose. Signing rather
than client TLS keeps the check out of whatever terminates TLS in front
of the intake and away from a forwarded certificate header.

Revocation is a short certificate lifetime renewed by MDM, and the runtime
overrides' device denylist; no CRL or OCSP is fetched.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import verification
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from ..models import DEVICE_ID
from ..policy import Policy
from .verify import Caller, Credential, credential_name, org_partition, parse_routes

SCHEME = "ForgdDevice"
JWS_TYPE = "forgd-request+jws"
# How far a request's `iat` may be from the intake's clock, in seconds.
DEFAULT_MAX_SKEW_S = 300
# The device id's certificate field.
FROM_SAN_URI = "san_uri"
FROM_SAN_DNS = "san_dns"
FROM_SUBJECT_CN = "subject_cn"
DEVICE_FIELDS = (FROM_SAN_URI, FROM_SAN_DNS, FROM_SUBJECT_CN)
# A JWS header longer than this is refused before it is parsed: a chain of
# a leaf and an intermediate fits several times over.
MAX_JWS_CHARS = 16 * 1024
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_HEX64 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class DeviceEntry:
    credential: Credential
    store: verification.Store
    eku: ObjectIdentifier
    device_from: str
    device_prefix: str
    max_skew_s: int
    # The anchors' subjects, so a chain is verified only against an entry
    # whose CA could have issued it.
    subjects: frozenset[bytes] = frozenset()


def _b64url(data: str) -> bytes:
    if not _B64URL.fullmatch(data):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _verify_signature(key: Any, alg: str, signing_input: bytes, signature: bytes) -> None:
    """InvalidSignature, or ValueError for an algorithm that does not fit
    the key."""
    if alg in ("ES256", "ES384") and isinstance(key, ec.EllipticCurvePublicKey):
        size = {"ES256": 32, "ES384": 48}[alg]
        curve = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1}[alg]
        if not isinstance(key.curve, curve) or len(signature) != 2 * size:
            raise InvalidSignature
        der = encode_dss_signature(int.from_bytes(signature[:size], "big"),
                                   int.from_bytes(signature[size:], "big"))
        digest = hashes.SHA256() if alg == "ES256" else hashes.SHA384()
        key.verify(der, signing_input, ec.ECDSA(digest))
    elif alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "PS256" and isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, signing_input,
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                   hashes.SHA256())
    elif alg == "EdDSA" and isinstance(key, ed25519.Ed25519PublicKey):
        key.verify(signature, signing_input)
    else:
        raise ValueError("unsupported algorithm for this key")


def _eku_validator(eku: ObjectIdentifier):
    def check(_policy: Any, _cert: Any, ext: Any) -> None:
        if ext is None or eku not in ext:
            raise ValueError("the certificate does not carry the allowed EKU")
    return check


def _not_a_ca(_policy: Any, _cert: Any, ext: Any) -> None:
    if ext is not None and ext.ca:
        raise ValueError("a CA certificate cannot sign as a device")


def _signs(_policy: Any, _cert: Any, ext: Any) -> None:
    if ext is not None and not ext.digital_signature:
        raise ValueError("the certificate's key usage does not allow signing")


def _ee_policy(eku: ObjectIdentifier) -> verification.ExtensionPolicy:
    """The device certificate's extensions: the allowed EKU, not a CA, and
    digitalSignature whenever KeyUsage is present."""
    agnostic = verification.Criticality.AGNOSTIC
    return (verification.ExtensionPolicy.permit_all()
            .require_present(x509.ExtendedKeyUsage, agnostic, _eku_validator(eku))
            .may_be_present(x509.BasicConstraints, agnostic, _not_a_ca)
            .may_be_present(x509.KeyUsage, agnostic, _signs))


class DeviceCertificates:
    """`intake.devices` entries, each a set of CA anchors with the EKU and
    the certificate field that carries the device id."""

    def __init__(self, entries: Sequence[DeviceEntry],
                 clock: Any = time.time):
        self._entries = list(entries)
        self._clock = clock

    def __len__(self) -> int:
        return len(self._entries)

    def credentials(self) -> list[Credential]:
        return [e.credential for e in self._entries]

    @classmethod
    def from_policy(cls, policy: Policy) -> DeviceCertificates:
        config = policy.raw.get("intake") or {}
        entries = []
        names: dict[str, int] = {}
        seen_anchors: dict[bytes, str] = {}
        for index, entry in enumerate(config.get("devices") or []):
            where = f"intake.devices[{index}]"
            if not isinstance(entry, dict):
                raise ValueError(f"{where} must be a mapping")
            name = credential_name(where, entry.get("name"))
            if name in names:
                raise ValueError(f"intake.devices[{names[name]}] and {where} are both "
                                 f"named {name!r}; each entry needs its own name")
            names[name] = index
            where = f"intake.devices[{name!r}]"
            routes = parse_routes(where, entry.get("routes"))
            anchors = _anchors(where, entry.get("ca_file"))
            eku = _oid(where, entry.get("eku", ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string))
            device_from = entry.get("device_id_from", FROM_SAN_URI)
            if device_from not in DEVICE_FIELDS:
                raise ValueError(f"{where}.device_id_from must be one of "
                                 f"{', '.join(DEVICE_FIELDS)}")
            prefix = entry.get("device_id_prefix", "")
            if not isinstance(prefix, str):
                raise ValueError(f"{where}.device_id_prefix must be a string")
            skew = entry.get("max_skew_s", DEFAULT_MAX_SKEW_S)
            if not isinstance(skew, int) or isinstance(skew, bool) or not 30 <= skew <= 3600:
                raise ValueError(f"{where}.max_skew_s must be a whole number of seconds "
                                 "from 30 to 3600")
            cred = Credential(name, routes, org_partition(policy, where, entry),
                              fleet=True, require_device=True)
            for anchor in anchors:
                fingerprint = anchor.fingerprint(hashes.SHA256())
                if fingerprint in seen_anchors:
                    raise ValueError(
                        f"{where}.ca_file and intake.devices[{seen_anchors[fingerprint]!r}] "
                        "list the same CA certificate; a certificate it issued would prove "
                        "either entry. Give each entry its own issuing CA")
                seen_anchors[fingerprint] = name
            entries.append(DeviceEntry(cred, verification.Store(anchors), eku, device_from,
                                       prefix, skew,
                                       frozenset(a.subject.public_bytes() for a in anchors)))
        return cls(entries)

    def verify(self, headers: Mapping[str, str]) -> Caller | None:
        raw = headers.get("authorization", "")
        scheme, _, token = raw.partition(" ")
        if scheme != SCHEME or not token or len(token) > MAX_JWS_CHARS:
            return None
        try:
            parsed = _parse_jws(token.strip())
        except (ValueError, TypeError, KeyError, binascii.Error, RecursionError):
            return None
        header, claims, signing_input, signature, chain = parsed
        now = self._clock()
        issuers = {c.issuer.public_bytes() for c in chain}
        matched = []
        for entry in self._entries:
            if not entry.subjects & issuers:
                continue
            device = self._check(entry, header, claims, signing_input, signature, chain, now)
            if device is not None:
                matched.append(Caller(entry.credential, device, claims["sha256"],
                                      claims["route"]))
        # More than one entry proved would make list order decide the org.
        return matched[0] if len(matched) == 1 else None

    def _check(self, entry: DeviceEntry, header: dict, claims: dict, signing_input: bytes,
               signature: bytes, chain: list[x509.Certificate], now: float) -> str | None:
        if abs(now - claims["iat"]) > entry.max_skew_s:
            return None
        leaf, intermediates = chain[0], chain[1:]
        moment = datetime.fromtimestamp(now, UTC)
        ee_policy = _ee_policy(entry.eku)
        try:
            verifier = (verification.PolicyBuilder().store(entry.store).time(moment)
                        .extension_policies(
                            ca_policy=verification.ExtensionPolicy.webpki_defaults_ca(),
                            ee_policy=ee_policy)
                        .build_client_verifier())
            verifier.verify(leaf, intermediates)
            _verify_signature(leaf.public_key(), header["alg"], signing_input, signature)
        except (verification.VerificationError, InvalidSignature, ValueError, TypeError):
            return None
        device = _device_id(leaf, entry.device_from, entry.device_prefix)
        return device if device is not None and DEVICE_ID.fullmatch(device) else None


def _parse_jws(token: str) -> tuple[dict, dict, bytes, bytes, list[x509.Certificate]]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    try:
        header = json.loads(_b64url(parts[0]))
        claims = json.loads(_b64url(parts[1]))
    except RecursionError as exc:
        raise ValueError("nested too deeply") from exc
    if not (isinstance(header, dict) and isinstance(claims, dict)):
        raise ValueError("not an object")
    if header.get("typ") != JWS_TYPE or header.get("crit") is not None:
        raise ValueError("not a forgd request JWS")
    if header.get("alg") not in ("ES256", "ES384", "RS256", "PS256", "EdDSA"):
        raise ValueError("unsupported algorithm")
    x5c = header.get("x5c")
    if not (isinstance(x5c, list) and 1 <= len(x5c) <= 4
            and all(isinstance(c, str) for c in x5c)):
        raise ValueError("x5c must list one to four certificates")
    # x5c is standard base64, not base64url (RFC 7515 4.1.6).
    chain = [x509.load_der_x509_certificate(base64.b64decode(c, validate=True)) for c in x5c]
    iat, route, digest = claims.get("iat"), claims.get("route"), claims.get("sha256")
    if not (isinstance(iat, int) and not isinstance(iat, bool)
            and isinstance(route, str) and isinstance(digest, str)
            and _HEX64.fullmatch(digest)):
        raise ValueError("claims must carry iat, route and sha256")
    return header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64url(parts[2]), chain


def _device_id(cert: x509.Certificate, field: str, prefix: str) -> str | None:
    values: list[str] = []
    if field == FROM_SUBJECT_CN:
        values = [str(a.value) for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    else:
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            return None
        kind = x509.UniformResourceIdentifier if field == FROM_SAN_URI else x509.DNSName
        values = [str(v) for v in san.get_values_for_type(kind)]
    matches = [v[len(prefix):] for v in values if v.startswith(prefix)]
    return matches[0] if len(matches) == 1 else None


def _anchors(where: str, raw: Any) -> list[x509.Certificate]:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{where}.ca_file must name a PEM file of the CA certificates "
                         "devices chain to")
    try:
        data = Path(raw).read_bytes()
    except OSError as exc:
        raise ValueError(f"{where}.ca_file could not be read: {type(exc).__name__}") from exc
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        raise ValueError(f"{where}.ca_file holds no PEM certificate") from exc
    return certs


def _oid(where: str, raw: Any) -> ObjectIdentifier:
    if not isinstance(raw, str):
        raise ValueError(f"{where}.eku must be a dotted OID string")
    try:
        return ObjectIdentifier(raw)
    except ValueError as exc:
        raise ValueError(f"{where}.eku must be a dotted OID string") from exc


def sign_request(body: bytes, route: str, chain: Sequence[x509.Certificate], key: Any,
                 now: float | None = None) -> str:
    """The Authorization header value a device sends with `body` on `route`."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        alg = "ES384" if isinstance(key.curve, ec.SECP384R1) else "ES256"
    elif isinstance(key, rsa.RSAPrivateKey):
        alg = "PS256"
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        alg = "EdDSA"
    else:
        raise ValueError("the device key must be EC (P-256 or P-384), RSA or Ed25519")
    from cryptography.hazmat.primitives.serialization import Encoding

    header = {"alg": alg, "typ": JWS_TYPE,
              "x5c": [base64.b64encode(c.public_bytes(Encoding.DER)).decode("ascii")
                      for c in chain]}
    claims = {"iat": int(now if now is not None else time.time()), "route": route,
              "sha256": body_digest(body)}
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
                     + b64url(json.dumps(claims, separators=(",", ":")).encode()))
    data = signing_input.encode("ascii")
    if alg.startswith("ES"):
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        digest = hashes.SHA256() if alg == "ES256" else hashes.SHA384()
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(digest)))
        size = 32 if alg == "ES256" else 48
        signature = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    elif alg == "PS256":
        signature = key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                               salt_length=32), hashes.SHA256())
    else:
        signature = key.sign(data)
    return f"{SCHEME} {signing_input}.{b64url(signature)}"
