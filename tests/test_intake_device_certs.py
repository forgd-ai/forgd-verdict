"""`intake.devices`: a request signed with a device certificate that chains
to the org's CA is accepted and attributed to the device the certificate
names; anything else is refused. Each test names the mutation that makes
it fail."""

from __future__ import annotations

import datetime as dt
import json
import time

import pytest
from conftest import ASGIClient
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from forgd_verdict.intake.app import Intake
from forgd_verdict.intake.devicecert import sign_request
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store import LocalFileStore, VerdictRecord
from forgd_verdict.store.base import SOURCE_CODE_HOOK

DEVICE = "d0123456789ab"
NOW = dt.datetime.now(dt.UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn="Device CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=1))
            .not_valid_after(NOW + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False,
                                         False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return cert, key


def _leaf(ca, ca_key, *, device=DEVICE, eku=ExtendedKeyUsageOID.CLIENT_AUTH,
          not_after=None, uri=True):
    key = ec.generate_private_key(ec.SECP256R1())
    san = ([x509.UniformResourceIdentifier(f"urn:forgd:device:{device}")] if uri
           else [x509.DNSName(f"{device}.devices.example")])
    cert = (x509.CertificateBuilder().subject_name(_name(device)).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(hours=1))
            .not_valid_after(not_after or NOW + dt.timedelta(days=7))
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return cert, key


@pytest.fixture
def ca(tmp_path):
    cert, key = _ca()
    (tmp_path / "ca.pem").write_bytes(cert.public_bytes(Encoding.PEM))
    return cert, key


def _policy(tmp_path, **entry):
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"devices": [{"name": "corp-macs", "ca_file": str(tmp_path / "ca.pem"),
                                "device_id_prefix": "urn:forgd:device:", **entry}]},
        "privacy": {"hash_salt": "s"}}))


def _batch() -> bytes:
    return (VerdictRecord(source=SOURCE_CODE_HOOK, action="allow",
                          request_id="UserPromptSubmit:p:1").to_json() + "\n").encode()


async def _post(tmp_path, policy, header, body, route="/intake"):
    store = LocalFileStore(tmp_path / "store", instance="t")
    intake = Intake(policy, store=store)
    try:
        status, out = await ASGIClient(intake).post(
            route, body, {"authorization": header, "content-type": "application/x-ndjson"})
        intake.flush()
        return status, out, list(store.read_verdicts()), intake
    finally:
        intake.close()


async def test_a_signed_batch_is_attributed_to_the_certificate_s_device(tmp_path, ca):
    cert, key = _leaf(*ca)
    body = _batch()
    status, out, records, _ = await _post(tmp_path, _policy(tmp_path),
                                          sign_request(body, "intake", [cert], key), body)
    assert (status, out["accepted"]) == (200, 1)
    assert [(r.client, r.device) for r in records] == [("corp-macs", DEVICE)]


@pytest.mark.parametrize("case", [
    "other-ca", "expired", "wrong-eku", "body-changed", "other-route", "stale",
    "bearer", "garbled", "no-chain"])
async def test_anything_but_a_valid_signature_is_refused(tmp_path, ca, case):
    """Mutation: skip the chain, EKU, expiry, body, route or time check."""
    cert, key = _leaf(*ca)
    body, sign_body, route, now = _batch(), _batch(), "intake", None
    chain = [cert]
    if case == "other-ca":
        cert, key = _leaf(*_ca("Someone else's CA"))
        chain = [cert]
    elif case == "expired":
        cert, key = _leaf(*ca, not_after=NOW - dt.timedelta(minutes=1))
        chain = [cert]
    elif case == "wrong-eku":
        cert, key = _leaf(*ca, eku=ExtendedKeyUsageOID.SERVER_AUTH)
        chain = [cert]
    elif case == "body-changed":
        sign_body = body.replace(b"allow", b"deny ")
    elif case == "other-route":
        route = "scan"
    elif case == "stale":
        now = time.time() - 3600
    header = sign_request(sign_body, route, chain, key, now=now)
    if case == "bearer":
        header = "Bearer " + "fleet-token-synthetic-" + "0123456789abcdef"
    elif case == "garbled":
        header = header[:-8] + "AAAAAAAA"
    elif case == "no-chain":
        prefix, token = header.split(" ", 1)
        head, rest = token.split(".", 1)
        import base64

        decoded = json.loads(base64.urlsafe_b64decode(head + "==="))
        decoded["x5c"] = []
        head = base64.urlsafe_b64encode(json.dumps(decoded).encode()).rstrip(b"=").decode()
        header = f"{prefix} {head}.{rest}"
    status, _, records, _ = await _post(tmp_path, _policy(tmp_path), header, body)
    assert status == 401 and records == []


async def test_the_eku_and_the_device_field_are_configurable(tmp_path, ca):
    """Mutation: ignore `eku` or `device_id_from`."""
    custom = "1.3.6.1.4.1.99999.7"
    cert, key = _leaf(*ca, eku=ObjectIdentifier(custom), uri=False)
    body = _batch()
    policy = _policy(tmp_path, eku=custom, device_id_from="san_dns", device_id_prefix="")
    # The DNS name carries a suffix, so it is not a device id and is refused.
    status, _, _, _ = await _post(tmp_path, policy, sign_request(body, "intake", [cert], key),
                                  body)
    assert status == 401
    cert, key = _leaf(*ca, eku=ObjectIdentifier(custom))
    policy = _policy(tmp_path, eku=custom)
    status, _, records, _ = await _post(tmp_path, policy,
                                        sign_request(body, "intake", [cert], key), body)
    assert status == 200 and records[0].device == DEVICE


async def test_a_denied_device_is_refused_though_its_certificate_is_valid(tmp_path, ca,
                                                                         monkeypatch):
    """Revocation without a CRL: the runtime overrides' device denylist.
    Mutation: skip the denylist for a certificate."""
    cert, key = _leaf(*ca)
    body = _batch()
    policy = _policy(tmp_path)
    store = LocalFileStore(tmp_path / "store", instance="t")
    intake = Intake(policy, store=store)
    monkeypatch.setattr(intake.overrides, "denied_devices", lambda: frozenset({DEVICE}))
    try:
        status, out = await ASGIClient(intake).post(
            "/intake", body, {"authorization": sign_request(body, "intake", [cert], key),
                              "content-type": "application/x-ndjson"})
    finally:
        intake.close()
    assert (status, out) == (403, {"error": "device_denied"})


@pytest.mark.parametrize("entry, message", [
    ({"ca_file": "/nonexistent/ca.pem"}, "could not be read"),
    ({"eku": "not an oid"}, "dotted OID"),
    ({"device_id_from": "email"}, "device_id_from"),
    ({"max_skew_s": 5}, "max_skew_s"),
])
def test_a_bad_entry_is_refused_at_load(tmp_path, ca, entry, message):
    from forgd_verdict.intake.verify import verifiers

    with pytest.raises(ValueError, match=message):
        verifiers(_policy(tmp_path, **entry))


def test_the_hook_signs_with_its_device_certificate(tmp_path, ca, capsys):
    """A placeholder path is refused, since a project's environment sets it.
    Mutation: accept a `$VAR` path."""
    from forgd_verdict.hook.devicesign import device_signer
    from forgd_verdict.intake.devicecert import DeviceCertificates

    cert, key = _leaf(*ca)
    (tmp_path / "device.pem").write_bytes(cert.public_bytes(Encoding.PEM))
    (tmp_path / "device.key").write_bytes(key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    signer = device_signer({"device_certificate": {
        "cert_file": str(tmp_path / "device.pem"), "key_file": str(tmp_path / "device.key")}})
    header = signer(b"body", "intake")
    caller = DeviceCertificates.from_policy(_policy(tmp_path)).verify({"authorization": header})
    assert caller is not None and caller.device == DEVICE and caller.route == "intake"
    capsys.readouterr()
    assert device_signer({"device_certificate": {
        "cert_file": "$DEVICE_CERT", "key_file": str(tmp_path / "device.key")}}) is None
    assert "placeholder" in capsys.readouterr().err


def _intermediate(root, root_key):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name("Device Issuing CA"))
            .issuer_name(root.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=1))
            .not_valid_after(NOW + dt.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False,
                                         False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
    return cert, key


def test_a_chain_through_an_intermediate_verifies_only_with_it_sent(tmp_path, ca):
    """Mutation: drop the intermediates from the chain the verifier sees."""
    from forgd_verdict.intake.devicecert import DeviceCertificates

    inter, inter_key = _intermediate(*ca)
    cert, key = _leaf(inter, inter_key)
    verifier = DeviceCertificates.from_policy(_policy(tmp_path))
    with_chain = sign_request(b"x", "intake", [cert, inter], key)
    assert verifier.verify({"authorization": with_chain}).device == DEVICE
    leaf_only = sign_request(b"x", "intake", [cert], key)
    assert verifier.verify({"authorization": leaf_only}) is None


@pytest.mark.parametrize("make_key", [
    lambda: ec.generate_private_key(ec.SECP384R1()),
    lambda: __import__("cryptography.hazmat.primitives.asymmetric.rsa", fromlist=["x"])
    .generate_private_key(public_exponent=65537, key_size=2048),
    lambda: __import__("cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["x"])
    .Ed25519PrivateKey.generate(),
], ids=["es384", "ps256", "eddsa"])
def test_each_supported_key_type_signs_and_verifies(tmp_path, ca, make_key):
    from forgd_verdict.intake.devicecert import DeviceCertificates

    root, root_key = ca
    key = make_key()
    cert = (x509.CertificateBuilder().subject_name(_name(DEVICE)).issuer_name(root.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(hours=1))
            .not_valid_after(NOW + dt.timedelta(days=7))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                           critical=False)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(f"urn:forgd:device:{DEVICE}")]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
    verifier = DeviceCertificates.from_policy(_policy(tmp_path))
    assert verifier.verify({"authorization": sign_request(b"x", "scan", [cert], key)}).route \
        == "scan"


def test_an_algorithm_that_does_not_fit_the_key_is_refused(tmp_path, ca):
    """An ES256 header over an RSA signature, or `none`. Mutation: trust the
    header's alg without checking it against the key."""
    import base64

    from forgd_verdict.intake.devicecert import DeviceCertificates

    cert, key = _leaf(*ca)
    prefix, token = sign_request(b"x", "intake", [cert], key).split(" ", 1)
    head, claims, sig = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(head + "==="))
    verifier = DeviceCertificates.from_policy(_policy(tmp_path))
    for alg in ("RS256", "none", "HS256"):
        header["alg"] = alg
        forged = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        assert verifier.verify({"authorization": f"{prefix} {forged}.{claims}.{sig}"}) is None


def test_two_entries_cannot_share_a_ca(tmp_path, ca):
    """A certificate the shared CA issued would prove either entry, and list
    order would choose the org. Mutation: drop the startup check."""
    from forgd_verdict.intake.devicecert import DeviceCertificates

    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"devices": [
            {"name": "org-a", "ca_file": str(tmp_path / "ca.pem")},
            {"name": "org-b", "ca_file": str(tmp_path / "ca.pem")}]},
        "privacy": {"hash_salt": "s"}}))
    with pytest.raises(ValueError, match="same CA certificate"):
        DeviceCertificates.from_policy(policy)


def _leaf_with(ca, ca_key, *extensions):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (x509.CertificateBuilder().subject_name(_name(DEVICE)).issuer_name(ca.subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(NOW - dt.timedelta(hours=1))
               .not_valid_after(NOW + dt.timedelta(days=7))
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                              critical=False)
               .add_extension(x509.SubjectAlternativeName([
                   x509.UniformResourceIdentifier(f"urn:forgd:device:{DEVICE}")]),
                   critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   ca_key.public_key()), critical=False))
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(ca_key, hashes.SHA256()), key


@pytest.mark.parametrize("extensions", [
    [(x509.BasicConstraints(ca=True, path_length=None), True)],
    [(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)],
], ids=["ca-as-leaf", "no-digital-signature"])
def test_a_certificate_that_may_not_sign_as_a_device_is_refused(tmp_path, ca, extensions):
    """Mutation: drop the BasicConstraints or KeyUsage check from the device
    certificate's policy."""
    from forgd_verdict.intake.devicecert import DeviceCertificates

    cert, key = _leaf_with(*ca, *extensions)
    verifier = DeviceCertificates.from_policy(_policy(tmp_path))
    assert verifier.verify({"authorization": sign_request(b"x", "intake", [cert], key)}) is None
    ok_cert, ok_key = _leaf_with(*ca, (x509.KeyUsage(True, False, False, False, False, False,
                                                      False, False, False), True))
    assert verifier.verify({"authorization": sign_request(b"x", "intake", [ok_cert],
                                                          ok_key)}) is not None


def test_the_hook_refuses_a_relative_certificate_path(tmp_path, ca, capsys):
    """A relative path names a file the project supplies. Mutation: accept it."""
    from forgd_verdict.hook.devicesign import device_signer

    assert device_signer({"device_certificate": {
        "cert_file": "device.pem", "key_file": str(tmp_path / "device.key")}}) is None
    assert "absolute path" in capsys.readouterr().err


def test_a_certificate_that_proves_two_entries_is_refused(tmp_path, ca):
    """Entries built past the startup check, as a cross-signed CA would
    leave them. Mutation: take the last or first match."""
    from forgd_verdict.intake.devicecert import DeviceCertificates

    one = DeviceCertificates.from_policy(_policy(tmp_path))._entries[0]
    two = one.__class__(one.credential._replace(name="org-b"), one.store, one.eku,
                        one.device_from, one.device_prefix, one.max_skew_s, one.subjects)
    cert, key = _leaf(*ca)
    header = sign_request(b"x", "intake", [cert], key)
    assert DeviceCertificates([one]).verify({"authorization": header}) is not None
    assert DeviceCertificates([one, two]).verify({"authorization": header}) is None
