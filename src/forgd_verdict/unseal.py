"""Open a sealed value with the KMS key that sealed it.

Runs as the operator, under the operator's own cloud login: the Azure
credential chain, the AWS credential chain or Application Default
Credentials. Only the data key goes to the KMS; the value is opened here
and printed to the terminal, and nowhere else.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from .sealing import KMS_KINDS, Sealing, split

# arn:aws:kms:<region>:<account>:key/<id>
_AWS_REGION = re.compile(r"arn:aws[a-z-]*:kms:([a-z0-9-]+):")


class UnsealError(RuntimeError):
    """The value cannot be opened, with a reason fit to print."""


def _azure(key_id: str) -> Callable[[bytes], bytes]:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
    except ImportError as exc:
        raise UnsealError("Azure Key Vault needs `pip install "
                          "'forgd-verdict[kms-azure]'`") from exc
    client = CryptographyClient(key_id, DefaultAzureCredential())
    return lambda wrapped: client.decrypt(EncryptionAlgorithm.rsa_oaep_256,
                                          wrapped).plaintext


def _aws(key_id: str) -> Callable[[bytes], bytes]:
    try:
        import boto3
    except ImportError as exc:
        raise UnsealError("AWS KMS needs `pip install 'forgd-verdict[aws]'`") from exc
    region = _AWS_REGION.match(key_id)
    client = boto3.client("kms", **({"region_name": region.group(1)} if region else {}))
    return lambda wrapped: client.decrypt(
        KeyId=key_id, CiphertextBlob=wrapped,
        EncryptionAlgorithm="RSAES_OAEP_SHA_256")["Plaintext"]


def _gcp(key_id: str) -> Callable[[bytes], bytes]:
    try:
        from google.cloud import kms
    except ImportError as exc:
        raise UnsealError("Cloud KMS needs `pip install 'forgd-verdict[kms-gcp]'`") from exc
    client = kms.KeyManagementServiceClient()
    return lambda wrapped: client.asymmetric_decrypt(
        request={"name": key_id, "ciphertext": wrapped}).plaintext


UNWRAPPERS: dict[str, Callable[[str], Callable[[bytes], bytes]]] = {
    "azure": _azure, "aws": _aws, "gcp": _gcp}


def resolve(token: str, sealing: Sealing | None, kms: str | None,
            key_id: str | None) -> tuple[str, str]:
    """The KMS and key id that open `token`: `kms` and `key_id` when both
    are given, otherwise the policy's key with the token's fingerprint."""
    try:
        parts = split(token)
    except ValueError as exc:
        raise UnsealError("that is not a sealed value") from exc
    if kms or key_id:
        if not (kms and key_id):
            raise UnsealError("--kms and --key-id go together")
        if kms not in KMS_KINDS:
            raise UnsealError(f"--kms must be one of {', '.join(KMS_KINDS)}")
        return kms, key_id
    key = sealing.key_for(parts.fingerprint) if sealing is not None else None
    if key is None:
        raise UnsealError(
            f"no key in privacy.sealing has fingerprint {parts.fingerprint}. Name the "
            "policy that sealed it with --policy, add a rotated key to "
            "privacy.sealing.retired, or pass --kms and --key-id")
    return key.kms, key.id
