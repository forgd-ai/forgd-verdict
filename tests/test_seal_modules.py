"""The seal-azure, seal-aws and seal-gcp modules: the key `privacy.sealing`
seals to, and who may decrypt with it.

Every forgd-verdict service seals with the public key alone, so the one
grant these modules make is decryption to the operators' group, and none
may reach a service identity. Rendered with mocked providers; nothing
reaches a cloud.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from terraform_render import RG, plugin_dir, render_once

from forgd_verdict import sealing

ROOT = Path(__file__).resolve().parent.parent
MODULES = ROOT / "deploy" / "terraform" / "modules"
PEM = rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

DEPLOYER = "99999999-0000-0000-0000-000000000000"
OPERATORS = "77777777-0000-0000-0000-000000000000"
# store-azure's writer, reader and control principal ids, as its render
# mocks them.
AZURE_SERVICES = [f"{d * 8}-0000-0000-0000-000000000000" for d in "123"]
AZURE_KEY_ID = "https://kv-seal.vault.azure.net/keys/forgd-verdict-seal/0123456789abcdef"

ACCOUNT = "111111111111"
AWS_OPERATORS = [f"arn:aws:iam::{ACCOUNT}:role/findings-responders"]
AWS_SERVICES = [f"arn:aws:iam::{ACCOUNT}:role/{n}-role" for n in ("writer", "reader", "control")]
AWS_KEY_ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/1234abcd-12ab-44cd-96ef-1234567890ab"

GCP_OPERATORS = ["group:findings-responders@example.com"]
GCP_SERVICES = [f"serviceAccount:{n}@p.iam.gserviceaccount.com"
                for n in ("writer", "reader", "control")]
GCP_KEY = "projects/p/locations/europe-west2/keyRings/forgd-verdict-seal/cryptoKeys/forgd-verdict-seal"


def _azure(block: str, kind: str, name: str) -> dict:
    if kind == "azurerm_key_vault":
        return {"id": f"{RG}/providers/Microsoft.KeyVault/vaults/kv-seal"}
    if kind == "azurerm_key_vault_key":
        return {"id": AZURE_KEY_ID, "public_key_pem": PEM}
    return {}


def _aws(block: str, kind: str, name: str) -> dict:
    if kind == "aws_kms_key":
        return {"arn": AWS_KEY_ARN, "key_id": AWS_KEY_ARN.rsplit("/", 1)[1]}
    return {}


def _gcp(block: str, kind: str, name: str) -> dict:
    if kind == "google_kms_key_ring":
        return {"id": GCP_KEY.rsplit("/cryptoKeys/", 1)[0]}
    if kind == "google_kms_crypto_key":
        return {"id": GCP_KEY}
    return {}


HARNESS = {
    "seal-azure": {"providers": ["azurerm"], "overrides": _azure, "mock_data": {
        "azurerm_client_config": {"object_id": DEPLOYER,
                                  "tenant_id": "00000000-0000-0000-0000-000000000000",
                                  "client_id": DEPLOYER,
                                  "subscription_id": "00000000-0000-0000-0000-000000000000"}}},
    "seal-aws": {"providers": ["aws"], "overrides": _aws, "mock_data": {
        "aws_caller_identity": {"account_id": ACCOUNT},
        "aws_partition": {"partition": "aws", "dns_suffix": "amazonaws.com"},
        "aws_kms_public_key": {"public_key_pem": PEM}}},
    "seal-gcp": {"providers": ["google"], "overrides": _gcp, "mock_data": {
        "google_kms_crypto_key_version": {
            "public_key": [{"algorithm": "RSA_DECRYPT_OAEP_3072_SHA256", "pem": PEM}]}}},
}

VARIABLES = {
    "seal-azure": {"resource_group_name": "rg", "location": "uksouth",
                   "key_vault_name": "kv-seal", "decrypt_principal_ids": [OPERATORS],
                   "service_principal_ids": AZURE_SERVICES},
    "seal-aws": {"decrypt_principal_arns": AWS_OPERATORS,
                 "service_principal_arns": AWS_SERVICES},
    "seal-gcp": {"project_id": "p", "location": "europe-west2",
                 "decrypt_members": GCP_OPERATORS, "service_members": GCP_SERVICES},
}


def _render(tmp_path: Path, name: str, **over) -> dict:
    module = MODULES / name
    return render_once(tmp_path / name, module, {**VARIABLES[name], **over},
                       plugins=plugin_dir(module), **HARNESS[name])


def _source(name: str) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted((MODULES / name).glob("*.tf")))


def _resource_types(name: str) -> set[str]:
    return set(re.findall(r'^(?:resource|data) "(\w+)"', _source(name), re.M))


requires_terraform = pytest.mark.skipif(
    __import__("shutil").which("terraform") is None, reason="terraform is not installed")


# -- every module ----------------------------------------------------------------


@pytest.mark.parametrize("name, kms", [("seal-azure", "azure"), ("seal-aws", "aws"),
                                       ("seal-gcp", "gcp")])
def test_the_output_is_a_privacy_sealing_key(name, kms):
    outputs = (MODULES / name / "outputs.tf").read_text(encoding="utf-8")
    block = re.search(r'output "sealing_key" \{.*?value = \{(.*?)\n  \}', outputs, re.S).group(1)
    assert set(re.findall(r"^\s*(\w+)\s*=", block, re.M)) == {"kms", "id", "public_key"}
    assert f'kms        = "{kms}"' in block


def test_the_azure_key_is_named_by_its_version():
    """`id`, not `versionless_id`: a rotated key's old values open only with
    the version that sealed them."""
    outputs = (MODULES / "seal-azure" / "outputs.tf").read_text(encoding="utf-8")
    assert "azurerm_key_vault_key.seal.id" in outputs and "versionless_id" not in outputs


@pytest.mark.parametrize("name, allowed", [
    ("seal-azure", {"azurerm_client_config", "azurerm_key_vault",
                    "azurerm_key_vault_access_policy", "azurerm_key_vault_key"}),
    ("seal-aws", {"aws_caller_identity", "aws_partition", "aws_kms_key", "aws_kms_alias",
                  "aws_kms_public_key"}),
    ("seal-gcp", {"google_kms_key_ring", "google_kms_crypto_key",
                  "google_kms_crypto_key_iam_member", "google_kms_crypto_key_version"}),
])
def test_no_module_grants_anything_but_what_these_tests_read(name, allowed):
    """A role assignment, a grant, an IAM binding or policy would be a way to
    decrypt these tests do not check."""
    assert _resource_types(name) == allowed


# -- Azure -----------------------------------------------------------------------


@requires_terraform
def test_azure_decrypt_goes_to_the_operators_alone(tmp_path):
    r = _render(tmp_path, "seal-azure")
    policies = [r["azurerm_key_vault_access_policy.deployer"],
                *r["azurerm_key_vault_access_policy.decrypt"].values()]
    by_object = {p["object_id"]: set(p["key_permissions"]) for p in policies}
    assert by_object == {DEPLOYER: {"Create", "Delete", "Get", "GetRotationPolicy", "Recover",
                                    "Update"},
                         OPERATORS: {"Decrypt", "Get"}}
    assert not any(p["secret_permissions"] or p["certificate_permissions"]
                   or p["storage_permissions"] for p in policies)
    vault = r["azurerm_key_vault.seal"]
    assert vault["rbac_authorization_enabled"] is False
    assert vault["purge_protection_enabled"] is True
    assert not vault["access_policy"]
    key = r["azurerm_key_vault_key.seal"]
    assert (key["key_type"], key["key_size"], key["key_opts"]) == ("RSA", 3072, ["decrypt"])


@requires_terraform
@pytest.mark.parametrize("over, message", [
    ({"decrypt_principal_ids": [OPERATORS, AZURE_SERVICES[1]]}, "service_principal_ids"),
    ({"deployer_object_id": AZURE_SERVICES[0]}, "deployer is a forgd-verdict service"),
])
def test_azure_refuses_a_service_that_could_decrypt(tmp_path, over, message):
    with pytest.raises(AssertionError, match=message):
        _render(tmp_path, "seal-azure", **over)


# -- AWS -------------------------------------------------------------------------


def _statements(r: dict) -> dict:
    return {s["Sid"]: s for s in json.loads(r["aws_kms_key.seal"]["policy"])["Statement"]}


@requires_terraform
def test_aws_decrypt_goes_to_the_operators_alone(tmp_path):
    r = _render(tmp_path, "seal-aws")
    statements = _statements(r)
    assert set(statements) == {"AccountAdministersTheKeyAndCannotUseIt",
                               "OperatorsDecryptSealedValues", "ServicesNeverDecrypt"}
    admin = statements["AccountAdministersTheKeyAndCannotUseIt"]
    assert "Action" not in admin and {"kms:Decrypt", "kms:CreateGrant"} <= set(admin["NotAction"])
    allows = [s for s in statements.values() if s["Effect"] == "Allow" and "Action" in s]
    assert [s["Sid"] for s in allows] == ["OperatorsDecryptSealedValues"]
    ops = statements["OperatorsDecryptSealedValues"]
    assert ops["Principal"] == {"AWS": AWS_OPERATORS} and ops["Action"] == ["kms:Decrypt"]
    assert ops["Condition"] == {"StringEquals": {"kms:EncryptionAlgorithm": "RSAES_OAEP_SHA_256"}}
    deny = statements["ServicesNeverDecrypt"]
    assert deny["Effect"] == "Deny" and deny["Principal"] == {"AWS": AWS_SERVICES}
    assert {"kms:Decrypt", "kms:CreateGrant"} <= set(deny["Action"])
    key = r["aws_kms_key.seal"]
    assert (key["key_usage"], key["customer_master_key_spec"]) == ("ENCRYPT_DECRYPT", "RSA_3072")


@requires_terraform
def test_aws_refuses_a_service_that_could_decrypt(tmp_path):
    with pytest.raises(AssertionError, match="service_principal_arns"):
        _render(tmp_path, "seal-aws", decrypt_principal_arns=[*AWS_OPERATORS, AWS_SERVICES[0]])


# -- Google Cloud ----------------------------------------------------------------


@requires_terraform
def test_gcp_decrypt_goes_to_the_operators_alone(tmp_path):
    r = _render(tmp_path, "seal-gcp")
    grants = list(r["google_kms_crypto_key_iam_member.decrypt"].values())
    assert [(g["member"], g["role"], g["crypto_key_id"]) for g in grants] == [
        (GCP_OPERATORS[0], "roles/cloudkms.cryptoKeyDecrypter", GCP_KEY)]
    key = r["google_kms_crypto_key.seal"]
    assert key["purpose"] == "ASYMMETRIC_DECRYPT"
    assert key["version_template"][0]["algorithm"] == "RSA_DECRYPT_OAEP_3072_SHA256"
    assert key["deletion_policy"] == "PREVENT"


@requires_terraform
def test_gcp_refuses_a_service_that_could_decrypt(tmp_path):
    with pytest.raises(AssertionError, match="service_members"):
        _render(tmp_path, "seal-gcp", decrypt_members=[*GCP_OPERATORS, GCP_SERVICES[2]])


# -- what privacy.sealing accepts ------------------------------------------------


@pytest.mark.parametrize("name, variable, accepted", [
    ("seal-azure", "key_size", {3072, 4096}),
    ("seal-aws", "key_spec", {"RSA_3072", "RSA_4096"}),
    ("seal-gcp", "algorithm", {"RSA_DECRYPT_OAEP_3072_SHA256", "RSA_DECRYPT_OAEP_4096_SHA256"}),
])
def test_each_module_offers_only_the_key_sizes_sealing_takes(name, variable, accepted):
    text = (MODULES / name / "variables.tf").read_text(encoding="utf-8")
    block = re.search(rf'variable "{variable}" \{{.*?\n\}}', text, re.S).group(0)
    listed = re.search(r"contains\(\[(.*?)\]", block).group(1)
    values = {json.loads(v) for v in re.findall(r'"[^"]*"|\d+', listed)}
    assert values == accepted
    assert {int(re.search(r"\d{4}", str(v)).group(0)) for v in values} == set(sealing.RSA_BITS)
