"""`azure_auth.credential()` picks the Azure credential for the store and the
Azure Monitor sink.

The azure extra is not installed in the test environment, so each test puts a
stub `azure.identity` in `sys.modules` for the lazy import to find.
"""

from __future__ import annotations

import sys
import types

import pytest

from forgd_verdict.azure_auth import credential


class _Default:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _Managed:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def _install_identity(monkeypatch):
    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = _Default
    identity.ManagedIdentityCredential = _Managed
    azure = types.ModuleType("azure")
    azure.identity = identity
    monkeypatch.setitem(sys.modules, "azure", azure)
    monkeypatch.setitem(sys.modules, "azure.identity", identity)


def test_client_id_names_the_managed_identity(monkeypatch):
    _install_identity(monkeypatch)
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-123")

    cred, desc = credential()

    assert type(cred) is _Managed
    assert cred.kwargs == {"client_id": "client-123"}
    assert desc == "managed:client-123"


def test_no_client_id_uses_the_default_chain(monkeypatch):
    _install_identity(monkeypatch)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)

    cred, desc = credential()

    assert type(cred) is _Default
    assert cred.kwargs == {}
    assert desc == "default-chain"


def test_empty_client_id_names_no_identity(monkeypatch):
    _install_identity(monkeypatch)
    monkeypatch.setenv("AZURE_CLIENT_ID", "")

    cred, desc = credential()

    assert type(cred) is _Default
    assert desc == "default-chain"


def test_missing_extra_names_the_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "azure.identity", None)

    with pytest.raises(RuntimeError, match=r"forgd-verdict\[azure\]"):
        credential()
