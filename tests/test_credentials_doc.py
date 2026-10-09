"""docs/CREDENTIALS.md against the code it describes."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import WHSEC, ASGIClient, make_policy

from forgd_verdict.policy import SECRET_LIST_PATHS, SECRET_MAP_PATHS, SECRET_PATHS
from forgd_verdict.server.app import VerdictServer

ROOT = Path(__file__).resolve().parents[1]
CREDENTIALS = " ".join((ROOT / "docs" / "CREDENTIALS.md").read_text(encoding="utf-8").split())
OPERATIONS = " ".join((ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8").split())


def _documented_healthz_fields(text: str, lead: str) -> set[str]:
    """The backticked names in the sentence of `text` that starts with `lead`."""
    start = text.index(lead)
    sentence = text[start:text.index(". ", start + len(lead))]
    return set(re.findall(r"`([a-z_]+)`", sentence))


async def _healthz_keys() -> set[str]:
    server = VerdictServer(make_policy(server={"mode": "observe", "secrets": [WHSEC]}))
    try:
        status, body = await ASGIClient(server).get("/healthz")
    finally:
        server.close()
    assert status == 200
    return set(body)


async def test_credentials_lists_every_healthz_field():
    documented = _documented_healthz_fields(CREDENTIALS, "probes work. It returns")
    assert documented == await _healthz_keys()


async def test_operations_lists_every_healthz_field():
    documented = _documented_healthz_fields(OPERATIONS, "On the verdict server the body has")
    documented -= {"not_configured", "ok", "down"}
    assert documented == await _healthz_keys()


SECRET_KEYS = sorted(
    [".".join(path) for path in SECRET_PATHS]
    + [".".join(parent) + "[]." + key for parent, key in SECRET_LIST_PATHS]
    + [".".join(path) for path in SECRET_MAP_PATHS])


@pytest.mark.parametrize("dotted", SECRET_KEYS)
def test_every_secret_policy_key_is_documented(dotted):
    """Each key the Policy tab redacts appears in CREDENTIALS.md in its dotted form."""
    assert f"`{dotted}`" in CREDENTIALS, dotted
