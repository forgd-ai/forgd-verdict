"""The intake binds what a shipped record may say about who and where.

A fleet token is shared by every laptop in it, so a field the sender
chooses is a field any of them can forge."""

from __future__ import annotations

import pytest
from conftest import ASGIClient
from test_intake_fleet import (
    AGENT_TOKEN,
    ALICE_TOKEN,
    FLEET_TOKEN,
    SALT,
    _app,
    _headers,
    _ndjson,
    _policy,
    _stored,
    org_env,  # noqa: F401
)

from forgd_verdict.metadata import opaque_id
from forgd_verdict.models import pseudonym, ulid
from forgd_verdict.store.base import SOURCE_CODE_HOOK, FindingRow, VerdictRecord

DEVICE = "d000000000042"
CLIENTS = [{"name": "alice-laptop", "token": ALICE_TOKEN},
           {"name": "billing-agent", "token": AGENT_TOKEN, "agent": True}]


def _hook_rec(**kw):
    """A record shaped as `hook/cli.py` `_spool` writes one."""
    fields = {
        "source": SOURCE_CODE_HOOK,
        "surface": "claude-code-local",
        "action": "deny",
        "findings": [FindingRow("regex:aws-access-key", "block", "cmd", "h1")],
        "findings_count": 1,
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "actor_hash": pseudonym("alice", "device-salt", "user"),
        "request_id": f"PreToolUse:Bash:{opaque_id('toolu_01', 'device-salt', 'id')}",
        "build": "0.46.0",
    }
    fields.update(kw)
    return VerdictRecord(**fields)


async def _ship(tmp_path, *records, token=FLEET_TOKEN, device=DEVICE):
    app = _app(tmp_path, _policy(clients=CLIENTS))
    try:
        status, _ = await ASGIClient(app).post("/intake", _ndjson(*records),
                                               _headers(token, device))
        return status, _stored(app)
    finally:
        app.close()


# -- surface ---------------------------------------------------------------


@pytest.mark.parametrize("forged", ["agent:bot/payroll", "claude.ai", "otel-unknown", None])
async def test_a_fleet_record_is_claude_code_local_whatever_it_claims(tmp_path, forged):
    _, [stored] = await _ship(tmp_path, _hook_rec(surface=forged))
    assert stored.surface == "claude-code-local"


async def test_an_agent_credential_record_is_agent_by_name(tmp_path):
    _, [stored] = await _ship(tmp_path, _hook_rec(surface="claude-code-local"),
                              token=AGENT_TOKEN, device=None)
    assert stored.surface == "agent:billing-agent"


# -- actor_hash ------------------------------------------------------------


async def test_a_sent_actor_hash_never_equals_a_server_side_one(tmp_path):
    server_side = pseudonym("ceo@corp.example", SALT, "user")
    _, [stored] = await _ship(tmp_path, _hook_rec(actor_hash=server_side))
    assert stored.actor_hash != server_side
    assert stored.actor_hash is not None


async def test_two_credentials_sending_one_actor_hash_store_different_values(tmp_path):
    sent = pseudonym("alice", "device-salt", "user")
    _, [fleet] = await _ship(tmp_path / "a", _hook_rec(actor_hash=sent))
    _, [laptop] = await _ship(tmp_path / "b", _hook_rec(actor_hash=sent),
                              token=ALICE_TOKEN, device=None)
    assert fleet.actor_hash != laptop.actor_hash
    assert sent not in (fleet.actor_hash, laptop.actor_hash)


async def test_one_laptop_user_still_groups(tmp_path):
    sent = pseudonym("alice", "device-salt", "user")
    _, stored = await _ship(tmp_path, _hook_rec(actor_hash=sent), _hook_rec(actor_hash=sent),
                            _hook_rec(actor_hash=pseudonym("bob", "device-salt", "user")))
    a, b, c = (r.actor_hash for r in stored)
    assert a == b != c


@pytest.mark.parametrize("sent", ["ceo@victim.example", "user_XYZ", "id_ceo",
                                  "user_" + "0" * 11, ""])
async def test_an_actor_hash_not_shaped_like_the_hooks_is_dropped(tmp_path, sent):
    _, [stored] = await _ship(tmp_path, _hook_rec(actor_hash=sent))
    assert stored.actor_hash is None


# -- bounded identifiers -----------------------------------------------------


@pytest.mark.parametrize("field,value", [
    ("session_id", "s" * 300),
    ("session_id", "sess id with spaces"),
    ("session_id", "<script>"),
    ("request_id", "PreToolUse:Bash:" + "x" * 300),
    ("request_id", "a\nb"),
    ("model", "m" * 200),
    ("model", "claude <b>bold</b>"),
    ("build", "0.46.0; rm -rf /"),
    ("build", "9" * 300),
])
async def test_an_oversized_or_odd_identifier_is_dropped(tmp_path, field, value):
    _, [stored] = await _ship(tmp_path, _hook_rec(**{field: value}))
    assert getattr(stored, field) in (None, "")


async def test_a_real_hook_record_keeps_its_identifiers(tmp_path):
    sent = _hook_rec(session_id="sess_0123456789abcdef", model="claude-opus-5-5",
                     build="0.46.0+0123456789ab+acme-plugins=1.2.0",
                     request_id=f"UserPromptSubmit:prompt:{ulid()}")
    _, [stored] = await _ship(tmp_path, sent)
    for field in ("session_id", "request_id", "model", "build"):
        assert getattr(stored, field) == getattr(sent, field), field


# -- fields only other adapters write ----------------------------------------


@pytest.mark.parametrize("field,value", [
    ("reported_as", "claude.ai"),
    ("session_started_at", "1999-01-01T00:00:00Z"),
    ("session_updated_at", "1999-01-01T00:00:00Z"),
    ("deleted_at", "1999-01-01T00:00:00Z"),
])
async def test_a_field_the_hook_never_sends_is_dropped(tmp_path, field, value):
    _, [stored] = await _ship(tmp_path, _hook_rec(**{field: value}))
    assert getattr(stored, field) is None
