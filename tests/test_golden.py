"""Replay every golden frame in tests/golden/ through the real ASGI app.

The fixtures are files rather than inline dicts so they can also be replayed
by hand (`curl`), fed to the load generator, or walked through in a
workshop. Each file declares the action it must produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import ASGIClient, sign

from forgd_verdict.models import DENY_REASON_MAX, REFERENCE_ID_CHARSET, REFERENCE_ID_MAX
from forgd_verdict.server.app import VerdictServer

GOLDEN = sorted((Path(__file__).parent / "golden").glob("*.json"))
assert GOLDEN, "no golden frames found"


@pytest.fixture
def client(policy):
    server = VerdictServer(policy)
    yield ASGIClient(server)
    server.close()


@pytest.mark.parametrize("path", GOLDEN, ids=[p.stem for p in GOLDEN])
async def test_golden_frame(path: Path, client):
    fixture = json.loads(path.read_text())
    expected = fixture["_expect_action"]
    raw = json.dumps(fixture["frame"]).encode()

    status, verdict = await client.post(
        "/hook", raw, sign(raw, webhook_id=fixture["frame"]["request_id"])
    )

    # Every outcome is HTTP 200 with a parseable verdict. Anything else is a
    # webhook failure on Anthropic's side, never a deny.
    assert status == 200, f"{path.name}: expected 200, got {status}"
    assert verdict["action"] == expected, f"{path.name}: {fixture['_note']}"

    if expected == "deny":
        assert 0 < len(verdict["deny_reason"]) <= DENY_REASON_MAX
        ref = verdict["reference_id"]
        assert 0 < len(ref) <= REFERENCE_ID_MAX
        assert set(ref) <= REFERENCE_ID_CHARSET
        # The planted secret must not survive into the verdict.
        assert "AKIAQYLPMN5HGZTHX4UQ" not in json.dumps(verdict)
    else:
        assert "deny_reason" not in verdict


def test_every_golden_frame_declares_intent():
    for path in GOLDEN:
        fixture = json.loads(path.read_text())
        assert fixture["_expect_action"] in ("allow", "deny"), path.name
        assert fixture["_note"].strip(), f"{path.name} needs a _note explaining why"
        assert fixture["frame"]["request_id"], path.name
