"""examples/policy/: each example loads, and does what it says."""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

from conftest import FAKE_AWS_KEY, WHSEC, ASGIClient, frame, sign, text_msg

from forgd_verdict.policy import load_policy

ENFORCE = Path(__file__).parents[1] / "examples" / "policy" / "enforce.yaml"
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def test_the_enforce_example_loads_and_fails_closed():
    policy = load_policy(ENFORCE)
    assert policy.mode == "enforce"
    assert policy.on_tier_dropped == "deny"
    assert policy.server["on_internal_error"] == "fail"
    assert policy.hook["on_error"] == "block"
    assert policy.build_detectors()


def test_the_enforce_example_holds_no_ids_or_secrets():
    text = ENFORCE.read_text()
    assert not _UUID.search(text)
    raw = load_policy(ENFORCE).raw
    for value in (*raw["server"]["secrets"], raw["server"]["store"],
                  raw["server"]["metrics_token"], raw["privacy"]["hash_salt"]):
        assert value.startswith("$"), value


async def test_the_enforce_example_denies_a_credential(tmp_path, monkeypatch):
    from forgd_verdict.server.app import VerdictServer

    monkeypatch.setenv("WEBHOOK_SECRET", WHSEC)
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "store"))
    monkeypatch.setenv("FORGD_HASH_SALT", "example-salt")
    monkeypatch.chdir(tmp_path)
    server = VerdictServer(load_policy(ENFORCE))
    try:
        raw = json.dumps(frame([text_msg(f"deploy with {FAKE_AWS_KEY}")])).encode()
        status, verdict = await ASGIClient(server).post("/hook", raw, sign(raw))
    finally:
        server.close()
    assert status == 200
    assert verdict["action"] == "deny"


def test_the_enforce_example_blocks_a_malformed_hook_payload(monkeypatch, capsys):
    from forgd_verdict.hook import cli

    monkeypatch.setattr(sys, "stdin", io.StringIO("{not json"))
    assert cli.main(["--policy", str(ENFORCE)]) == 2
