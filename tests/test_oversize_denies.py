"""A block over the per-block scan limit denies under `on_tier_dropped: allow`.

Its middle is never scanned and is recorded as UNSCANNED. With a block
detector in the policy that denies, on the verdict path, the hook and the
collector. A secret in the head or tail is named as itself. Assertions are
presence and absence only, so a failure never prints a planted value.
"""

from __future__ import annotations

import json
import shutil

import pytest
from conftest import GITLEAKS_T1_ONLY, WHSEC, ASGIClient, frame, make_policy, sign, text_msg

from forgd_verdict.extract import MAX_UNIT_BYTES, TAIL_UNIT_BYTES, frame_units, hook_units
from forgd_verdict.hook.cli import run
from forgd_verdict.models import UNSCANNED, UNSCANNED_CAPPED
from forgd_verdict.otel.collect import collect
from forgd_verdict.otel.extract import record_units
from forgd_verdict.otel.payload import MAX_VALUE_CHARS
from forgd_verdict.server.app import VerdictServer

# Multi-MiB inputs through real gitleaks: alone, after the parallel suite.
pytestmark = [pytest.mark.serial,
              pytest.mark.skipif(not shutil.which("gitleaks"), reason="needs gitleaks")]

PAT = GITLEAKS_T1_ONLY["gitlab-pat"]
WORDS = "the quick brown fox jumps over the lazy dog "
SIZE = 6 * 1024 * 1024


# Past the head and before the tail on every adapter.
MIDDLE = MAX_UNIT_BYTES + (SIZE - MAX_UNIT_BYTES - TAIL_UNIT_BYTES) // 2


def _block(secret: str | None) -> str:
    """A SIZE-character block, with `secret` at MIDDLE when given."""
    text = (WORDS * (SIZE // len(WORDS) + 1))[:SIZE]
    if secret is None:
        return text
    planted = f" token {secret} "
    return text[:MIDDLE] + planted + text[MIDDLE + len(planted):]


SECRET_TEXT = _block(PAT)
BENIGN_TEXT = _block(None)
CASES = {"secret in the middle": SECRET_TEXT, "benign": BENIGN_TEXT}


def _policy(tmp_path):
    policy = make_policy(
        detectors={"gitleaks": {"enabled": True, "severity": "block", "timeout_ms": 300_000}},
        server={"mode": "enforce", "secrets": [WHSEC], "on_tier_dropped": "allow",
                "csv_path": str(tmp_path / "timings.csv"),
                "archive_dir": str(tmp_path / "archive")},
    )
    assert policy.on_tier_dropped == "allow"
    return policy


def test_the_secret_is_in_what_no_detector_reads():
    assert len(SECRET_TEXT) == len(BENIGN_TEXT) == SIZE > MAX_UNIT_BYTES
    units = frame_units([text_msg(SECRET_TEXT)])
    assert any(u.truncated for u in units)
    assert not any(PAT in u.text for u in units)
    hooked = hook_units({"hook_event_name": "UserPromptSubmit", "prompt": SECRET_TEXT})
    assert any(u.truncated for u in hooked)
    assert not any(PAT in u.text for u in hooked)


def _assert_size_deny(reason: str, reference_id: str):
    assert "over the size limit for scanning" in reason
    assert reference_id.startswith("fv_oversize_")
    assert PAT not in reason + reference_id
    assert PAT[-8:] not in reason + reference_id


# -- adapter 1: the verdict path ------------------------------------------


@pytest.mark.parametrize("case", sorted(CASES))
async def test_the_server_denies_an_oversize_block(case, tmp_path):
    server = VerdictServer(_policy(tmp_path))
    rows = []
    server.sink.submit = lambda row, findings: rows.append(row)
    raw = json.dumps(frame([text_msg(CASES[case])])).encode()
    try:
        status, verdict = await ASGIClient(server).post("/hook", raw, sign(raw))
    finally:
        server.close()

    assert status == 200
    assert verdict["action"] == "deny"
    _assert_size_deny(verdict["deny_reason"], verdict["reference_id"])
    assert PAT not in json.dumps(verdict)
    assert UNSCANNED in rows[0]["tiers_dropped"]
    assert UNSCANNED_CAPPED not in rows[0]["tiers_dropped"]


async def test_the_server_names_a_secret_in_the_head_of_an_oversize_block(tmp_path):
    server = VerdictServer(_policy(tmp_path))
    raw = json.dumps(frame([text_msg(f"token {PAT} " + BENIGN_TEXT)])).encode()
    try:
        status, verdict = await ASGIClient(server).post("/hook", raw, sign(raw))
    finally:
        server.close()

    assert status == 200
    assert verdict["action"] == "deny"
    assert "could not be checked" not in verdict["deny_reason"]
    assert PAT not in json.dumps(verdict)


# -- adapter 2: the hook's local scan -------------------------------------


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_hook_denies_an_oversize_prompt(case, tmp_path):
    code, out = run({"session_id": "s", "hook_event_name": "UserPromptSubmit",
                     "prompt": CASES[case]}, _policy(tmp_path))

    assert code == 0
    assert out, "the hook allowed"
    body = json.loads(out)
    assert body["decision"] == "block"
    assert "over the size limit for scanning" in body["reason"]
    assert PAT not in out


# -- adapter 4: the collector ---------------------------------------------


def _otel_record(prompt: str):
    from test_otel_payload import RESOURCE, logs_json

    from forgd_verdict.otel.payload import decode

    body = logs_json([{"attributes": {"event.name": "claude_code.user_prompt",
                                      "prompt": prompt, "session.id": "s",
                                      "prompt.id": "p"},
                       "body": ""}], RESOURCE)
    return decode(body, "application/json", "logs")[0]


def test_the_collector_leaves_the_middle_unscanned():
    units = record_units(_otel_record(SECRET_TEXT))
    prompt = [u for u in units if "prompt" in u.locator]
    assert prompt and all(len(u.text) <= MAX_VALUE_CHARS for u in prompt)
    assert any(u.truncated for u in prompt)
    assert not any(PAT in u.text for u in units)


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_collector_records_an_oversize_prompt_as_a_deny(case, tmp_path):
    policy = _policy(tmp_path)
    detectors = policy.build_detectors(profile="collector")
    assert any(d.name == "gitleaks" for d in detectors)

    (rec,), _ = collect([_otel_record(CASES[case])], detectors,
                        budget_ms=300_000, policy=policy)

    assert not rec.findings
    assert UNSCANNED in rec.tiers_dropped
    assert UNSCANNED_CAPPED not in rec.tiers_dropped
    assert rec.action == "deny"
