"""The hook's prompt events put `prompt` last in document order.

gitleaks keeps the newest units that fit under `max_bytes`, newest being
last in document order. Padding in `slash_command`, `user_input` or
`command_args` must push those out of the window and keep `prompt`.
Assertions are presence and absence only, so a failure never prints a
planted value.
"""

from __future__ import annotations

import json
import shutil

import pytest
from conftest import GITLEAKS_T1_ONLY, make_policy

from forgd_verdict.core import SEAM_CHARS, decide, scan
from forgd_verdict.detectors.gitleaks import DEFAULT_MAX_BYTES
from forgd_verdict.extract import MAX_UNIT_BYTES, hook_units
from forgd_verdict.hook.cli import run
from forgd_verdict.models import UNSCANNED, UNSCANNED_CAPPED

PAT = GITLEAKS_T1_ONLY["gitlab-pat"]
WORDS = "the quick brown fox jumps over the lazy dog "
# One whole unit: at MAX_UNIT_BYTES nothing is cut, and two of them joined
# are one byte over DEFAULT_MAX_BYTES.
PAD = (WORDS * (MAX_UNIT_BYTES // len(WORDS) + 1))[:MAX_UNIT_BYTES]
# The secret is further from either end of `prompt` than a seam reaches,
# so only a window that holds `prompt` finds it.
FILLER = WORDS * 10
PROMPT = f"{FILLER}deploy with token {PAT} please {FILLER}"


def submit_event(**fields) -> dict:
    return {"session_id": "s", "hook_event_name": "UserPromptSubmit", **fields}


def expansion_event(**fields) -> dict:
    return {"session_id": "s", "hook_event_name": "UserPromptExpansion",
            "expansion_type": "slash_command", "command_name": "deploy",
            "command_source": "project", **fields}


PADDED = {
    "UserPromptSubmit": submit_event(slash_command=PAD, user_input=PAD, prompt=PROMPT),
    "UserPromptExpansion": expansion_event(command_args=PAD, prompt=PAD[:-len(PROMPT)] + PROMPT),
}


@pytest.mark.parametrize("payload", [
    submit_event(slash_command="/deploy", user_input="old", prompt="new"),
    expansion_event(command_args="prod", prompt="new"),
], ids=["UserPromptSubmit", "UserPromptExpansion"])
def test_prompt_is_the_last_unit(payload):
    units = hook_units(payload)
    assert [u.locator for u in units][-1] == "prompt"


def test_padding_fills_the_gitleaks_window():
    assert 2 * len(PAD) + 1 > DEFAULT_MAX_BYTES >= len(PAD) + 1 + len(PROMPT)
    assert PROMPT.index(PAT) > SEAM_CHARS
    assert len(PROMPT) - PROMPT.index(PAT) - len(PAT) > SEAM_CHARS
    assert len(PADDED["UserPromptExpansion"]["prompt"]) == MAX_UNIT_BYTES
    for payload in PADDED.values():
        assert not any(u.truncated for u in hook_units(payload))


needs_gitleaks = pytest.mark.skipif(not shutil.which("gitleaks"), reason="needs gitleaks")


def _policy():
    policy = make_policy(
        detectors={"gitleaks": {"enabled": True, "severity": "block", "timeout_ms": 300_000,
                                "binary": shutil.which("gitleaks")}},
        server={"on_tier_dropped": "allow"},
    )
    assert policy.on_tier_dropped == "allow"
    return policy


@needs_gitleaks
@pytest.mark.parametrize("event", sorted(PADDED))
def test_a_padded_prompt_event_keeps_prompt_in_the_gitleaks_window(event):
    policy = _policy()
    detectors = policy.build_detectors(include_local_only=True, profile="hook")
    result = scan(hook_units(PADDED[event]), detectors)

    assert UNSCANNED_CAPPED in result.detectors_skipped
    assert UNSCANNED not in result.detectors_skipped
    assert [(f.detector, f.locator) for f in result.findings
            if f.detector.startswith("gitleaks")] == [("gitleaks:gitlab-pat", "prompt")]
    verdict = decide(result.findings, policy, dropped=result.detectors_skipped)
    assert verdict.action == "deny"
    assert "GitLab" in verdict.deny_reason
    assert "could not be checked" not in verdict.deny_reason


@needs_gitleaks
@pytest.mark.parametrize("event", sorted(PADDED))
def test_the_hook_names_the_secret_in_a_padded_prompt(event):
    code, out = run(PADDED[event], _policy())

    assert code == 0
    body = json.loads(out)
    assert body["decision"] == "block"
    assert "GitLab" in body["reason"]
    assert "could not be checked" not in body["reason"]
    assert PAT not in out
