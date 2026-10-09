"""`forgd-verdict scan` does not exit 0 on content a blocking tier did not scan.

Exit 1 is a deny, as `decide` reaches it. Exit 3 is an allow from an
incomplete scan: a blocking detector that failed, stopped early or was left
out at build."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import FAKE_AWS_KEY

from forgd_verdict.cli import main

FAILING = "#!/bin/sh\ncat >/dev/null\nexit 3\n"
CLEAN = "please summarise the release notes"


def _failing_gitleaks(tmp_path: Path) -> str:
    path = tmp_path / "opt" / "gitleaks"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(FAILING, encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _scan(tmp_path, capsys, gitleaks: dict, text: str = CLEAN, **policy):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "privacy": {"hash_salt": "s"},
        "detectors": {"gitleaks": {"severity": "block", "timeout_ms": 300, **gitleaks}},
        **policy}))
    source = tmp_path / "input.txt"
    source.write_text(text)
    code = main(["--policy", str(path), "scan", str(source)])
    out = capsys.readouterr()
    return code, json.loads(out.out), out.err


def _gitleaks(tmp_path, failure: str) -> dict:
    if failure == "fails-during-the-scan":
        return {"enabled": True, "binary": _failing_gitleaks(tmp_path)}
    return {"enabled": "auto", "binary": str(tmp_path / "no-such-gitleaks")}


FAILURES = ["fails-during-the-scan", "missing-at-build"]


@pytest.mark.parametrize("failure", FAILURES)
def test_a_clean_scan_without_t1_exits_3(tmp_path, capsys, failure):
    code, body, err = _scan(tmp_path, capsys, _gitleaks(tmp_path, failure))
    assert code == 3
    assert body["action"] == "allow"
    assert body["tiers_dropped"] == ["gitleaks"]
    assert "gitleaks did not run" in err


@pytest.mark.parametrize("failure", FAILURES)
def test_under_on_tier_dropped_deny_it_is_a_deny(tmp_path, capsys, failure):
    code, body, _ = _scan(tmp_path, capsys, _gitleaks(tmp_path, failure),
                          server={"on_tier_dropped": "deny"})
    assert code == 1
    assert body["action"] == "deny"
    assert "gitleaks did not run" in body["deny_reason"]


@pytest.mark.parametrize("failure", FAILURES)
def test_a_deny_still_exits_1_when_t1_did_not_run(tmp_path, capsys, failure):
    code, body, _ = _scan(tmp_path, capsys, _gitleaks(tmp_path, failure),
                          text=f"deploy {FAKE_AWS_KEY}")
    assert code == 1
    assert body["action"] == "deny"


def test_a_disabled_t1_is_a_complete_scan(tmp_path, capsys):
    code, body, err = _scan(tmp_path, capsys, {"enabled": False})
    assert code == 0
    assert body["tiers_dropped"] == []
    assert "did not run" not in err
