"""`hook.device_salt_path` is in the shipped policy.yaml, commented with the
MDM paths, and POLICY.md is its reference."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from forgd_verdict.policy import ENV_OVERRIDES

REPO = Path(__file__).resolve().parent.parent
POSIX = "/etc/forgd/device-salt"
WINDOWS = r"C:\ProgramData\forgd\device-salt"


def _hook_section() -> str:
    text = (REPO / "policy.yaml").read_text()
    start = text.index("\nhook:\n")
    end = re.search(r"\n[a-z_]+:\n", text[start + 1:]).start() + start + 1
    return text[start:end]


def test_the_shipped_policy_names_the_setting_commented_with_both_paths():
    section = _hook_section()
    line = next(ln for ln in section.splitlines() if "device_salt_path:" in ln)
    assert line.lstrip().startswith("#"), "shipped commented: the path must be provisioned first"
    assert POSIX in line
    assert WINDOWS in section


def test_uncommented_the_line_is_valid_yaml_for_the_hook():
    line = next(ln for ln in _hook_section().splitlines() if "device_salt_path:" in ln)
    uncommented = line.replace("#", "", 1).split("  #")[0]
    parsed = yaml.safe_load("hook:\n" + uncommented)
    assert parsed == {"hook": {"device_salt_path": POSIX}}


def test_the_shipped_policy_says_what_happens_without_it():
    section = _hook_section().lower()
    assert "per-user" in section and "new device id" in section


def test_policy_md_has_a_reference_entry():
    text = (REPO / "docs" / "POLICY.md").read_text()
    m = re.search(r"^## `hook\.device_salt_path`\n(.*?)(?=^## )", text, re.M | re.S)
    assert m, "POLICY.md has no `hook.device_salt_path` section"
    body = m.group(1)
    for needle in (POSIX, WINDOWS, "deploy/MDM.md", "stderr", "environment"):
        assert needle in body, needle
    assert "dashboard" in body.lower()


def test_it_is_not_settable_from_the_environment():
    assert all(path != ("hook", "device_salt_path") for path, _ in ENV_OVERRIDES.values())
