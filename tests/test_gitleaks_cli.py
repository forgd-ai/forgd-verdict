"""The gitleaks CLI the image ships.

It is built from deploy/gitleaks-cli at the Dockerfile's GITLEAKS_VERSION,
so the module's require must name the same version. The subprocess path
always passes --config, and with the shipped policy that is the packaged
baseline, the same file gitleaksd loads."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = (REPO / "deploy" / "Dockerfile").read_text(encoding="utf-8")
GO_MOD = (REPO / "deploy" / "gitleaks-cli" / "go.mod").read_text(encoding="utf-8")


def _dockerfile_version() -> str:
    preamble = re.split(r"(?m)^FROM\s", DOCKERFILE, maxsplit=1)[0]
    (version,) = re.findall(r"(?m)^ARG GITLEAKS_VERSION=(\S+)\s*$", preamble)
    return version


def _go_mod_version() -> str:
    (version,) = re.findall(r"(?m)^\s*github\.com/zricethezav/gitleaks/v8 v(\S+)", GO_MOD)
    return version


def test_go_mod_requires_the_dockerfile_gitleaks_version():
    assert _go_mod_version() == _dockerfile_version()


def test_the_version_is_declared_only_before_the_first_stage():
    stages = re.split(r"(?m)^FROM\s", DOCKERFILE)[1:]
    for body in stages:
        assert not re.search(r"(?m)^ARG GITLEAKS_VERSION=", body)


def test_go_mod_declares_gitleaks_as_its_tool():
    assert re.search(r"(?m)^tool github\.com/zricethezav/gitleaks/v8\s*$", GO_MOD)


# --- the config the CLI loads ----------------------------------------------

def _argv(monkeypatch, **kwargs) -> list[str]:
    from forgd_verdict.detectors import gitleaks
    from forgd_verdict.models import ScanUnit

    seen: list[list[str]] = []

    def run(cmd, **_kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=b"[]", stderr=b"")

    monkeypatch.setattr(gitleaks.subprocess, "run", run)
    gitleaks.GitleaksDetector(binary=sys.executable, **kwargs).scan([ScanUnit("t", None, "x")])
    (cmd,) = seen
    return cmd


def test_the_subprocess_passes_the_packaged_baseline_when_no_config_is_set(monkeypatch):
    from forgd_verdict.detectors.gitleaks import BASELINE_CONFIG

    cmd = _argv(monkeypatch)
    assert cmd.count("--config") == 1
    assert cmd[cmd.index("--config") + 1] == str(BASELINE_CONFIG)


def test_the_subprocess_passes_an_operator_config(monkeypatch, tmp_path):
    config = str(tmp_path / "rules.toml")
    cmd = _argv(monkeypatch, config=config)
    assert cmd[cmd.index("--config") + 1] == config


def test_the_shipped_policy_gives_the_cli_and_the_daemon_the_same_config(monkeypatch):
    from forgd_verdict.detectors.gitleaks import BASELINE_CONFIG, GITLEAKS_CONFIG_ENV
    from forgd_verdict.policy import GITLEAKS_ROLE_PROFILES, gitleaks_daemon_config, load_policy

    monkeypatch.delenv(GITLEAKS_CONFIG_ENV, raising=False)
    monkeypatch.setenv("FORGD_GITLEAKS_SOCKET", "/run/forgd/gitleaks.sock")
    policy = load_policy(REPO / "policy.yaml")
    profiles = [name for name, section in policy.raw.items()
                if isinstance(section, dict) and "detectors" in section]
    assert profiles
    for name in (None, *profiles):
        derived = policy if name is None else policy.for_profile(name)
        assert derived.gitleaks_config() is None, name
    for role in GITLEAKS_ROLE_PROFILES:
        assert gitleaks_daemon_config(policy, role) == str(BASELINE_CONFIG), role
