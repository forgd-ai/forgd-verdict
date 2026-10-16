"""The gitleaks CLI the image ships.

It is built from deploy/gitleaks-cli at the Dockerfile's GITLEAKS_VERSION,
so the module's require must name the same version. The subprocess path
always passes --config, and with the shipped policy that is the packaged
baseline, the same file gitleaksd loads."""

from __future__ import annotations

import re
import shutil
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


# --- relative paths under hook.project_overrides ---------------------------

# A rule only the project's config has, so a finding of it shows which config
# the scan loaded.
PROJECT_RULE = '''
[[rules]]
id = "project-only-token"
regex = 'PROJECTTOKEN[0-9]{12}'
'''


def _project_scan(tmp_path, monkeypatch, gitleaks: dict) -> list:
    """Load a hook policy with `hook.project_overrides: true` and `gitleaks`,
    from a directory other than the project, and scan from the project."""
    import pytest
    import yaml

    from forgd_verdict.models import ScanUnit
    from forgd_verdict.policy import load_policy

    if not shutil.which("gitleaks"):
        pytest.skip("gitleaks is not installed")
    managed, project = tmp_path / "managed", tmp_path / "project"
    managed.mkdir()
    project.mkdir(exist_ok=True)
    (project / ".gitleaks.toml").write_text(PROJECT_RULE, encoding="utf-8")
    policy_path = managed / "policy.yaml"
    policy_path.write_text(yaml.safe_dump({
        "hook": {"project_overrides": True},
        "detectors": {"gitleaks": {"enabled": True, **gitleaks}},
    }), encoding="utf-8")
    monkeypatch.chdir(project)
    policy = load_policy(str(policy_path), for_hook=True)
    assert policy.raw["detectors"]["gitleaks"].get("config") == gitleaks.get("config")
    [detector] = [d for d in policy.build_detectors(profile="hook") if d.name == "gitleaks"]
    return detector.scan([ScanUnit("t", None, "token PROJECTTOKEN123456789012 here")])


def test_a_relative_config_under_project_overrides_is_the_projects_file(tmp_path, monkeypatch):
    """gitleaks runs from a fresh temporary directory, and the relative
    path was passed to it unchanged, so it named a file in that empty
    directory and every scan failed on a bad --config."""
    findings = _project_scan(tmp_path, monkeypatch, {"config": ".gitleaks.toml"})
    assert [f.detector for f in findings] == ["gitleaks:project-only-token"]


def test_a_relative_binary_path_under_project_overrides_runs(tmp_path, monkeypatch):
    """`_resolve_binary` found it from this process's working directory, and
    the child was started from the temporary one."""
    (tmp_path / "project" / "bin").mkdir(parents=True)
    (tmp_path / "project" / "bin" / "gitleaks").symlink_to(shutil.which("gitleaks") or "/x")
    findings = _project_scan(tmp_path, monkeypatch,
                             {"config": ".gitleaks.toml", "binary": "bin/gitleaks"})
    assert [f.detector for f in findings] == ["gitleaks:project-only-token"]


def test_the_detector_holds_absolute_paths(tmp_path, monkeypatch):
    from forgd_verdict.detectors.gitleaks import GitleaksDetector

    monkeypatch.chdir(tmp_path)
    exe = tmp_path / "bin" / "tool"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(0o755)
    detector = GitleaksDetector(binary="bin/tool", config="rules.toml")
    assert detector._binary == str(exe)
    assert detector._config == str(tmp_path / "rules.toml")
