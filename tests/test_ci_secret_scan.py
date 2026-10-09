"""ci.yml's secret scan reads each event's own commits, and the default
branch's full history on the schedule -- never every fetched branch.

`gitleaks git` with no `--log-opts` walks `git log --all`, so with
`fetch-depth: 0` it scanned every remote branch against the checked-out
commit's `.gitleaks.toml`, which allowlists none of the other branches'
fixtures.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
ZERO = "0" * 40


def _job() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["secret-scan"]


def _git_steps() -> list[dict]:
    return [s for s in _job()["steps"] if "gitleaks git" in str(s.get("run", ""))]


def _event_step() -> dict:
    [step] = [s for s in _git_steps() if s.get("if") == "github.event_name != 'schedule'"]
    return step


def test_the_job_runs_on_the_schedule():
    assert "schedule" not in _job().get("if", ""), _job().get("if")


def test_the_working_tree_is_scanned_on_every_event():
    [step] = [s for s in _job()["steps"] if "gitleaks dir ." in str(s.get("run", ""))]
    assert "if" not in step, step["if"]


def test_every_history_scan_names_its_commits():
    steps = _git_steps()
    assert len(steps) == 2, [s.get("name") for s in steps]
    for step in steps:
        assert "--log-opts=" in step["run"], step["name"]
        assert "--all" not in step["run"], step["name"]


def test_the_schedule_scans_the_default_branch_full_history():
    [step] = [s for s in _git_steps() if s.get("if") == "github.event_name == 'schedule'"]
    assert "--log-opts=HEAD" in step["run"], step["run"]


def test_the_event_scan_takes_its_shas_from_env():
    step = _event_step()
    assert "${{" not in step["run"], step["run"]
    assert step["env"] == {
        "EVENT": "${{ github.event_name }}",
        "PR_BASE": "${{ github.event.pull_request.base.sha }}",
        "PR_HEAD": "${{ github.event.pull_request.head.sha }}",
        "BEFORE": "${{ github.event.before }}",
        "SHA": "${{ github.sha }}",
    }


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """Three commits on main, and a side commit that main does not contain."""
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    for i in range(3):
        (r / "f").write_text(str(i))
        _git(r, "add", "f")
        _git(r, "-c", "user.name=t", "-c", "user.email=t@example.com",
             "-c", "commit.gpgsign=false", "commit", "-q", "-m", str(i))
    _git(r, "checkout", "-q", "-b", "side", "HEAD~1")
    (r / "g").write_text("side")
    _git(r, "add", "g")
    _git(r, "-c", "user.name=t", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", "commit", "-q", "-m", "side")
    _git(r, "checkout", "-q", "main")
    return r


@pytest.mark.skipif(shutil.which("bash") is None or shutil.which("git") is None,
                    reason="needs bash and git")
@pytest.mark.parametrize("case", ["pr", "push", "push-new-branch", "push-forced", "dispatch"])
def test_the_event_scan_chooses_its_range(repo, tmp_path, case):
    """The step's own shell, run against a real repository with a gitleaks
    that records its arguments."""
    head = _git(repo, "rev-parse", "HEAD")
    first = _git(repo, "rev-parse", "HEAD~2")
    side = _git(repo, "rev-parse", "side")
    env = {"EVENT": "push", "PR_BASE": "", "PR_HEAD": "", "BEFORE": "", "SHA": head}
    expected = {
        "pr": (dict(EVENT="pull_request", PR_BASE=first, PR_HEAD=head), f"{first}..{head}"),
        "push": (dict(BEFORE=first), f"{first}..{head}"),
        "push-new-branch": (dict(BEFORE=ZERO), head),
        "push-forced": (dict(BEFORE=side), head),
        "dispatch": (dict(EVENT="workflow_dispatch"), "HEAD"),
    }
    overrides, want = expected[case]
    env.update(overrides)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "gitleaks.args"
    fake = bin_dir / "gitleaks"
    fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {log}\n')
    fake.chmod(0o755)

    proc = subprocess.run(
        ["bash", "-c", _event_step()["run"]], cwd=repo, capture_output=True, text=True,
        env={**os.environ, **env, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"},
    )
    assert proc.returncode == 0, proc.stderr
    args = log.read_text().splitlines()
    assert args[:2] == ["git", "."], args
    assert f"--log-opts={want}" in args, args
