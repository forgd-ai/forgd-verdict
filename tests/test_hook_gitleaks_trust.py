"""The hook runs a gitleaks binary the policy names, not one a project can
put on PATH.

A Claude Code project's `.claude/settings.json` `env` block reaches the
hook's environment, PATH included. A `gitleaks` that exits 0 with no output
reads as a clean T1 scan."""

from __future__ import annotations

import io
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from forgd_verdict.hook import cli

REPO = Path(__file__).resolve().parents[1]
REAL_GITLEAKS = shutil.which("gitleaks")
needs_gitleaks = pytest.mark.skipif(REAL_GITLEAKS is None, reason="needs gitleaks")

# deploy/MDM.md's T1 probe: a GitLab token, which gitleaks detects and T0
# does not, assembled from two parts so this file holds no literal one.
GITLAB_PROBE = {"hook_event_name": "UserPromptSubmit",
                "prompt": "token " + "glpat-" + "V9v0M48onQvilZzFz0tS"}


def _policy(tmp_path: Path, *, gitleaks=None, hook=None) -> str:
    """The shipped policy.yaml with `gitleaks` merged into
    `detectors.gitleaks` and `hook` into `hook`, written to `tmp_path`.
    The hook profile's `binary` is removed, so the top-level one applies."""
    data = yaml.safe_load((REPO / "policy.yaml").read_text(encoding="utf-8"))
    data["hook"]["detectors"]["gitleaks"].pop("binary")
    data["detectors"]["gitleaks"].update(gitleaks or {})
    data["hook"].update(hook or {})
    path = tmp_path / "etc" / "policy.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


def _fake_gitleaks_on_path(tmp_path: Path, monkeypatch) -> None:
    """A `gitleaks` that reports no findings and exits 0, first on PATH."""
    bin_dir = tmp_path / "project-bin"
    bin_dir.mkdir()
    fake = bin_dir / "gitleaks"
    fake.write_text("#!/bin/sh\ncat >/dev/null\nprintf '[]'\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def _hook(policy: str, monkeypatch, capsys) -> tuple[int, str, str]:
    """`forgd-verdict hook --policy <policy>` on GITLAB_PROBE, in process."""
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(GITLAB_PROBE)))
    code = cli.main(["--policy", policy])
    out = capsys.readouterr()
    return code, out.out, out.err


def _blocked(code: int, out: str) -> bool:
    return code == 2 or (code == 0 and bool(out) and json.loads(out).get("decision") == "block")


@pytest.fixture(autouse=True)
def _throwaway_spool(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_VERDICT_SPOOL", str(tmp_path / "state" / "spool"))


@needs_gitleaks
def test_a_project_gitleaks_on_path_does_not_replace_the_configured_one(
        tmp_path, monkeypatch, capsys):
    policy = _policy(tmp_path, gitleaks={"binary": REAL_GITLEAKS})
    _fake_gitleaks_on_path(tmp_path, monkeypatch)
    code, out, err = _hook(policy, monkeypatch, capsys)
    assert code == 0, err
    assert json.loads(out)["decision"] == "block"


def test_a_project_gitleaks_on_path_is_not_run_when_no_binary_is_configured(
        tmp_path, monkeypatch, capsys):
    policy = _policy(tmp_path, hook={"on_error": "block"})
    _fake_gitleaks_on_path(tmp_path, monkeypatch)
    code, out, err = _hook(policy, monkeypatch, capsys)
    assert _blocked(code, out), (code, out, err)
    assert "gitleaks" in err


def test_no_gitleaks_under_auto_is_said_and_follows_on_error(tmp_path, monkeypatch, capsys):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    policy = _policy(tmp_path, hook={"on_error": "block"})
    code, out, err = _hook(policy, monkeypatch, capsys)
    assert _blocked(code, out), (code, out, err)
    assert "gitleaks" in err


def test_no_gitleaks_under_auto_and_on_error_allow_is_said(tmp_path, monkeypatch, capsys):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    code, out, err = _hook(_policy(tmp_path), monkeypatch, capsys)
    assert code == 0, err
    assert "decision" not in json.loads(out)
    assert "gitleaks" in err


@pytest.mark.parametrize("binary", ["gitleaks", "./bin/gitleaks", "$GITLEAKS"])
def test_a_binary_that_is_not_absolute_is_refused_without_project_overrides(
        tmp_path, monkeypatch, capsys, binary):
    """Through `evaluate`, which sees the policy before `main` anchors a
    relative path to the policy's directory."""
    _fake_gitleaks_on_path(tmp_path, monkeypatch)
    (tmp_path / "bin").mkdir()
    shutil.copy(tmp_path / "project-bin" / "gitleaks", tmp_path / "bin" / "gitleaks")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITLEAKS", str(tmp_path / "project-bin" / "gitleaks"))
    from forgd_verdict.policy import load_policy

    policy = load_policy(_policy(tmp_path, gitleaks={"binary": binary},
                                 hook={"on_error": "block"}), for_hook=True)
    code, out, _spool = cli.evaluate(GITLAB_PROBE, policy)
    err = capsys.readouterr().err
    assert _blocked(code, out), (code, out, err)
    assert "gitleaks" in err


def test_a_bare_binary_name_is_refused_through_main(tmp_path, monkeypatch, capsys):
    _fake_gitleaks_on_path(tmp_path, monkeypatch)
    policy = _policy(tmp_path, gitleaks={"binary": "gitleaks"}, hook={"on_error": "block"})
    code, out, err = _hook(policy, monkeypatch, capsys)
    assert _blocked(code, out), (code, out, err)
    assert "gitleaks" in err


@needs_gitleaks
@pytest.mark.parametrize("binary", [None, "gitleaks"])
def test_project_overrides_keep_the_path_lookup(tmp_path, monkeypatch, capsys, binary):
    monkeypatch.setenv("PATH", f"{Path(REAL_GITLEAKS).parent}{os.pathsep}/usr/bin:/bin")
    gitleaks = {"binary": binary} if binary else {}
    policy = _policy(tmp_path, gitleaks=gitleaks, hook={"project_overrides": True})
    code, out, err = _hook(policy, monkeypatch, capsys)
    assert code == 0, err
    assert json.loads(out)["decision"] == "block"
    assert "trusted" not in err


def test_t1_not_running_under_on_error_allow_is_shown_in_the_session(
        tmp_path, monkeypatch, capsys):
    _fake_gitleaks_on_path(tmp_path, monkeypatch)
    code, out, err = _hook(_policy(tmp_path), monkeypatch, capsys)
    assert code == 0, err
    body = json.loads(out)
    assert "decision" not in body
    assert "detectors.gitleaks.binary" in body["systemMessage"]
    assert GITLAB_PROBE["prompt"].split()[-1] not in out + err
