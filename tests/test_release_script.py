"""scripts/cut_release.sh bumps, stages and rewrites every version it owns,
prepares the bump on a release branch, and tags main once it is merged.

The subcommand tests run the script in a throwaway repository whose origin
is a local bare repository, with `uv` replaced by a stub."""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tomllib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "cut_release.sh"
CHART = "deploy/helm/forgd-verdict/Chart.yaml"
HOOK = "packaging/forgd-verdict-hook/pyproject.toml"
SYNC = "  uv sync --all-extras --no-extra ml\n"
BUMPED = ("pyproject.toml", "src/forgd_verdict/__init__.py", CHART, HOOK)


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _block() -> str:
    block = re.search(r"^\s*python3 - \"\$VERSION\" <<'PY'\n(.*?)^PY$", _script(), re.M | re.S)
    assert block, "could not find the bump block in cut_release.sh"
    return block.group(1)


def _bump(tmp_path: pathlib.Path, version: str) -> pathlib.Path:
    for rel in BUMPED:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, dst)
    subprocess.run([sys.executable, "-", version], input=_block(), text=True,
                   cwd=tmp_path, check=True, capture_output=True)
    return tmp_path


def _chart_version(text: str) -> tuple[int, int, int]:
    m = re.search(r"(?m)^version: (\d+)\.(\d+)\.(\d+)$", text)
    assert m, "no chart version line"
    return tuple(int(g) for g in m.groups())


def test_the_release_script_stages_every_file_it_bumps():
    bumped = set(re.findall(r'^\s*\("([^"]+)", r', _block(), re.MULTILINE))
    assert bumped == set(BUMPED)
    add = re.search(r"^\s*git add (.*?)\n\s*git commit", _script(), re.MULTILINE | re.DOTALL)
    assert add, "no `git add ... git commit` pair in cut_release.sh"
    missing = sorted(p for p in bumped if p not in add.group(1).split())
    assert not missing, f"cut_release.sh bumps {missing} but never stages them"


def test_the_release_script_bumps_the_chart_app_version_and_patch_version(tmp_path):
    before = (REPO / CHART).read_text(encoding="utf-8")
    after = (_bump(tmp_path, "9.9.9") / CHART).read_text(encoding="utf-8")
    assert 'appVersion: "9.9.9"' in after
    major, minor, patch = _chart_version(before)
    assert _chart_version(after) == (major, minor, patch + 1)


def test_the_release_script_bump_block_rewrites_every_version_it_owns(tmp_path):
    root = _bump(tmp_path, "9.9.9")
    core = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    hook = tomllib.loads((root / HOOK).read_text())["project"]
    assert core["version"] == "9.9.9"
    assert hook["version"] == "9.9.9"
    assert hook["dependencies"] == ["forgd-verdict==9.9.9"]
    assert '__version__ = "9.9.9"' in (root / "src/forgd_verdict/__init__.py").read_text()
    assert 'appVersion: "9.9.9"' in (root / CHART).read_text()


def test_the_release_script_writes_no_changelog():
    assert "CHANGELOG" not in _script().upper()


def test_the_release_script_signs_off_and_leaves_signing_to_git_config():
    script = _script()
    assert 'git commit -q -s -m "release: v$VERSION"' in script
    assert 'git tag -a "v$VERSION" -m "v$VERSION"' in script
    for line in script.splitlines():
        words = line.split()
        if words[:2] == ["git", "commit"]:
            assert "-S" not in words and not any(w.startswith("--gpg-sign") for w in words)
        if words[:2] == ["git", "tag"]:
            assert not {"-s", "-u", "--sign"} & set(words)


def test_the_release_script_refuses_off_a_clean_main():
    script = _script()
    assert 'if [ -n "$(git status --porcelain)" ]; then' in script
    assert 'if [ "$BRANCH" != "main" ]; then' in script
    assert (script.index("git status --porcelain") < script.index(SYNC)
            < script.index('uv run pytest -q -n auto -m "not serial"\n')
            < script.index("uv run pytest -q -m serial\n"))


def test_the_release_script_syncs_every_extra_but_ml():
    script = _script()
    assert SYNC in script
    project = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]
    assert "ml" in project["optional-dependencies"]


def test_the_release_script_points_at_the_release_workflow():
    script = _script()
    assert ".github/workflows/release.yml" in script
    assert "gh run watch" in script and "--workflow release.yml" in script


def _git(cwd, *args, env=None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def _release_repo(tmp_path: pathlib.Path):
    """A clone of a bare origin holding the version files and the script."""
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text("")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "uv").write_text("#!/bin/sh\nexit 0\n")
    (stubs / "uv").chmod(0o755)
    env = {**os.environ, "GIT_CONFIG_GLOBAL": str(gitconfig), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "Ada Example", "GIT_AUTHOR_EMAIL": "ada@example.com",
           "GIT_COMMITTER_NAME": "Ada Example", "GIT_COMMITTER_EMAIL": "ada@example.com",
           "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}"}
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin), env=env)
    work = tmp_path / "work"
    for rel in (*BUMPED, "scripts/cut_release.sh"):
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, work / rel)
    _git(work, "init", "-q", "-b", "main", env=env)
    _git(work, "add", "-A", env=env)
    _git(work, "commit", "-q", "-m", "base", env=env)
    _git(work, "remote", "add", "origin", str(origin), env=env)
    _git(work, "push", "-q", "-u", "origin", "main", env=env)

    def run(*args):
        return subprocess.run(["bash", "scripts/cut_release.sh", *args], cwd=work, env=env,
                              capture_output=True, text=True, timeout=120)

    def remote(*args):
        return _git(work, "--git-dir", str(origin), *args, env=env)

    run.git = lambda *args: _git(work, *args, env=env)
    run.remote = remote
    return run


def _refs(run) -> dict[str, str]:
    lines = run.remote("for-each-ref", "--format=%(refname) %(objectname)").splitlines()
    return dict(line.split() for line in lines)


def _merge_release_branch(run, version: str):
    """What merging the release PR does to origin's main."""
    run.git("push", "-q", "origin", f"release/v{version}:main")


def test_the_release_script_takes_a_subcommand():
    assert "git push origin main" not in _script()
    for args in ((), ("9.9.9",), ("publish", "9.9.9"), ("prepare",), ("tag", "9.9")):
        proc = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True)
        assert proc.returncode == 64, (args, proc.stdout + proc.stderr)


def test_prepare_pushes_a_release_branch_and_leaves_main_alone(tmp_path):
    run = _release_repo(tmp_path)
    before = _refs(run)
    proc = run("prepare", "9.9.9")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    after = _refs(run)
    assert "refs/heads/release/v9.9.9" in after
    after.pop("refs/heads/release/v9.9.9")
    assert after == before
    message = run.remote("log", "-1", "--format=%B", "refs/heads/release/v9.9.9")
    assert message.startswith("release: v9.9.9")
    assert "Signed-off-by: Ada Example <ada@example.com>" in message
    assert "gh pr create" in proc.stdout and "release/v9.9.9" in proc.stdout
    assert not run.git("tag", "--list")


def test_prepare_refuses_a_main_behind_origin(tmp_path):
    run = _release_repo(tmp_path)
    run.git("commit", "-q", "--allow-empty", "-m", "ahead")
    run.git("push", "-q", "origin", "main")
    run.git("reset", "-q", "--hard", "HEAD~1")
    before = _refs(run)
    proc = run("prepare", "9.9.9")
    assert proc.returncode == 1
    assert "origin/main" in proc.stderr
    assert _refs(run) == before


def test_tag_refuses_a_tree_whose_versions_do_not_match(tmp_path):
    run = _release_repo(tmp_path)
    before = _refs(run)
    proc = run("tag", "9.9.9")
    assert proc.returncode == 1
    assert "9.9.9" in proc.stderr
    assert _refs(run) == before
    assert not run.git("tag", "--list")


def test_tag_refuses_a_main_behind_origin(tmp_path):
    run = _release_repo(tmp_path)
    assert run("prepare", "9.9.9").returncode == 0
    _merge_release_branch(run, "9.9.9")
    run.git("checkout", "-q", "main")
    before = _refs(run)
    proc = run("tag", "9.9.9")
    assert proc.returncode == 1
    assert "origin/main" in proc.stderr
    assert _refs(run) == before


def test_tag_refuses_a_tag_that_exists(tmp_path):
    run = _release_repo(tmp_path)
    assert run("prepare", "9.9.9").returncode == 0
    _merge_release_branch(run, "9.9.9")
    run.git("checkout", "-q", "main")
    run.git("pull", "-q", "--ff-only")
    run.git("tag", "v9.9.9")
    proc = run("tag", "9.9.9")
    assert proc.returncode == 1
    assert "v9.9.9 already exists" in proc.stderr
    assert "refs/tags/v9.9.9" not in _refs(run)


def test_tag_pushes_only_the_tag(tmp_path):
    run = _release_repo(tmp_path)
    assert run("prepare", "9.9.9").returncode == 0
    _merge_release_branch(run, "9.9.9")
    run.git("checkout", "-q", "main")
    run.git("pull", "-q", "--ff-only")
    before = _refs(run)
    proc = run("tag", "9.9.9")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    after = _refs(run)
    tag = after.pop("refs/tags/v9.9.9")
    assert after == before
    assert run.remote("cat-file", "-t", tag) == "tag"
    assert run.remote("rev-parse", "refs/tags/v9.9.9^{commit}") == before["refs/heads/main"]


REJECTED_VERSIONS = ["01.2.3", "1.02.3", "1.2.03", "00.1.0", "1.2", "1.2.3.400", "v1.2.3",
                     "1.2.3-rc1", " 1.2.3", "1.2.3\n", "1.2.3\n4.5.6", ""]
ACCEPTED_VERSIONS = ["0.0.0", "0.46.1", "10.0.200"]


def _run_with_stubs(tmp_path, *args):
    """Runs the script outside any repository with `git` and `uv` replaced
    by stubs that log their arguments and fail."""
    stubs = tmp_path / "bin"
    stubs.mkdir()
    log = tmp_path / "calls.log"
    for name in ("git", "uv"):
        (stubs / name).write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\nexit 97\n')
        (stubs / name).chmod(0o755)
    env = {**os.environ, "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}"}
    proc = subprocess.run(["bash", str(SCRIPT), *args], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=30)
    return proc, log.read_text() if log.exists() else ""


@pytest.mark.parametrize("command", ["prepare", "tag"])
@pytest.mark.parametrize("version", REJECTED_VERSIONS)
def test_the_release_script_refuses_a_non_canonical_version(tmp_path, command, version):
    proc, calls = _run_with_stubs(tmp_path, command, version)
    assert proc.returncode == 64, proc.stdout + proc.stderr
    assert calls == ""


@pytest.mark.parametrize("command", ["prepare", "tag"])
@pytest.mark.parametrize("version", ACCEPTED_VERSIONS)
def test_the_release_script_accepts_a_canonical_version(tmp_path, command, version):
    proc, calls = _run_with_stubs(tmp_path, command, version)
    assert proc.returncode not in (0, 64), proc.stdout + proc.stderr
    assert calls.startswith("git status --porcelain\n"), calls
