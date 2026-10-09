"""scripts/check_dco.sh, run against throwaway git repositories."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_dco.sh"
AUTHOR = ("Ada Example", "ada@example.com")


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    empty = tmp_path / "gitconfig"
    empty.write_text("")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": AUTHOR[0], "GIT_AUTHOR_EMAIL": AUTHOR[1],
           "GIT_COMMITTER_NAME": AUTHOR[0], "GIT_COMMITTER_EMAIL": AUTHOR[1]}

    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=root, env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    git("init", "-q", "-b", "main")
    git("commit", "-q", "--allow-empty", "-m", "base")
    git.env = env
    git.root = root
    return git


def _check(git, base: str = "main", head: str = "HEAD",
           pr_author_login: str | None = None) -> subprocess.CompletedProcess:
    env = {k: v for k, v in git.env.items() if k != "PR_AUTHOR_LOGIN"}
    if pr_author_login is not None:
        env["PR_AUTHOR_LOGIN"] = pr_author_login
    return subprocess.run(["bash", str(SCRIPT), base, head], cwd=git.root, env=env,
                          capture_output=True, text=True, timeout=60)


def test_a_signed_off_commit_passes(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty", "-s", "-m", "signed")
    proc = _check(repo)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 commit(s) checked" in proc.stdout


def test_a_missing_sign_off_fails(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty", "-s", "-m", "signed")
    repo("commit", "-q", "--allow-empty", "-m", "unsigned")
    proc = _check(repo)
    assert proc.returncode == 1
    assert "FAIL" in proc.stdout and "unsigned" in proc.stdout
    assert "1 without every sign-off" in proc.stdout
    assert "git rebase --signoff" in proc.stderr


def test_a_sign_off_with_another_email_fails(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty", "-m",
         "mismatched\n\nSigned-off-by: Ada Example <someone-else@example.com>")
    proc = _check(repo)
    assert proc.returncode == 1
    assert f"no 'Signed-off-by: {AUTHOR[0]} <{AUTHOR[1]}>'" in proc.stdout


def test_a_sign_off_with_another_name_fails(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty", "-m",
         f"renamed\n\nSigned-off-by: Someone Else <{AUTHOR[1]}>")
    assert _check(repo).returncode == 1


def _diverge(repo) -> str:
    """Give main and topic one signed-off commit each; return the base of the range."""
    repo("checkout", "-q", "-b", "topic")
    (repo.root / "topic.txt").write_text("topic\n")
    repo("add", "topic.txt")
    repo("commit", "-q", "-s", "-m", "on topic")
    repo("checkout", "-q", "main")
    (repo.root / "main.txt").write_text("main\n")
    repo("add", "main.txt")
    repo("commit", "-q", "-s", "-m", "on main")
    return repo("rev-parse", "HEAD~1")


def test_a_clean_unsigned_merge_commit_passes(repo):
    base = _diverge(repo)
    repo("merge", "-q", "--no-ff", "--no-edit", "topic")
    proc = _check(repo, base=base)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "3 commit(s) checked" in proc.stdout
    assert "clean merge" in proc.stdout


def test_an_unsigned_merge_with_a_change_of_its_own_fails(repo):
    base = _diverge(repo)
    repo("merge", "-q", "--no-ff", "--no-commit", "topic")
    (repo.root / "extra.txt").write_text("in neither parent\n")
    repo("add", "extra.txt")
    repo("commit", "-q", "--no-edit")
    proc = _check(repo, base=base)
    assert proc.returncode == 1
    assert "FAIL" in proc.stdout and "Merge branch" in proc.stdout


def test_an_unsigned_merge_resolving_a_conflict_fails(repo):
    (repo.root / "shared.txt").write_text("base\n")
    repo("add", "shared.txt")
    repo("commit", "-q", "-s", "-m", "shared")
    repo("checkout", "-q", "-b", "topic")
    (repo.root / "shared.txt").write_text("topic\n")
    repo("commit", "-q", "-s", "-am", "topic edit")
    repo("checkout", "-q", "main")
    (repo.root / "shared.txt").write_text("main\n")
    repo("commit", "-q", "-s", "-am", "main edit")
    base = repo("rev-parse", "HEAD~1")
    subprocess.run(["git", "merge", "-q", "--no-edit", "topic"], cwd=repo.root,
                   env=repo.env, capture_output=True)
    (repo.root / "shared.txt").write_text("resolved\n")
    repo("add", "shared.txt")
    repo("commit", "-q", "--no-edit")
    proc = _check(repo, base=base)
    assert proc.returncode == 1
    assert "FAIL" in proc.stdout and "Merge branch" in proc.stdout


DEPENDABOT = "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"


def test_a_dependabot_commit_passes(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty",
         "--author", DEPENDABOT,
         "-m", "build(deps): Bump example\n\nSigned-off-by: dependabot[bot] <support@github.com>")
    proc = _check(repo, pr_author_login="dependabot[bot]")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "bot" in proc.stdout


def test_a_bot_name_without_a_bot_address_still_needs_a_sign_off(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty", "--author", "dependabot[bot] <support@github.com>",
         "-m", "lookalike")
    assert _check(repo).returncode == 1


def test_another_bot_address_still_needs_a_sign_off(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty",
         "--author", "foo[bot] <foo[bot]@users.noreply.github.com>", "-m", "spoofed")
    assert _check(repo, pr_author_login="dependabot[bot]").returncode == 1


@pytest.mark.parametrize("pr_author_login", [None, "", "ada", "other-app[bot]"])
def test_the_dependabot_address_needs_a_sign_off_unless_dependabot_opened_the_pr(
        repo, pr_author_login):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty", "--author", DEPENDABOT, "-m", "spoofed")
    proc = _check(repo, pr_author_login=pr_author_login)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL" in proc.stdout and "spoofed" in proc.stdout


def test_the_dependabot_address_passes_when_dependabot_opened_the_pr(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty", "--author", DEPENDABOT, "-m", "bump")
    proc = _check(repo, pr_author_login="dependabot[bot]")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "(dependabot)" in proc.stdout


def test_a_signed_off_merge_commit_passes(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty", "-s", "-m", "signed")
    repo("checkout", "-q", "main")
    repo("commit", "-q", "--allow-empty", "-s", "-m", "on main")
    base = repo("rev-parse", "HEAD~1")
    repo("merge", "-q", "--no-ff", "--no-edit", "--signoff", "topic")
    proc = _check(repo, base=base)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_co_author_needs_no_sign_off_of_their_own(repo):
    repo("checkout", "-q", "-b", "topic")
    repo("commit", "-q", "--allow-empty", "-s", "-m",
         "paired\n\nCo-authored-by: Bea Example <bea@example.com>")
    proc = _check(repo)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_an_empty_range_passes(repo):
    proc = _check(repo, base="HEAD", head="HEAD")
    assert proc.returncode == 0
    assert "0 commit(s) checked" in proc.stdout


def test_the_script_is_executable():
    assert os.access(SCRIPT, os.X_OK)
