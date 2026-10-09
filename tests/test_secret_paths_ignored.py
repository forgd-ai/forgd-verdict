"""Secret- and state-bearing filenames are ignored by git and excluded from
the Docker build context, at the repository root and nested under a
Terraform example; `*.tfvars.example` stays tracked and in the context."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from dockerignore_match import DockerIgnore

REPO = Path(__file__).resolve().parents[1]
DOCKERIGNORE = DockerIgnore.read(REPO / ".dockerignore")

NAMES = [
    "terraform.tfvars.json",
    "prod.auto.tfvars.json",
    "x.tfvars",
    "terraform.tfstate",
    "terraform.tfstate.backup",
    ".env",
    ".env.local",
    "kubeconfig",
    ".kube/config",
    "key.pem",
    "tls.key",
    "credentials",
    "credentials.json",
    "gha-creds-abc.json",
]
KEPT = ["terraform.tfvars.example", "x.tfvars.example"]
DIRS = ["", "deploy/terraform/examples/aks/"]

SECRET_PATHS = [d + n for d in DIRS for n in NAMES]
KEPT_PATHS = [d + n for d in DIRS for n in KEPT]


def _git_ignored(path: str) -> bool:
    r = subprocess.run(["git", "check-ignore", "-q", "--no-index", path],
                       cwd=REPO, capture_output=True, text=True)
    assert r.returncode in (0, 1), r.stderr
    return r.returncode == 0


@pytest.mark.parametrize("path", SECRET_PATHS)
def test_git_ignores(path):
    assert _git_ignored(path)


@pytest.mark.parametrize("path", SECRET_PATHS)
def test_docker_context_excludes(path):
    assert DOCKERIGNORE.ignored(path)


@pytest.mark.parametrize("path", KEPT_PATHS)
def test_example_is_kept(path):
    assert not _git_ignored(path)
    assert not DOCKERIGNORE.ignored(path)


@pytest.mark.parametrize(("lines", "path", "expected"), [
    (["**/.env"], ".env", True),
    (["**/.env"], "a/b/.env", True),
    (["*.tfvars"], "a/x.tfvars", False),
    (["**/.kube/"], "a/.kube/config", True),
    (["**/*.tfvars", "!**/keep.tfvars"], "a/keep.tfvars", False),
    (["findings/"], "findings/x.json", True),
    (["/findings"], "findings/x.json", True),
    (["src/*.py"], "src/a/b.py", False),
    (["src/**"], "src/a/b.py", True),
])
def test_matcher_semantics(lines, path, expected):
    assert DockerIgnore(lines).ignored(path) is expected
