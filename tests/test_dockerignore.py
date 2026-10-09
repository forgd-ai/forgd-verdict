""".dockerignore keeps the secret- and state-bearing paths that .gitignore
names out of the build context, and none of them hides a path the
Dockerfile copies."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from dockerignore_match import DockerIgnore

REPO = Path(__file__).resolve().parents[1]
LINES = (REPO / ".dockerignore").read_text(encoding="utf-8").splitlines()
MATCHER = DockerIgnore(LINES)
DOCKERFILE = (REPO / "deploy" / "Dockerfile").read_text(encoding="utf-8")

REQUIRED = [
    "**/.env",
    "**/policy.local.yaml",
    "**/policy.local.json",
    "**/*.tfstate",
    "**/*.tfstate.*",
    "**/*.tfvars",
    "**/.terraform/",
    "**/*.jsonl.gz",
    "**/archive/",
    "**/timings.csv",
    "**/compliance-state.json",
    "**/.claude/",
    "**/.playwright-mcp/",
    "**/dist/",
    "**/build/",
    "**/*.tfvars.json",
    "**/.env.*",
    "**/gha-creds-*.json",
    "**/credentials",
    "**/credentials.json",
    "**/kubeconfig",
    "**/.kube/",
    "**/*.pem",
    "**/*.key",
    "findings/",
]


@pytest.mark.parametrize("pattern", REQUIRED)
def test_pattern_is_a_line(pattern):
    assert pattern in LINES


def _copy_sources() -> list[str]:
    sources = []
    for m in re.finditer(r"(?m)^\s*(?:COPY|ADD)\s+(.+)$", DOCKERFILE):
        args = [a for a in m.group(1).split() if not a.startswith("--")]
        if "--from=" in m.group(1):
            continue
        sources.extend(args[:-1])
    return sources


def _ignored(path: str) -> bool:
    return MATCHER.ignored(path)


def test_dockerfile_copies_something():
    assert "src" in _copy_sources()


@pytest.mark.parametrize("source", _copy_sources())
def test_copy_source_is_not_ignored(source):
    assert (REPO / source).exists(), source
    assert not _ignored(source), source
    if (REPO / source).is_dir():
        for f in (REPO / source).rglob("*"):
            rel = f.relative_to(REPO).as_posix()
            if f.is_file() and "__pycache__" not in rel:
                assert not _ignored(rel), rel
