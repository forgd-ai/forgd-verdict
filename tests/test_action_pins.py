"""Every `uses:` in the repository's workflows, composite actions and
example workflows is a local path or an action pinned to a full commit SHA
with a `# vX.Y.Z` comment."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_workflows", REPO / "scripts" / "check_workflows.py")
check_workflows = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_workflows)

ROOTS = (".github", "examples/github", "examples/deployment-repo/.github")
FILES = sorted(
    p for root in ROOTS for p in (REPO / root).rglob("*")
    if p.suffix in (".yml", ".yaml") and p.is_file()
)

USES_LINE = re.compile(r"""^\s*(?:-\s+)?["']?uses["']?\s*:\s*(?P<ref>[^\s#]+)(?P<rest>.*)$""")
PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}")
COMMENT = re.compile(r"\s+#\s*v\d+(?:\.\d+)*\S*\s*")


def _yaml_uses(node) -> list[str]:
    found = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "uses" and isinstance(v, str):
                found.append(v)
            else:
                found.extend(_yaml_uses(v))
    elif isinstance(node, list):
        for v in node:
            found.extend(_yaml_uses(v))
    return found


def _line_uses(text: str) -> list[tuple[int, str, str]]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        m = USES_LINE.match(line)
        if m:
            out.append((n, m["ref"].strip("\"'"), m["rest"]))
    return out


def problems(text: str) -> list[str]:
    errs = []
    lines = _line_uses(text)
    parsed = _yaml_uses(yaml.load(text, Loader=check_workflows._Strict))
    # A `uses:` the line scan cannot see -- flow style, a quoted key it
    # does not expect -- would otherwise go unchecked.
    if sorted(r for _, r, _ in lines) != sorted(parsed):
        errs.append(f"line scan found {sorted(r for _, r, _ in lines)}, YAML has {sorted(parsed)}")
    for n, ref, rest in lines:
        if ref.startswith("./"):
            continue
        if not PINNED.fullmatch(ref):
            errs.append(f"line {n}: {ref} is not owner/repo[/path]@<40-hex sha>")
        elif not COMMENT.fullmatch(rest):
            errs.append(f"line {n}: {ref} has no trailing '# v...' comment")
    return errs


def test_files_are_found():
    names = {p.relative_to(REPO).as_posix() for p in FILES}
    assert ".github/workflows/ci.yml" in names
    assert ".github/actions/install-gitleaks/action.yml" in names
    assert "examples/github/deploy.yml" in names
    assert "examples/deployment-repo/.github/workflows/deploy.yml" in names


def _dependabot_reads(directories: list[str]) -> set[str]:
    """The workflow and action files Dependabot's github-actions updater
    reads: for `/`, the root action file and `.github/workflows/*`; for any
    other directory, the YAML files directly in it."""
    read = set()
    for d in directories:
        base = REPO / d.strip("/")
        if d == "/":
            read |= {f for f in ("action.yml", "action.yaml") if (REPO / f).is_file()}
            base = REPO / ".github" / "workflows"
        read |= {p.relative_to(REPO).as_posix() for p in base.glob("*")
                 if p.suffix in (".yml", ".yaml") and p.is_file()}
    return read


def _github_actions_directories() -> list[str]:
    config = yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    [entry] = [u for u in config["updates"] if u["package-ecosystem"] == "github-actions"]
    return entry["directories"]


def test_dependabot_reads_every_file_with_a_pin():
    """A pin Dependabot does not read stays behind when it bumps the same
    action elsewhere, and the setup-uv check below then fails its pull
    request."""
    pinned = {p.relative_to(REPO).as_posix() for p in FILES if _line_uses(p.read_text(encoding="utf-8"))}
    assert "examples/deployment-repo/.github/workflows/ci.yml" in pinned
    unread = pinned - _dependabot_reads(_github_actions_directories())
    assert not unread, sorted(unread)


def test_the_dependabot_reader_misses_a_directory_left_out():
    directories = [d for d in _github_actions_directories() if d != "/examples/github"]
    assert "examples/github/deploy.yml" not in _dependabot_reads(directories)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(REPO).as_posix())
def test_every_uses_is_pinned(path):
    assert problems(path.read_text(encoding="utf-8")) == []


GOOD = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1"


@pytest.mark.parametrize("text", [
    "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n",
    "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7.0.1  # v7.0.1\n",
    "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n",
    "jobs:\n  a:\n    steps:\n      - uses: docker://alpine:3.20  # v3.20\n",
    "jobs:\n  a:\n    steps:\n      - {uses: actions/checkout@v7}\n",
    "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n",
    "jobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@main\n",
])
def test_unpinned_references_are_refused(text):
    assert problems(text)


@pytest.mark.parametrize("text", [
    f"jobs:\n  a:\n    steps:\n      - uses: {GOOD}\n",
    "jobs:\n  a:\n    steps:\n      - uses: ./.github/actions/install-gitleaks\n",
    f"runs:\n  using: composite\n  steps:\n    - uses: {GOOD}\n",
    ("jobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@"
     + "3d3c42e5aac5ba805825da76410c181273ba90b1  # v1.2.3\n"),
])
def test_pinned_references_pass(text):
    assert problems(text) == []


def _steps_using(node, action: str) -> list[dict]:
    found = []
    if isinstance(node, dict):
        if str(node.get("uses", "")).split("@", 1)[0] == action:
            found.append(node)
        for v in node.values():
            found.extend(_steps_using(v, action))
    elif isinstance(node, list):
        for v in node:
            found.extend(_steps_using(v, action))
    return found


def test_every_setup_uv_is_the_same_pin_and_names_a_uv_version():
    steps = []
    for path in FILES:
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=check_workflows._Strict)
        for step in _steps_using(doc, "astral-sh/setup-uv"):
            steps.append((path.relative_to(REPO).as_posix(), step))
    assert steps
    shas = {step["uses"] for _, step in steps}
    assert len(shas) == 1, sorted(shas)
    unversioned = [(f, step.get("name") or step["uses"]) for f, step in steps
                   if not (step.get("with") or {}).get("version")]
    assert not unversioned, unversioned
    versions = {str(step["with"]["version"]) for _, step in steps}
    assert len(versions) == 1, sorted(versions)



def test_install_gitleaks_verifies_the_checksum_on_a_cache_hit_too():
    """The cache holds the downloaded tarball, so the checksum and the
    extraction run whether or not the cache hit."""
    action = yaml.safe_load((REPO / ".github" / "actions" / "install-gitleaks" / "action.yml").read_text())
    steps = action["runs"]["steps"]
    [cache] = [s for s in steps if s.get("uses", "").startswith("actions/cache@")]
    assert "/usr/local/bin" not in cache["with"]["path"], cache["with"]["path"]
    [check] = [s for s in steps if "sha256sum --check --strict" in s.get("run", "")]
    assert "cache-hit" not in check.get("if", ""), check.get("if")
    assert "tar -xzf" in check["run"]
    [download] = [s for s in steps if "curl " in s.get("run", "")]
    assert "--retry-all-errors" in download["run"]
