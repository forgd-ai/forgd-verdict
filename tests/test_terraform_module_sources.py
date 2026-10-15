"""Each Terraform module stands alone, so a root outside this repository can
source it by git ref at a release tag:

    source = "git::https://github.com/forgd-ai/forgd-verdict.git//deploy/terraform/modules/<name>?ref=v<version>"

A module may name only registry modules, read only files inside its own
directory, and carry no symlinks. deploy/terraform/README.md shows that form
and lists every module.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TERRAFORM = ROOT / "deploy" / "terraform"
README = TERRAFORM / "README.md"
GIT_SOURCE = re.compile(
    r'git::https://github\.com/forgd-ai/forgd-verdict\.git//deploy/terraform/modules/([a-z0-9-]+)\?ref=v')

MODULES = sorted(d.name for d in (TERRAFORM / "modules").iterdir() if (d / "main.tf").is_file())


def _tf(module: str) -> list[tuple[Path, str]]:
    return [(p, p.read_text(encoding="utf-8")) for p in sorted((TERRAFORM / "modules" / module).glob("*.tf"))]


def _code(text: str) -> str:
    """The text with `#` and `//` comments and heredoc descriptions removed."""
    text = re.sub(r"<<-?(\w+)\n.*?\n\s*\1\n", "", text, flags=re.S)
    return "\n".join(re.sub(r"\s(#|//).*$", "", " " + line)[1:] for line in text.splitlines()
                     if not line.lstrip().startswith(("#", "//")))


def test_there_are_modules():
    assert len(MODULES) >= 10, MODULES


@pytest.mark.parametrize("module", MODULES)
def test_a_module_sources_no_local_module(module):
    for path, text in _tf(module):
        for source in re.findall(r'^\s*source\s*=\s*"([^"]+)"', _code(text), re.M):
            assert not source.startswith((".", "/")), f"{path.name}: {source}"


@pytest.mark.parametrize("module", MODULES)
def test_a_module_reads_files_only_inside_itself(module):
    here = TERRAFORM / "modules" / module
    for path, text in _tf(module):
        code = _code(text)
        assert not re.search(r"\bpath\.(root|cwd)\b", code), f"{path.name} reads path.root or path.cwd"
        for rel in re.findall(r"\$\{path\.module\}/([^\"}]+)", code):
            target = (here / rel).resolve()
            assert target.is_relative_to(here.resolve()), f"{path.name}: {rel}"
            assert target.exists(), f"{path.name}: {rel} does not exist"


@pytest.mark.parametrize("module", MODULES)
def test_a_module_holds_no_symlink(module):
    links = [p for p in (TERRAFORM / "modules" / module).rglob("*")
             if p.is_symlink() and ".terraform" not in p.parts]
    assert links == []


def test_the_readme_shows_the_git_source_and_lists_every_module():
    text = README.read_text(encoding="utf-8")
    shown = GIT_SOURCE.findall(text)
    assert shown and set(shown) <= set(MODULES), shown
    listed = set(re.findall(r"^modules/([a-z0-9-]+)/", text, re.M))
    assert listed == set(MODULES)


def test_the_checks_see_a_module_that_breaks_them():
    bad = '''module "x" {
  source = "../store-azure"
}
locals {
  p = file("${path.module}/../../policy.yaml")
}
'''
    code = _code(bad)
    assert re.findall(r'^\s*source\s*=\s*"([^"]+)"', code, re.M) == ["../store-azure"]
    assert re.findall(r"\$\{path\.module\}/([^\"}]+)", code) == ["../../policy.yaml"]
