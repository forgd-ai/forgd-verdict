""".github/dependabot.yml covers every directory with a manifest Dependabot
reads, so a new Terraform module or example cannot go without updates."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
CONFIG = yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
TERRAFORM = REPO / "deploy" / "terraform"


def _directories(update: dict) -> list[str]:
    return update.get("directories") or [update["directory"]]


def _updates(ecosystem: str) -> list[dict]:
    found = [u for u in CONFIG["updates"] if u["package-ecosystem"] == ecosystem]
    assert found, ecosystem
    return found


def _listed(ecosystem: str) -> set[str]:
    return {d for u in _updates(ecosystem) for d in _directories(u)}


def test_the_config_is_version_2():
    assert CONFIG["version"] == 2


@pytest.mark.parametrize("ecosystem, directories", [
    ("pip", {"/", "/packaging/forgd-verdict-hook"}),
    ("gomod", {"/sidecar/gitleaksd", "/deploy/gitleaks-cli"}),
    ("github-actions", {"/", "/.github/actions/install-gitleaks"}),
    ("docker", {"/deploy"}),
])
def test_each_ecosystem_lists_its_directories(ecosystem, directories):
    assert _listed(ecosystem) == directories


MANIFESTS = {"gomod": "go.mod", "pip": "pyproject.toml", "docker": "Dockerfile"}


def _tracked(name: str) -> set[str]:
    """The directory of every tracked file called `name`, outside tests/."""
    files = subprocess.run(["git", "ls-files", "-z"], cwd=REPO, check=True,
                           capture_output=True).stdout.decode().split("\0")
    found = {Path(f) for f in files if f and Path(f).name == name}
    return {"/" + p.parent.as_posix() if p.parent != Path(".") else "/"
            for p in found if p.parts[0] != "tests"}


@pytest.mark.parametrize("ecosystem", sorted(MANIFESTS))
def test_every_tracked_manifest_is_listed(ecosystem):
    on_disk = _tracked(MANIFESTS[ecosystem])
    assert on_disk, ecosystem
    assert on_disk <= _listed(ecosystem)


def test_every_listed_directory_exists():
    for update in CONFIG["updates"]:
        for d in _directories(update):
            assert (REPO / d.lstrip("/")).is_dir(), (update["package-ecosystem"], d)


def test_every_terraform_module_and_example_is_listed():
    on_disk = {f"/{p.relative_to(REPO).as_posix()}"
               for kind in ("modules", "examples")
               for p in sorted((TERRAFORM / kind).iterdir()) if p.is_dir()}
    assert len(on_disk) >= 13
    assert _listed("terraform") == on_disk


def test_every_composite_action_is_listed():
    actions = {f"/{p.relative_to(REPO).as_posix()}"
               for p in sorted((REPO / ".github" / "actions").iterdir()) if p.is_dir()}
    assert actions <= _listed("github-actions")


@pytest.mark.parametrize("update", CONFIG["updates"], ids=lambda u: u["package-ecosystem"])
def test_weekly_with_minor_and_patch_and_majors_grouped(update):
    assert update["schedule"]["interval"] == "weekly"
    kinds = sorted(sorted(g["update-types"]) for g in update["groups"].values())
    if update["package-ecosystem"] == "terraform":
        assert kinds == [["minor", "patch"]]
    else:
        assert kinds == [["major"], ["minor", "patch"]]


def test_the_hooks_exact_pin_on_the_core_is_not_bumped():
    (pip,) = _updates("pip")
    assert {"dependency-name": "forgd-verdict"} in pip["ignore"]


def test_the_python_base_image_moves_only_by_patch():
    (docker,) = _updates("docker")
    assert {"dependency-name": "python",
            "update-types": ["version-update:semver-major",
                             "version-update:semver-minor"]} in docker["ignore"]


def test_the_go_builder_image_moves_only_by_patch():
    (docker,) = _updates("docker")
    assert {"dependency-name": "golang",
            "update-types": ["version-update:semver-major",
                             "version-update:semver-minor"]} in docker["ignore"]


def test_terraform_providers_move_only_by_minor_and_patch():
    (tf,) = _updates("terraform")
    assert {"dependency-name": "*",
            "update-types": ["version-update:semver-major"]} in tf["ignore"]


def test_pip_opens_a_pull_request_only_outside_the_declared_range():
    (pip,) = _updates("pip")
    assert pip["versioning-strategy"] == "increase-if-necessary"


def _declared_majors() -> dict[str, set[int]]:
    """{provider source: the majors its `~> N.x` constraints name}."""
    block = re.compile(r'source\s*=\s*"([^"]+)"\s*version\s*=\s*"~>\s*(\d+)\.')
    out: dict[str, set[int]] = {}
    for path in TERRAFORM.rglob("*.tf"):
        if ".terraform" not in path.parts:
            for source, major in block.findall(path.read_text(encoding="utf-8")):
                out.setdefault(source, set()).add(int(major))
    return out


def test_each_terraform_provider_is_held_below_its_next_major():
    (tf,) = _updates("terraform")
    held = {i["dependency-name"]: i["versions"] for i in tf["ignore"] if "versions" in i}
    declared = _declared_majors()
    assert declared
    for source, majors in declared.items():
        assert len(majors) == 1, (source, majors)
        (major,) = majors
        assert held.get(source) == [f">= {major + 1}.0"], source
    assert set(held) == set(declared)
