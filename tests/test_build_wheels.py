"""`scripts/build_wheels.sh`, run against a copy of the tree.

The script builds forgd-verdict and forgd-verdict-hook into one directory
and must refuse a pair that cannot install together. The copy is what lets
a test tamper with the hook's pin without touching the real tree.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HOOK_PYPROJECT = Path("packaging/forgd-verdict-hook/pyproject.toml")
BUILD_TXT = Path("deploy/constraints/build.txt")


def tree_copy(tmp_path: Path) -> Path:
    """The files a wheel build reads, and nothing else."""
    dst = tmp_path / "repo"
    for rel in ("pyproject.toml", "hatch_build.py", "README.md", "LICENSE", "NOTICE",
                "scripts/build_wheels.sh", str(HOOK_PYPROJECT), str(BUILD_TXT)):
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, dst / rel)
    shutil.copytree(REPO / "src", dst / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def build(root: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(root / "scripts" / "build_wheels.sh"), str(root / "dist")],
        capture_output=True, text=True, env=env,
    )


def logged_uv(tmp_path: Path) -> tuple[dict, Path]:
    """An environment whose `uv` records each call's arguments, one call per
    line, before running the real uv."""
    bin_dir, log = tmp_path / "bin", tmp_path / "uv.log"
    bin_dir.mkdir()
    shim = bin_dir / "uv"
    shim.write_text(f'#!/bin/sh\necho "$*" >> {log}\nexec {shutil.which("uv")} "$@"\n')
    shim.chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}, log


def build_pins() -> dict[str, str]:
    return dict(re.findall(r"^([A-Za-z0-9][\w.-]*)==(\S+)", (REPO / BUILD_TXT).read_text(),
                           re.MULTILINE))


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_the_two_wheels_build_and_are_named(tmp_path):
    r = build(tree_copy(tmp_path))
    assert r.returncode == 0, r.stderr
    names = [Path(line).name for line in r.stdout.splitlines()]
    assert len(names) == 2
    assert names[0].startswith("forgd_verdict-") and names[1].startswith("forgd_verdict_hook-")


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_a_hook_wheel_whose_pin_names_another_core_is_refused(tmp_path):
    """Both wheels can carry the same version while the pin inside the hook
    names an older core. The documented install would then fail to
    resolve, so the script has to fail first."""
    root = tree_copy(tmp_path)
    p = root / HOOK_PYPROJECT
    p.write_text(re.sub(r'"forgd-verdict==[^"]+"', '"forgd-verdict==0.0.1"', p.read_text()))
    r = build(root)
    assert r.returncode != 0
    assert "forgd-verdict==" in r.stderr


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_both_wheels_carry_the_root_license_and_notice(tmp_path):
    root = tree_copy(tmp_path)
    r = build(root)
    assert r.returncode == 0, r.stderr
    for line in r.stdout.splitlines():
        whl = Path(line)
        dist_info = "-".join(whl.name.split("-")[:2]) + ".dist-info"
        with zipfile.ZipFile(whl) as z:
            for name in ("LICENSE", "NOTICE"):
                assert z.read(f"{dist_info}/licenses/{name}") == (REPO / name).read_bytes()
    # The copies made for the hook's build are gone.
    hook_dir = root / HOOK_PYPROJECT.parent
    assert sorted(p.name for p in hook_dir.iterdir()) == ["pyproject.toml"]


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_the_copies_are_removed_when_the_hook_build_fails(tmp_path):
    root = tree_copy(tmp_path)
    p = root / HOOK_PYPROJECT
    p.write_text(p.read_text().replace('build-backend = "hatchling.build"',
                                       'build-backend = "no_such_backend"'))
    r = build(root)
    assert r.returncode != 0
    hook_dir = root / HOOK_PYPROJECT.parent
    assert sorted(p.name for p in hook_dir.iterdir()) == ["pyproject.toml"]


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_a_wheel_without_notice_is_refused(tmp_path):
    root = tree_copy(tmp_path)
    pyproject = root / "pyproject.toml"
    text, n = re.subn(r"^license-files = \[.*?\]\n", 'license-files = ["LICENSE"]\n',
                      pyproject.read_text(), count=1, flags=re.MULTILINE | re.DOTALL)
    assert n == 1
    pyproject.write_text(text)
    r = build(root)
    assert r.returncode != 0
    assert "licenses/NOTICE is missing or differs" in r.stderr


FONTS = "src/forgd_verdict/dashboard/assets/fonts"


def wheel_metadata(whl: Path) -> tuple[str, list[str]]:
    with zipfile.ZipFile(whl) as z:
        (metadata,) = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")]
        return z.read(metadata).decode().split("\n\n", 1)[0], z.namelist()


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_the_core_wheel_declares_the_font_licence_and_carries_its_text(tmp_path):
    r = build(tree_copy(tmp_path))
    assert r.returncode == 0, r.stderr
    core, hook = (Path(line) for line in r.stdout.splitlines())

    headers, names = wheel_metadata(core)
    assert "License-Expression: Apache-2.0 AND OFL-1.1" in headers.splitlines()
    assert not re.search(r"^(License: |Classifier: License ::)", headers, re.MULTILINE)
    dist_info = "-".join(core.name.split("-")[:2]) + ".dist-info"
    fonts = sorted(p.name for p in (REPO / FONTS).glob("OFL-*.txt"))
    assert fonts
    for name in fonts:
        assert f"License-File: {FONTS}/{name}" in headers.splitlines()
        with zipfile.ZipFile(core) as z:
            assert z.read(f"{dist_info}/licenses/{FONTS}/{name}") == \
                (REPO / FONTS / name).read_bytes()

    # The hook wheel ships no fonts, so it stays Apache-2.0 alone.
    headers, names = wheel_metadata(hook)
    assert not [n for n in names if n.endswith((".woff2", ".woff", ".ttf", ".otf"))]
    assert "License: Apache-2.0" in headers.splitlines()


def core_description(whl: Path) -> str:
    with zipfile.ZipFile(whl) as z:
        (metadata,) = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")]
        return z.read(metadata).decode().split("\n\n", 1)[1]


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_the_core_long_description_pins_the_readme_links_to_the_tag(tmp_path):
    root = tree_copy(tmp_path)
    before = (root / "README.md").read_bytes()
    r = build(root)
    assert r.returncode == 0, r.stderr
    assert (root / "README.md").read_bytes() == before
    assert "](docs/" in before.decode()
    version = Path(r.stdout.splitlines()[0]).name.split("-")[1]
    description = core_description(Path(r.stdout.splitlines()[0]))
    assert f"](https://github.com/forgd-ai/forgd-verdict/blob/v{version}/docs/" in description
    assert "](docs/" not in description
    assert re.search(rf"/blob/v{re.escape(version)}/[^)#\s]+\.md#[\w-]+\)", description)


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_a_core_wheel_whose_readme_links_stay_relative_is_refused(tmp_path):
    root = tree_copy(tmp_path)
    pyproject = root / "pyproject.toml"
    pyproject.write_text(pyproject.read_text()
                         .replace('dynamic = ["readme"]\n', 'readme = "README.md"\n', 1)
                         .replace("[tool.hatch.metadata.hooks.custom]\n", "", 1))
    r = build(root)
    assert r.returncode != 0
    assert "long description has no link pinned to /blob/v" in r.stderr


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_both_wheels_are_built_in_place_from_the_hashed_build_constraints(tmp_path):
    root = tree_copy(tmp_path)
    env, log = logged_uv(tmp_path)
    r = build(root, env)
    assert r.returncode == 0, r.stderr
    calls = log.read_text().splitlines()
    installs = [c.split() for c in calls if c.startswith("pip install ")]
    assert len(installs) == 1
    (install,) = installs
    assert {"--require-hashes", "--no-deps"} <= set(install)
    assert install[install.index("-r") + 1] == str(root / BUILD_TXT)
    py = install[install.index("--python") + 1]
    builds = [c.split() for c in calls if c.startswith("build ")]
    assert [b[-1] for b in builds] == [str(root), str(root / HOOK_PYPROJECT.parent)]
    for b in builds:
        assert "--no-build-isolation" in b
        assert b[b.index("--python") + 1] == py


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_the_wheels_are_generated_by_the_pinned_hatchling(tmp_path):
    r = build(tree_copy(tmp_path))
    assert r.returncode == 0, r.stderr
    pinned = build_pins()["hatchling"]
    for line in r.stdout.splitlines():
        with zipfile.ZipFile(line) as z:
            (wheel,) = [n for n in z.namelist() if n.endswith(".dist-info/WHEEL")]
            assert f"Generator: hatchling {pinned}\n" in z.read(wheel).decode()


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_a_build_constraint_whose_hash_does_not_match_is_refused(tmp_path):
    root = tree_copy(tmp_path)
    p = root / BUILD_TXT
    text = p.read_text()
    p.write_text(re.sub(r"(hatchling==\S+ \\\n\s+--hash=sha256:)[0-9a-f]{64}( \\\n\s+--hash=sha256:)[0-9a-f]{64}",
                        r"\g<1>" + "0" * 64 + r"\g<2>" + "0" * 64, text, count=1))
    assert p.read_text() != text
    r = build(root)
    assert r.returncode != 0
    assert not list((root / "dist").glob("*.whl"))


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_a_build_environment_missing_a_dependency_is_refused(tmp_path):
    root = tree_copy(tmp_path)
    p = root / BUILD_TXT
    text = p.read_text()
    p.write_text(re.sub(r"^trove-classifiers==.*?(?=^\S|\Z)", "", text, flags=re.M | re.S))
    assert not re.search(r"^trove-classifiers==", p.read_text(), re.M)
    r = build(root)
    assert r.returncode != 0
    assert "trove-classifiers" in r.stderr
    assert not list((root / "dist").glob("*.whl"))


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_a_build_requirement_the_pins_do_not_satisfy_is_refused(tmp_path):
    root = tree_copy(tmp_path)
    p = root / HOOK_PYPROJECT
    p.write_text(p.read_text().replace('requires = ["hatchling"]',
                                       'requires = ["hatchling<1.30"]'))
    r = build(root)
    assert r.returncode != 0
    assert "build requirement hatchling<1.30 is not satisfied by build.txt" in r.stderr


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_the_notice_says_which_wheel_includes_the_fonts(tmp_path):
    """One NOTICE ships in both wheels, so its fonts claim has to name the
    wheel that holds them and exclude the one that does not."""
    r = build(tree_copy(tmp_path))
    assert r.returncode == 0, r.stderr
    core, hook = (zipfile.ZipFile(line) for line in r.stdout.splitlines())
    fonts = "forgd_verdict/dashboard/assets/fonts/"
    assert any(n.startswith(fonts) for n in core.namelist())
    assert not any("fonts/" in n for n in hook.namelist())
    notice = " ".join((REPO / "NOTICE").read_text().split())
    assert "The forgd-verdict wheel, and so both container images, includes these fonts" in notice
    assert "The forgd-verdict-hook wheel and the Helm chart carry this NOTICE but include " \
           "neither the fonts" in notice


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_the_core_wheel_carries_the_deployment_verifier(tmp_path):
    """`forgd-verdict verify-deployment` runs the copy inside the wheel, so the
    verifier a deployment runs comes from the release it rolled."""
    r = build(tree_copy(tmp_path))
    assert r.returncode == 0, r.stderr
    core, hook = (zipfile.ZipFile(line) for line in r.stdout.splitlines())
    name = "forgd_verdict/verify_deployment.sh"
    assert core.read(name) == (REPO / "src" / name).read_bytes()
    assert name not in hook.namelist()
