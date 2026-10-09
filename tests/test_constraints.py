"""deploy/constraints/*.txt, the hashed pins the images install, agree with
pyproject.toml. Offline: CI's `scripts/compile_constraints.sh --check` is
what compares them with a fresh resolve."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

REPO = Path(__file__).resolve().parents[1]
DIR = REPO / "deploy" / "constraints"
PYPROJECT = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
HOOK_PYPROJECT = Path("packaging/forgd-verdict-hook/pyproject.toml")
HOOK = tomllib.loads((REPO / HOOK_PYPROJECT).read_text(encoding="utf-8"))
BASE_EXTRAS = ("server", "azure", "aws", "gcp", "dashboard", "connector")
SETS = {
    "build.txt": (PYPROJECT["build-system"]["requires"] + HOOK["build-system"]["requires"], ()),
    "base.txt": (PYPROJECT["project"]["dependencies"], BASE_EXTRAS),
    "ingest.txt": (PYPROJECT["project"]["dependencies"], (*BASE_EXTRAS, "ml-pii")),
    "hook.txt": (PYPROJECT["project"]["dependencies"], ()),
}
MODEL = ("en-core-web-lg @ https://github.com/explosion/spacy-models/releases/download/"
         "en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl#sha256=")


def _entries(name: str) -> list[tuple[str, list[str]]]:
    """(requirement line, its hashes) for each requirement in the file."""
    text = (DIR / name).read_text(encoding="utf-8").replace("\\\n", " ")
    out = []
    for line in text.splitlines():
        # As pip reads it: a comment starts at a `#` that begins the line or
        # follows whitespace, so a URL's #sha256= fragment is kept.
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line:
            continue
        req, *opts = re.split(r"\s+--hash=", line)
        out.append((req.strip(), [o.strip() for o in opts]))
    return out


def _pins(name: str) -> dict[str, str]:
    pins = {}
    for req, _ in _entries(name):
        if "==" in req:
            n, v = req.split("==", 1)
            pins[canonicalize_name(n)] = v
    return pins


def _required(deps: list[str], extras: tuple[str, ...]) -> list[Requirement]:
    reqs = [Requirement(d) for d in deps]
    for extra in extras:
        reqs += [Requirement(d) for d in PYPROJECT["project"]["optional-dependencies"][extra]]
    return reqs


@pytest.mark.parametrize("name", SETS)
def test_every_requirement_is_pinned_with_hashes(name):
    entries = _entries(name)
    assert entries
    for req, hashes in entries:
        assert "==" in req or req.startswith("en-core-web-lg @ "), req
        assert hashes and all(re.fullmatch(r"sha256:[0-9a-f]{64}", h) for h in hashes), req


@pytest.mark.parametrize("name", SETS)
def test_pyproject_requirements_are_pinned_and_satisfied(name):
    deps, extras = SETS[name]
    pins = _pins(name)
    for req in _required(deps, extras):
        n = canonicalize_name(req.name)
        assert n in pins, f"{name} has no pin for {req}"
        assert req.specifier.contains(pins[n], prereleases=True), f"{name}: {n}=={pins[n]} vs {req}"


def test_ingest_keeps_every_base_pin():
    base, ingest = _pins("base.txt"), _pins("ingest.txt")
    assert {n: ingest.get(n) for n in base} == base


def test_ingest_installs_the_model_by_hashed_url():
    (model,) = [(r, h) for r, h in _entries("ingest.txt") if r.startswith("en-core-web-lg")]
    req, hashes = model
    assert req.startswith(MODEL)
    assert hashes == [f"sha256:{req.rsplit('#sha256=', 1)[1]}"]
    assert (DIR / "ingest.in").read_text(encoding="utf-8").count(req) == 1


def test_the_model_matches_the_pinned_spacy():
    assert _pins("ingest.txt")["spacy"].startswith("3.8.")


def test_no_constraint_file_pins_forgd_verdict():
    for name in SETS:
        assert "forgd-verdict" not in _pins(name)


def test_the_dockerfile_installs_from_the_constraint_files():
    dockerfile = (REPO / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    for name in ("build.txt", "base.txt", "ingest.txt"):
        path = f"/tmp/{name}" if name == "build.txt" else f"/tmp/constraints/{name}"
        assert f"--require-hashes --no-deps -r {path}" in dockerfile, name
    assert "spacy download" not in dockerfile
    assert "pip install --no-cache-dir '." not in dockerfile


def test_the_compile_check_reads_both_projects_build_requirements(tmp_path):
    """The build set is fed to `uv pip compile` on stdin. A stub uv records
    that input and writes the committed files back, so --check passes and
    the test needs no index."""
    root = tmp_path / "repo"
    for rel in ("pyproject.toml", str(HOOK_PYPROJECT), "scripts/compile_constraints.sh",
                *(f"deploy/constraints/{f.name}" for f in DIR.iterdir())):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, root / rel)
    hook = root / HOOK_PYPROJECT
    hook.write_text(hook.read_text().replace('requires = ["hatchling"]',
                                             'requires = ["hatchling", "hook-only-backend"]'))
    bin_dir, stdin_log = tmp_path / "bin", tmp_path / "stdin.log"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f"""#!/bin/sh
out=
prev=
for a in "$@"; do
  [ "$prev" = -o ] && out=$a
  [ "$a" = - ] && cat >> {stdin_log}
  prev=$a
done
name=$(basename "$out"); name=${{name%%[.-]*}}
cp {DIR}/"$name".txt "$out"
""")
    (bin_dir / "uv").chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    r = subprocess.run([str(root / "scripts" / "compile_constraints.sh"), "--check"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    fed = stdin_log.read_text().split()
    assert "hook-only-backend" in fed
    assert fed.count("hatchling") == 2  # once per platform, deduplicated across projects


HOOK_COMPILE = ("--universal", "--python-version 3.11", "pyproject.toml -o \"$DIR/hook.txt\"")
# What a laptop installs with --no-build: a wheel of every pin for these
# targets, at the lowest and the highest CPython the hook supports.
LAPTOPS = ("aarch64-apple-darwin", "x86_64-pc-windows-msvc")
LAPTOP_PYTHONS = ("3.11", "3.13")


def _hook_compile() -> str:
    script = (REPO / "scripts" / "compile_constraints.sh").read_text(encoding="utf-8")
    [line] = [x for x in script.replace("\\\n", " ").splitlines()
              if "uv pip compile" in x and '-o "$DIR/hook.txt"' in x]
    return " ".join(line.split())


def test_hook_txt_is_resolved_from_pyproject_for_every_platform():
    """uv.lock is not committed (.gitignore), so nothing may be derived
    from it: hook.txt is resolved like the other constraint files."""
    line = _hook_compile()
    for part in HOOK_COMPILE:
        assert part in line, (part, line)
    assert "--generate-hashes" in line or "${COMMON_HOOK[@]}" in line, line
    assert "--extra" not in line and "--python-platform" not in line, line
    header = (DIR / "hook.txt").read_text(encoding="utf-8").splitlines()[:3]
    assert "#    scripts/compile_constraints.sh" in header, header


def test_the_check_resolves_hook_txt_wheel_only_for_each_laptop():
    script = (REPO / "scripts" / "compile_constraints.sh").read_text(encoding="utf-8")
    flat = " ".join(script.split())
    for laptop in LAPTOPS:
        assert laptop in script, laptop
    for py in LAPTOP_PYTHONS:
        assert py in flat, py
    assert "--only-binary :all:" in flat
    assert "x86_64-apple-darwin" not in script


def test_an_intel_mac_is_not_a_laptop_target_and_mdm_says_so():
    mdm = re.sub(r"\s+", " ", (REPO / "deploy" / "MDM.md").read_text(encoding="utf-8"))
    assert "no wheel for Intel Macs" in mdm
    assert not any("x86_64-apple" in laptop for laptop in LAPTOPS)


def test_nothing_reads_the_uncommitted_lock():
    """uv.lock is ignored, so a test, script or workflow that reads it works
    on one machine and fails in CI and in a fork."""
    ignored = subprocess.run(["git", "check-ignore", "-q", "uv.lock"], cwd=REPO).returncode == 0
    assert ignored
    readers = []
    for path in [*(REPO / "tests").glob("*.py"), *(REPO / "scripts").glob("*.sh"),
                 *(REPO / ".github" / "workflows").glob("*.yml")]:
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r'/\s*"uv\.lock"|uv export', text):
            readers.append(str(path.relative_to(REPO)))
    assert not readers, readers
