"""The layering gate, probed with imports it must catch.

Each test copies the package to a scratch directory, adds one import, and
runs `scripts/import_graph.py --check` against the copy. The exit status
and the message are the assertions; nothing here reads the script's
internals.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "import_graph.py"
PACKAGE = REPO / "src" / "forgd_verdict"


def check(root: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--check", str(root)],
        capture_output=True, text=True,
    )


def package_copy(tmp_path: pathlib.Path) -> pathlib.Path:
    dst = tmp_path / "forgd_verdict"
    shutil.copytree(PACKAGE, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def prepend(path: pathlib.Path, line: str) -> None:
    path.write_text(line + "\n" + path.read_text())


def test_the_shipped_tree_passes(tmp_path):
    r = check(package_copy(tmp_path))
    assert r.returncode == 0, r.stdout


def test_an_absolute_from_package_import_of_a_higher_layer_fails(tmp_path):
    """`from forgd_verdict import dashboard` names a layer-4 package from
    layer 0. The relative spelling, `from . import dashboard`, is caught;
    the absolute spelling must be too."""
    root = package_copy(tmp_path)
    prepend(root / "models.py", "from forgd_verdict import dashboard")
    r = check(root)
    assert r.returncode == 1, r.stdout
    assert "NEW upward dependency: models -> dashboard" in r.stdout


def test_an_import_of_a_module_that_does_not_exist_fails(tmp_path):
    """A target the script cannot resolve is not graded, so it must fail
    the check rather than be dropped."""
    root = package_copy(tmp_path)
    prepend(root / "dashboard" / "app.py", "from ..modelz import Finding")
    r = check(root)
    assert r.returncode == 1, r.stdout
    assert "could not read an import" in r.stdout
    assert "modelz" in r.stdout


def test_a_relative_from_package_import_of_a_higher_layer_fails(tmp_path):
    root = package_copy(tmp_path)
    prepend(root / "models.py", "from . import dashboard")
    r = check(root)
    assert r.returncode == 1, r.stdout
    assert "NEW upward dependency: models -> dashboard" in r.stdout


def test_a_plain_import_of_a_higher_layer_fails(tmp_path):
    root = package_copy(tmp_path)
    prepend(root / "models.py", "import forgd_verdict.dashboard.auth")
    r = check(root)
    assert r.returncode == 1, r.stdout
    assert "NEW upward dependency: models -> dashboard.auth" in r.stdout
