"""The dev toolchain matches what CI resolves.

Not a test of the product. It is here because the alternative is discovering
the mismatch in someone's pull request: a local `ruff check` that passes
against a different version than the one gating the merge is a check that
reports on a tool nobody runs.

A venv has been found holding ruff 0.16.8 while the pin resolved 0.14.14,
two minor series apart, and the pin exists precisely because ruff adds rules
in minor releases.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _pinned_spec() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    for dep in data["project"]["optional-dependencies"]["dev"]:
        if dep.replace(" ", "").startswith("ruff"):
            return dep
    raise AssertionError("no ruff entry in the dev extra")


def _installed_version(exe: Path) -> tuple[int, ...]:
    out = subprocess.run([str(exe), "--version"], capture_output=True, text=True,
                         timeout=30).stdout
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    assert m, f"could not read a version out of {out!r}"
    return tuple(int(p) for p in m.groups())


def _bounds(spec: str) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """`ruff>=0.14,<0.15` -> ((0,14), (0,15)). Only the shape we actually use."""
    lo = re.search(r">=\s*(\d+)\.(\d+)", spec)
    hi = re.search(r"<\s*(\d+)\.(\d+)", spec)
    assert lo and hi, f"unexpected pin shape: {spec!r}"
    return (
        tuple(int(p) for p in lo.groups()),
        tuple(int(p) for p in hi.groups()),
    )


def test_the_installed_ruff_satisfies_the_pin():
    """A local lint that passes on a different ruff than CI runs is not the
    check that gates the merge.

    `uv run ruff --version` reports the venv's copy rather than resolving
    the lock, so the obvious way to check this gives the wrong answer --
    which is how the drift survived. Rebuild with `uv sync --extra dev`.
    """
    exe = ROOT / ".venv" / "bin" / "ruff"
    if not exe.exists():  # pragma: no cover - depends on the environment
        pytest.skip("no ruff in .venv; nothing to compare")

    spec = _pinned_spec()
    low, high = _bounds(spec)
    got = _installed_version(exe)

    assert low <= got[: len(low)] < high, (
        f".venv has ruff {'.'.join(map(str, got))} but pyproject pins {spec!r}. "
        "CI resolves the pin, so this lints with a different tool than the one "
        "gating the merge. Fix with: uv sync --extra dev"
    )
