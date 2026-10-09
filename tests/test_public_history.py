"""No file under tests/ names a commit of this repository's history.

The public repository starts from an export with none of this history, so a
test that reads a commit there can only skip, and the hash itself names
internal history in a public tree."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HEX = re.compile(r"\b[0-9a-f]{12,40}\b")


def _hex_literals() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in (REPO / "tests").rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        for value in HEX.findall(path.read_text(encoding="utf-8", errors="ignore")):
            found.setdefault(value, set()).add(str(path.relative_to(REPO)))
    return found


def test_no_hex_literal_under_tests_resolves_to_a_commit():
    found = _hex_literals()
    assert found, "the scan found no hex literals at all"
    values = sorted(found)
    batch = "".join(f"{value}^{{commit}}\n" for value in values)
    out = subprocess.run(["git", "cat-file", "--batch-check"], cwd=REPO, input=batch,
                         capture_output=True, text=True, check=True).stdout.splitlines()
    resolved = {value: sorted(found[value]) for value, line in zip(values, out, strict=True)
                if not line.endswith(" missing")}
    assert resolved == {}
