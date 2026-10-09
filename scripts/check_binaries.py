#!/usr/bin/env python3
"""Every binary file git tracks is listed in tests/allowed-binaries.txt with
its sha256 and a reason.

A file is binary when it reads as neither UTF-8 nor UTF-16 text without
control characters. GitHub secret scanning reads binaries too, and a build
output can carry another tool's credential fixtures.

A finding is `path <reason>`: unlisted-binary, hash-mismatch, stale-entry,
or `<list>:<line> malformed`.

Usage: check_binaries.py            (run from the repository root)
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ALLOWLISTS = [
    REPO / "tests" / "allowed-binaries.txt",
]
ENTRY = re.compile(r"^(\S+)\s+([0-9a-f]{64})\s+#\s*\S")
CONTROL = re.compile(r"[\x00-\x08\x0e-\x1f\x7f]")


def decode(data: bytes) -> str | None:
    """The text `data` holds, or None when it is binary."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return _strict(data, "utf-16")
    if b"\0" not in data:
        return _strict(data, "utf-8-sig")
    if len(data) % 2:
        return None
    even, odd = data[0::2].count(0), data[1::2].count(0)
    if even and not odd and even * 2 >= len(data) // 2:
        return _strict(data, "utf-16-be")
    if odd and not even and odd * 2 >= len(data) // 2:
        return _strict(data, "utf-16-le")
    return None


def _strict(data: bytes, encoding: str) -> str | None:
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        return None
    return None if CONTROL.search(text) else text


def listed(paths: list[Path]) -> tuple[dict[str, str], list[str]]:
    """{path: sha256} from each list that exists, and malformed or repeated lines."""
    out: dict[str, str] = {}
    bad = []
    for path in paths:
        if not path.is_file():
            continue
        for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = ENTRY.match(line)
            if m is None or m.group(1) in out:
                bad.append(f"{path.name}:{n} malformed")
                continue
            out[m.group(1)] = m.group(2)
    return out, bad


def findings(root: Path, tracked: list[str], allowlists: list[Path]) -> list[str]:
    allowed, out = listed(allowlists)
    binaries = []
    for rel in tracked:
        f = root / rel
        if f.is_file() and not f.is_symlink() and decode(f.read_bytes()) is None:
            binaries.append(rel)
    for rel in binaries:
        if rel not in allowed:
            out.append(f"{rel} unlisted-binary")
        elif hashlib.sha256((root / rel).read_bytes()).hexdigest() != allowed[rel]:
            out.append(f"{rel} hash-mismatch")
    for rel in sorted(set(allowed) - set(binaries)):
        out.append(f"{rel} stale-entry")
    return out


def tracked(root: Path) -> list[str] | None:
    """The paths git tracks under `root`, or None when it is not a checkout."""
    proc = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                          capture_output=True, check=False)
    if proc.returncode != 0:
        return None
    return [p for p in proc.stdout.decode("utf-8").split("\0") if p]


def main() -> int:
    paths = tracked(REPO)
    if paths is None:
        print("check_binaries: not a git checkout", file=sys.stderr)
        return 2
    out = findings(REPO, paths, ALLOWLISTS)
    for line in out:
        print(line)
    return 1 if out else 0


if __name__ == "__main__":
    sys.exit(main())
