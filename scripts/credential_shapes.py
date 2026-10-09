#!/usr/bin/env python3
"""No credential shape that GitHub secret scanning reports without a
provider pattern.

gitleaks knows provider tokens. GitHub also reports shapes that belong to no
provider, and it reads each line as written: a value split across string
literals is not one match. Each line of each text file is searched for

  private-key      a PEM private-key header, `-----BEGIN ... PRIVATE KEY-----`
  http-basic       `Basic ` and at least 8 base64 characters
  http-bearer      `Bearer ` and at least 16 token characters, other than
                   an auth-param name followed by `="` (a challenge)
  connection-uri   a database or broker URI with a password before `@`

There is no allowlist. A fixture that needs one of these shapes builds it
from pieces, as tests/test_detectors.py does.

A finding is `path:line <rule>`. The match is not printed.

Usage: credential_shapes.py [<file> ...]
With no files, every file git tracks, from the repository root.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from check_binaries import REPO, decode, tracked

RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("http-basic", re.compile(r"\bBasic [A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])")),
    ("http-bearer", re.compile(r"\bBearer ([A-Za-z0-9._~+/-]{16,})(=*)")),
    ("connection-uri", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|sqlserver)"
        r"://[^\s:/@\"'`]+:[^\s/@\"'`]+@")),
)
AUTH_PARAM = re.compile(r"[A-Za-z_-]+")


def hits(line: str) -> list[str]:
    out = []
    for name, pattern in RULES:
        for m in pattern.finditer(line):
            if name == "http-bearer" and m.group(2) == "=" and line[m.end():m.end() + 1] == '"' \
                    and AUTH_PARAM.fullmatch(m.group(1)):
                continue
            out.append(name)
            break
    return out


def findings(root: Path, paths: list[str]) -> list[str]:
    out = []
    for rel in paths:
        f = root / rel
        if not f.is_file() or f.is_symlink():
            continue
        text = decode(f.read_bytes())
        if text is None:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            out.extend(f"{rel}:{n} {rule}" for rule in hits(line))
    return out


def main(argv: list[str]) -> int:
    if argv:
        root, paths = Path.cwd(), argv
    else:
        root, paths = REPO, tracked(REPO)
        if paths is None:
            print("credential_shapes: not a git checkout", file=sys.stderr)
            return 2
    out = findings(root, paths)
    for line in out:
        print(line)
    return 1 if out else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
