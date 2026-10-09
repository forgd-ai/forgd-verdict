"""A .dockerignore matcher with the semantics of moby/patternmatcher, which
the Docker CLI and BuildKit use to filter the build context.

Patterns are cleaned and anchored at the context root. `*` and `?` stop at
`/`; `**` matches any number of path components, including none. A path is
excluded when a pattern matches it or any of its parent directories, and the
last matching pattern wins, so a later `!pattern` re-includes."""

from __future__ import annotations

import posixpath
import re
from pathlib import Path


def _clean(pattern: str) -> str:
    pattern = posixpath.normpath(pattern)
    if len(pattern) > 1 and pattern.startswith("/"):
        pattern = pattern[1:]
    return pattern


def _regex(pattern: str) -> re.Pattern[str]:
    out = "^"
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                i += 1
                if i + 1 < n and pattern[i + 1] == "/":
                    i += 1
                out += ".*" if i + 1 >= n else "(.*/)?"
            else:
                out += "[^/]*"
        elif ch == "?":
            out += "[^/]"
        elif ch == "\\" and i + 1 < n:
            i += 1
            out += re.escape(pattern[i])
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end == -1:
                out += re.escape(ch)
            else:
                body = pattern[i + 1:end]
                if body.startswith("^"):
                    body = "^" + body[1:]
                out += "[" + body + "]"
                i = end
        else:
            out += re.escape(ch)
        i += 1
    return re.compile(out + "$")


class DockerIgnore:
    def __init__(self, lines: list[str]):
        self.patterns: list[tuple[bool, re.Pattern[str]]] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            exclusion = line.startswith("!") and len(line) > 1
            if exclusion:
                line = line[1:].strip()
            self.patterns.append((exclusion, _regex(_clean(line))))

    @classmethod
    def read(cls, path: Path) -> DockerIgnore:
        return cls(path.read_text(encoding="utf-8").splitlines())

    def ignored(self, path: str) -> bool:
        path = _clean(path)
        parts = path.split("/")
        parents = ["/".join(parts[:i + 1]) for i in range(len(parts) - 1)]
        matched = False
        for exclusion, rx in self.patterns:
            if exclusion != matched:
                continue
            if rx.match(path) or any(rx.match(p) for p in parents):
                matched = not exclusion
        return matched
