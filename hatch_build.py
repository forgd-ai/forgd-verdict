"""Hatchling metadata hook: the long description is README.md with every
relative link and image made absolute on the release tag.

A file link goes under `<Source>/blob/v<version>/`, a directory link under
`<Source>/tree/v<version>/` and an image under
`raw.githubusercontent.com/<repo>/v<version>/`, where `<Source>` is
`[project.urls] Source`. Links are `[text](target)` and `[label]: target`
outside code fences and inline code; an `#anchor` is kept, and a bare
`#anchor` points into README.md. README.md itself is only read.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

from hatchling.metadata.plugin.interface import MetadataHookInterface

README = "README.md"

FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+\1")
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]*)>?(?:\s+[\"'(][^)]*)?\)")
REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
GITHUB = re.compile(r"^https://github\.com/([^/\s]+/[^/\s]+?)/?$")


def absolute_readme(text: str, source: str, version: str, root: Path) -> str:
    """`text` with its relative link targets made absolute on tag v`version`
    of the GitHub repository `source`; `root` decides file from directory."""
    m = GITHUB.match(source)
    if not m:
        raise ValueError(f"[project.urls] Source is not a GitHub repository URL: {source}")
    repo, tag = m.group(1), f"v{version}"
    blob = f"https://github.com/{repo}/blob/{tag}/"
    tree = f"https://github.com/{repo}/tree/{tag}/"
    raw = f"https://raw.githubusercontent.com/{repo}/{tag}/"

    out, fenced = [], False
    for line in text.split("\n"):
        if FENCE.match(line):
            fenced = not fenced
            out.append(line)
            continue
        if fenced:
            out.append(line)
            continue
        blanked = INLINE_CODE.sub(lambda c: " " * len(c.group(0)), line)
        spans = [(s.start(1), s.end(1), s.group(0).startswith("!"))
                 for s in INLINE.finditer(blanked)]
        ref = REFDEF.match(blanked)
        if ref:
            spans.append((ref.start(1), ref.end(1), False))
        for start, end, image in sorted(spans, reverse=True):
            target = line[start:end]
            if not target or SCHEME.match(target) or target.startswith("//"):
                continue
            path, _, anchor = target.partition("#")
            resolved = posixpath.normpath(path).lstrip("/") if path else README
            if image:
                new = raw + resolved
            elif (root / resolved).is_dir():
                new = tree + resolved
            else:
                new = blob + resolved + (f"#{anchor}" if anchor else "")
            line = line[:start] + new + line[end:]
        out.append(line)
    return "\n".join(out)


class ReadmeLinksHook(MetadataHookInterface):
    def update(self, metadata: dict) -> None:
        root = Path(self.root)
        text = (root / README).read_text(encoding="utf-8")
        metadata["readme"] = {
            "content-type": "text/markdown",
            "text": absolute_readme(text, metadata["urls"]["Source"], metadata["version"], root),
        }
