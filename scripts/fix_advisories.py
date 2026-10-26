#!/usr/bin/env python3
"""Move the pins in deploy/constraints/*.txt that an advisory names.

Audits each constraints file with the pip-audit CI runs. For every package
an advisory names with a fixed version, drops that package's pin from every
file that pins it and runs scripts/compile_constraints.sh, which resolves
the dropped pins again and keeps every other pin as it is. Then audits the
files again.

Usage: scripts/fix_advisories.py --report <file.md>

Writes a Markdown report to <file.md>, and when GITHUB_OUTPUT is set,
`changed` (true when a file was rewritten) and `unfixed` (true when an
advisory remains after the fix, such as one with no fixed release).
Exits 0 either way, and 2 when an audit cannot run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSTRAINTS = ROOT / "deploy" / "constraints"
FILES = ("build", "base", "hook", "ingest")
PIP_AUDIT = "pip-audit==2.10.1"


@dataclass(frozen=True)
class Finding:
    file: str
    package: str
    version: str
    advisory: str
    fixed_in: tuple[str, ...]


def normalize(name: str) -> str:
    """PEP 503: the name uv writes into the files."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _pin_block(package: str) -> re.Pattern[str]:
    # A pin is `name==version \`, or `name==version ; <marker> \` in
    # hook.txt's universal resolution, and its indented hash and `# via`
    # lines.
    name = re.escape(normalize(package))
    return re.compile(rf"^{name}==([^\s;]+)(?: ;[^\\\n]*)? \\\n(?:    .*\n)*", re.M)


def pinned(text: str, package: str) -> str | None:
    m = _pin_block(package).search(text)
    return m.group(1) if m else None


def drop_pin(text: str, package: str) -> str:
    return _pin_block(package).sub("", text, count=1)


def audit(path: Path) -> list[Finding]:
    """pip-audit's findings for one file. pip-audit exits 1 when it finds
    something, so the exit code is read from the report, not the process."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "audit.json"
        run = subprocess.run(
            ["uvx", PIP_AUDIT, "-r", str(path), "--require-hashes", "--disable-pip",
             "-f", "json", "-o", str(report)],
            capture_output=True, text=True, check=False)
        if not report.is_file():
            raise RuntimeError(f"pip-audit wrote no report for {path.name}: {run.stderr.strip()}")
        deps = json.loads(report.read_text(encoding="utf-8"))["dependencies"]
    return [Finding(path.stem, normalize(d["name"]), d["version"], v["id"],
                    tuple(v.get("fix_versions") or ()))
            for d in deps for v in d.get("vulns") or ()]


def audit_all(files: dict[str, Path]) -> list[Finding]:
    return [f for path in files.values() for f in audit(path)]


Moved = dict[str, dict[str, tuple[str, str]]]

# Package names, versions and advisory ids come from PyPI and the advisory
# feeds, and go into the issue and the commit message. Anything outside
# these characters is shown as "?", so a field cannot break a table row,
# add a link or a mention, or end the message early with a trailer.
_SAFE = re.compile(r"[^A-Za-z0-9._+:-]")


def cell(value: str) -> str:
    return _SAFE.sub("?", value)[:80] or "?"


def report(before: list[Finding], after: list[Finding], moved: Moved) -> str:
    lines = ["## Pins moved for advisories", ""]
    if moved:
        lines += ["| package | file | from | to | advisories |", "|---|---|---|---|---|"]
        for package in sorted(moved):
            ids = ", ".join(sorted({cell(f.advisory) for f in before if f.package == package}))
            for file, (old, new) in sorted(moved[package].items()):
                lines.append(f"| {cell(package)} | {file}.txt | {cell(old)} | {cell(new)} "
                             f"| {ids} |")
    else:
        lines.append("None.")
    if after:
        lines += ["", "## Advisories still open", "",
                  "| package | file | version | advisory | fixed in |", "|---|---|---|---|---|"]
        for f in sorted(after, key=lambda f: (f.package, f.file, f.advisory)):
            fixed = ", ".join(cell(v) for v in f.fixed_in) or "no fixed release"
            lines.append(f"| {cell(f.package)} | {f.file}.txt | {cell(f.version)} | "
                         f"{cell(f.advisory)} | {fixed} |")
    return "\n".join(lines) + "\n"


def fix(files: dict[str, Path], compile_constraints) -> tuple[list[Finding], list[Finding], dict]:
    """Drop every flagged package with a fixed release from every file that
    pins it, re-resolve, and audit again. Returns the findings before and
    after, and package -> file -> (old, new) for each pin that moved."""
    before = audit_all(files)
    flagged = sorted({f.package for f in before if f.fixed_in})
    if not flagged:
        return before, before, {}
    texts = {name: path.read_text(encoding="utf-8") for name, path in files.items()}
    old = {p: {n: v for n, t in texts.items() if (v := pinned(t, p))} for p in flagged}
    for name, path in files.items():
        text = texts[name]
        for package in flagged:
            text = drop_pin(text, package)
        path.write_text(text, encoding="utf-8")
    compile_constraints()
    moved: dict[str, dict[str, tuple[str, str]]] = {}
    for package in flagged:
        for name, version in old[package].items():
            new = pinned(files[name].read_text(encoding="utf-8"), package)
            if new != version:
                moved.setdefault(package, {})[name] = (version, new or "(dropped)")
    return before, audit_all(files), moved


def _compile() -> None:
    subprocess.run([str(ROOT / "scripts" / "compile_constraints.sh")], check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    files = {name: CONSTRAINTS / f"{name}.txt" for name in FILES}
    originals = {name: path.read_text(encoding="utf-8") for name, path in files.items()}
    try:
        before, after, moved = fix(files, _compile)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        for name, path in files.items():
            path.write_text(originals[name], encoding="utf-8")
        print(f"fix_advisories: {exc}", file=sys.stderr)
        return 2
    args.report.write_text(report(before, after, moved), encoding="utf-8")
    changed = any(path.read_text(encoding="utf-8") != originals[name]
                  for name, path in files.items())
    if out := os.environ.get("GITHUB_OUTPUT"):
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"changed={'true' if changed else 'false'}\n")
            fh.write(f"unfixed={'true' if after else 'false'}\n")
    print(args.report.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
