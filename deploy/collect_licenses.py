"""Copy the licence files of every installed Python distribution into OUT_DIR.

    python collect_licenses.py OUT_DIR [--supplement DIR]

Each distribution's files go to OUT_DIR/<name>-<version>/, and OUT_DIR/index.json
lists, per distribution: name, version, the License, License-Expression and
licence classifier metadata, and the files copied. forgd-verdict itself is
skipped; its LICENSE and NOTICE are at /app.

Licence files are found in the installed RECORD: anything under a
.dist-info/licenses/ directory, and any file named LICENSE*, LICENCE*,
COPYING*, NOTICE* or AUTHORS* wherever the distribution installed it.

A distribution that installed none takes its files from DIR/<name>/ in the
--supplement directory, and its index entry says so. One with neither fails
the run.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from importlib import metadata
from pathlib import Path

SELF = "forgd-verdict"
NAMES = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|AUTHORS)", re.IGNORECASE)


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _licence_files(dist: metadata.Distribution) -> list[Path]:
    found = []
    for entry in dist.files or []:
        parts = entry.parts
        in_licenses = any(p.endswith(".dist-info") for p in parts[:-1]) and "licenses" in parts
        if in_licenses or NAMES.match(parts[-1]):
            path = Path(entry.locate())
            if path.is_file():
                found.append(path)
    return found


def _supplied(root: Path | None, name: str) -> list[Path]:
    if root is None or not (root / name).is_dir():
        return []
    return sorted(p for p in (root / name).iterdir() if p.is_file())


def main(argv: list[str]) -> int:
    args = argv[1:]
    supplement = None
    if "--supplement" in args:
        i = args.index("--supplement")
        supplement = Path(args[i + 1])
        del args[i : i + 2]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    out = Path(args[0])

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    index, missing, seen = [], [], set()
    for dist in sorted(metadata.distributions(), key=lambda d: _canonical(d.metadata["Name"])):
        name = _canonical(dist.metadata["Name"])
        if name == SELF or name in seen:
            continue
        seen.add(name)
        dest = out / f"{name}-{dist.version}"
        copied = []
        sources = _licence_files(dist)
        supplied = not sources
        if supplied:
            sources = _supplied(supplement, name)
        for src in sources:
            target = dest / src.name
            n = 1
            while target.exists():
                n += 1
                target = dest / f"{src.name}.{n}"
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
            copied.append(target.name)
        meta = dist.metadata
        index.append({
            "name": name,
            "version": dist.version,
            "license": meta.get("License"),
            "license_expression": meta.get("License-Expression"),
            "classifiers": [c for c in meta.get_all("Classifier") or []
                            if c.startswith("License ::")],
            "files": copied,
            "supplied": supplied and bool(copied),
        })
        if not copied:
            missing.append(name)

    (out / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

    for entry in index:
        if entry["supplied"]:
            print(f"supplied: {entry['name']} installed no licence file", file=sys.stderr)
    for name in missing:
        print(f"MISSING: {name} installed no licence file and none is supplied",
              file=sys.stderr)
    print(f"{len(index)} distributions, {len(missing)} without a licence file", file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
