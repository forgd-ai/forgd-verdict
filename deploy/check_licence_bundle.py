"""Check an image's third-party licence bundle against what the image contains.

    python check_licence_bundle.py BUNDLE FREEZE GO_VERSION_M GITLEAKS_VERSION_M

BUNDLE is a copy of /usr/share/licenses/forgd-verdict/third-party taken out
of the image. FREEZE is `pip freeze --all` run in the image, GO_VERSION_M is
`go version -m` run on its gitleaksd, and GITLEAKS_VERSION_M is
`go version -m` run on its /usr/local/bin/gitleaks; all are produced
independently of the bundle. Exits non-zero, naming each gap, if:

- gitleaks/LICENSE, fonts/OFL-Inter.txt or fonts/OFL-RobotoMono.txt is
  missing or empty;
- a module gitleaksd was linked with, or the Go standard library, has no
  non-empty file under go/<module>@<version>/;
- a module the gitleaks CLI was linked with, or the Go standard library, has
  no non-empty file under go-gitleaks/<module>@<version>/;
- a distribution in FREEZE, other than forgd-verdict, has no python/index.json
  entry with the same version (any version, for a `name @ url` line), or its
  listed files are not all present.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _nonempty(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def go_modules(text: str) -> list[tuple[str, str]]:
    """(module, version) for each `dep`, after any `=>` replacement."""
    mods: list[tuple[str, str]] = []
    for line in text.splitlines():
        fields = line.split()
        if fields[:1] == ["dep"]:
            mods.append((fields[1], fields[2]))
        elif fields[:1] == ["=>"] and mods:
            mods[-1] = (fields[1], fields[2])
    return mods


def frozen(text: str) -> list[tuple[str, str | None]]:
    """(name, version) per line; version is None for a `name @ url` line."""
    out: list[tuple[str, str | None]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            out.append((_canonical(name), version))
        elif " @ " in line:
            out.append((_canonical(line.split(" @ ", 1)[0]), None))
        else:
            raise ValueError(f"not a pip freeze line: {line!r}")
    return out


def _go_problems(bundle: Path, subdir: str, go_version_m: str, binary: str) -> list[str]:
    found = []
    mods = go_modules(go_version_m)
    if not mods:
        found.append(f"go version -m listed no modules for {binary}")
    stdlib = list((bundle / subdir).glob("go-stdlib@*"))
    if not any(_nonempty(f) for d in stdlib for f in d.iterdir()):
        found.append(f"{subdir}/go-stdlib@*/ has no licence file")
    for mod, ver in mods:
        d = bundle / subdir / f"{mod}@{ver}"
        if not (d.is_dir() and any(_nonempty(f) for f in d.iterdir())):
            found.append(f"go module {mod} {ver} has no licence file in {subdir}/{mod}@{ver}/")
    return found


def problems(bundle: Path, freeze: str, go_version_m: str,
             gitleaks_version_m: str) -> list[str]:
    found = []
    for rel in ("gitleaks/LICENSE", "fonts/OFL-Inter.txt", "fonts/OFL-RobotoMono.txt"):
        if not _nonempty(bundle / rel):
            found.append(f"{rel} is missing or empty")

    found += _go_problems(bundle, "go", go_version_m, "gitleaksd")
    found += _go_problems(bundle, "go-gitleaks", gitleaks_version_m, "gitleaks")

    index_path = bundle / "python" / "index.json"
    index = {}
    if index_path.is_file():
        index = {e["name"]: e for e in json.loads(index_path.read_text(encoding="utf-8"))}
    else:
        found.append("python/index.json is missing")
    dists = [(n, v) for n, v in frozen(freeze) if n != "forgd-verdict"]
    if not dists:
        found.append("pip freeze listed no distributions")
    for name, version in dists:
        entry = index.get(name)
        if entry is None:
            found.append(f"python distribution {name} {version} has no index entry")
            continue
        version = version or entry["version"]
        if entry["version"] != version:
            found.append(f"python distribution {name} is {version} but indexed as "
                         f"{entry['version']}")
            continue
        d = bundle / "python" / f"{name}-{version}"
        if not entry["files"]:
            found.append(f"python distribution {name} {version} has no licence file")
        for f in entry["files"]:
            if not _nonempty(d / f):
                found.append(f"python/{name}-{version}/{f} is missing or empty")
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    bundle = Path(argv[1])
    freeze = Path(argv[2]).read_text(encoding="utf-8")
    go_version_m = Path(argv[3]).read_text(encoding="utf-8")
    gitleaks_version_m = Path(argv[4]).read_text(encoding="utf-8")
    found = problems(bundle, freeze, go_version_m, gitleaks_version_m)
    for p in found:
        print(f"::error::{p}")
    if not found:
        print(f"licence bundle covers {len(go_modules(go_version_m))} gitleaksd Go modules, "
              f"{len(go_modules(gitleaks_version_m))} gitleaks Go modules and "
              f"{len(frozen(freeze))} pip freeze lines")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
