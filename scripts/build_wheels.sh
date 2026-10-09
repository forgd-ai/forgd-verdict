#!/usr/bin/env bash
# Build the two wheels one release produces: forgd-verdict (the package) and
# forgd-verdict-hook (metadata and a console script, pinned exactly to it).
#
# Nothing here publishes. The wheels land in dist/ for a local or private
# install, where both files are named so the pin resolves against the
# sibling wheel and never against an index:
#
#   uv pip install dist/forgd_verdict-*.whl dist/forgd_verdict_hook-*.whl
#
# Usage: build_wheels.sh [out-dir]     default out-dir: dist
#
# Both wheels are built without build isolation in one throwaway venv that
# holds only deploy/constraints/build.txt, installed with --require-hashes,
# so nothing in the build environment is resolved at build time.
#
# Exits non-zero if the build environment cannot be installed from
# build.txt, is inconsistent, or does not satisfy either project's
# [build-system] requires; if either build fails; if the two wheels disagree
# on version; if the hook's pin names a core other than the one built beside
# it; if either wheel lacks the root LICENSE or NOTICE; or if the core
# wheel's long description has no link pinned to /blob/v<version>/ or keeps
# a relative `](docs/` link.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist}"
HOOK="$ROOT/packaging/forgd-verdict-hook"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

# Older wheels would make the install glob in the header ambiguous.
rm -f "$OUT"/forgd_verdict-*.whl "$OUT"/forgd_verdict_hook-*.whl

# The hook's project directory has no LICENSE or NOTICE of its own. The
# root files are copied in for its build, where hatchling's default
# license-file globs pick them up, and removed on exit.
benv=$(mktemp -d)
trap 'rm -rf "$benv"; rm -f "$HOOK/LICENSE" "$HOOK/NOTICE"' EXIT

uv venv --quiet --no-config --python 3.13.11 "$benv"
py="$benv/bin/python"
uv pip install --quiet --no-config --python "$py" --require-hashes --no-deps \
  --only-binary :all: -r "$ROOT/deploy/constraints/build.txt"
uv pip check --no-config --python "$py"
"$py" - "$ROOT/pyproject.toml" "$HOOK/pyproject.toml" <<'PY'
import sys, tomllib
from importlib.metadata import PackageNotFoundError, version
from packaging.requirements import Requirement

bad = []
for path in sys.argv[1:]:
    for r in tomllib.load(open(path, "rb"))["build-system"]["requires"]:
        req = Requirement(r)
        try:
            v = version(req.name)
        except PackageNotFoundError:
            v = None
        if v is None or not req.specifier.contains(v, prereleases=True):
            bad.append(f"{path}: build requirement {r} is not satisfied by build.txt"
                       f" (installed: {v or 'none'})")
if bad:
    sys.exit("\n".join(bad))
PY

uv build --wheel --quiet --no-config --no-build-isolation --python "$py" --out-dir "$OUT" "$ROOT"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$HOOK/"
uv build --wheel --quiet --no-config --no-build-isolation --python "$py" --out-dir "$OUT" "$HOOK"

core=$(ls -t "$OUT"/forgd_verdict-*.whl | head -1)
hook=$(ls -t "$OUT"/forgd_verdict_hook-*.whl | head -1)

version() { basename "$1" | cut -d- -f2; }
if [ "$(version "$core")" != "$(version "$hook")" ]; then
  echo "version mismatch: $(basename "$core") vs $(basename "$hook")" >&2
  exit 1
fi

# The pin inside the hook wheel must name the core wheel beside it.
pin=$(unzip -p "$hook" '*/METADATA' | sed -n 's/^Requires-Dist: forgd-verdict==\(.*\)$/\1/p')
if [ "$pin" != "$(version "$core")" ]; then
  echo "pin mismatch: $(basename "$hook") requires forgd-verdict==${pin:-<none>}," \
       "but the core wheel is $(version "$core")" >&2
  exit 1
fi

# Each wheel carries the root LICENSE and NOTICE, byte for byte.
for whl in "$core" "$hook"; do
  dist_info="$(basename "$whl" | cut -d- -f1-2).dist-info"
  for f in LICENSE NOTICE; do
    if ! unzip -p "$whl" "$dist_info/licenses/$f" | cmp -s - "$ROOT/$f"; then
      echo "$(basename "$whl"): $dist_info/licenses/$f is missing or differs from $f" >&2
      exit 1
    fi
  done
done

# hatch_build.py pins the README's relative links to the release tag.
v=$(version "$core")
description=$(unzip -p "$core" "forgd_verdict-$v.dist-info/METADATA")
if ! grep -qF "/blob/v$v/" <<<"$description"; then
  echo "$(basename "$core"): long description has no link pinned to /blob/v$v/" >&2
  exit 1
fi
if grep -qF "](docs/" <<<"$description"; then
  echo "$(basename "$core"): long description keeps a relative ](docs/ link" >&2
  exit 1
fi

echo "$core"
echo "$hook"
