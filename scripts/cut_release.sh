#!/usr/bin/env bash
# Cut a release in two steps, either side of a pull request.
#
# prepare <version>: from a clean main that matches origin/main, run the
# tests and lint, bump every version on a new branch release/v<version>,
# commit the bump signed off, push the branch, and print the `gh pr create`
# command for it. It neither tags nor pushes main.
#
# tag <version>: once that pull request is merged, from a clean main that
# matches origin/main after a fetch, check that every version in the tree
# is <version> and that tag v<version> exists neither here nor on origin,
# then create the annotated tag and push the tag alone. The tag runs
# .github/workflows/release.yml, which publishes the release.
#
# The core, the hook, the hook's pin on the core and the chart's appVersion
# all become <version>. The chart's own version moves up one patch.
#
# Usage: scripts/cut_release.sh prepare|tag <MAJOR.MINOR.PATCH>
set -euo pipefail

usage() {
  echo "usage: cut_release.sh prepare|tag <MAJOR.MINOR.PATCH>   e.g. prepare 0.2.0" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
COMMAND="$1"
VERSION="$2"
case "$COMMAND" in
  prepare|tag) ;;
  *) usage ;;
esac
# [[ =~ ]] matches the whole string, so a trailing newline cannot pass the
# way it does through a line-based grep.
N='(0|[1-9][0-9]*)'
if ! [[ "$VERSION" =~ ^$N\.$N\.$N$ ]]; then
  echo "version must be MAJOR.MINOR.PATCH, got '$VERSION'" >&2
  exit 64
fi

say() { printf '\n==> %s\n' "$*"; }
die() { echo "$*" >&2; exit 1; }

# A clean main that matches origin/main after a fetch, and no tag v<version>
# here or on origin.
check_main() {
  if [ -n "$(git status --porcelain)" ]; then
    die "working tree is dirty; commit or stash first"
  fi
  BRANCH="$(git rev-parse --abbrev-ref HEAD)"
  if [ "$BRANCH" != "main" ]; then
    die "releases are cut from main, not '$BRANCH'"
  fi
  git fetch -q origin main
  if [ "$(git rev-parse main)" != "$(git rev-parse origin/main)" ]; then
    die "main is $(git rev-parse --short main) but origin/main is" \
        "$(git rev-parse --short origin/main); run \`git pull --ff-only\` first"
  fi
  if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null ||
     [ -n "$(git ls-remote --tags origin "refs/tags/v$VERSION")" ]; then
    die "tag v$VERSION already exists"
  fi
}

prepare() {
  check_main
  RELEASE_BRANCH="release/v$VERSION"
  if git rev-parse -q --verify "refs/heads/$RELEASE_BRANCH" >/dev/null ||
     [ -n "$(git ls-remote --heads origin "refs/heads/$RELEASE_BRANCH")" ]; then
    die "branch $RELEASE_BRANCH already exists"
  fi

  say "tests and lint"
  uv sync --all-extras --no-extra ml
  uv run pytest -q -n auto -m "not serial"
  uv run pytest -q -m serial
  uv run ruff check src tests loadtest.py deploy/assert_presidio.py

  say "bumping to $VERSION on $RELEASE_BRANCH"
  git switch -q -c "$RELEASE_BRANCH"
  python3 - "$VERSION" <<'PY'
import pathlib, re, sys
version = sys.argv[1]


def chart_patch(m):
    major, minor, patch = m.group(1), m.group(2), int(m.group(3))
    return f"version: {major}.{minor}.{patch + 1}"


for path, pattern, replacement in (
    ("pyproject.toml", r'(?m)^version = "[^"]+"', f'version = "{version}"'),
    ("src/forgd_verdict/__init__.py", r'(?m)^__version__ = "[^"]+"', f'__version__ = "{version}"'),
    ("deploy/helm/forgd-verdict/Chart.yaml", r'(?m)^appVersion: "[^"]+"', f'appVersion: "{version}"'),
    ("deploy/helm/forgd-verdict/Chart.yaml", r'(?m)^version: (\d+)\.(\d+)\.(\d+)$', chart_patch),
    ("packaging/forgd-verdict-hook/pyproject.toml", r'(?m)^version = "[^"]+"', f'version = "{version}"'),
    ("packaging/forgd-verdict-hook/pyproject.toml", r'"forgd-verdict==[^"]+"', f'"forgd-verdict=={version}"'),
):
    p = pathlib.Path(path)
    text = p.read_text()
    updated, n = re.subn(pattern, replacement, text, count=1)
    if n != 1:
        raise SystemExit(f"could not find the version line in {path}")
    p.write_text(updated)
    print(f"  {path}")
PY
  # The version tests ran before the bump; they run again on the bumped tree.
  uv run pytest -q tests/test_policy.py -k "declared_version or hook_distribution"

  # Every file the bump block writes.
  git add pyproject.toml src/forgd_verdict/__init__.py \
          deploy/helm/forgd-verdict/Chart.yaml \
          packaging/forgd-verdict-hook/pyproject.toml
  git commit -q -s -m "release: v$VERSION"

  say "pushing $RELEASE_BRANCH"
  git push -q -u origin "$RELEASE_BRANCH"

  cat <<EOF

Pushed $RELEASE_BRANCH with the bump to $VERSION. Open the pull request:

  gh pr create --base main --head $RELEASE_BRANCH --title "release: v$VERSION" --body "Bump every version to $VERSION."

Once it is merged, tag main:

  git switch main && git pull --ff-only && scripts/cut_release.sh tag $VERSION
EOF
}

tag() {
  check_main

  say "checking every version is $VERSION"
  python3 - "$VERSION" <<'CHECK'
import pathlib, re, sys, tomllib
version = sys.argv[1]
core = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]
hook = tomllib.loads(pathlib.Path("packaging/forgd-verdict-hook/pyproject.toml").read_text())["project"]
init = pathlib.Path("src/forgd_verdict/__init__.py").read_text()
chart = pathlib.Path("deploy/helm/forgd-verdict/Chart.yaml").read_text()
dunder = re.search(r'(?m)^__version__ = "([^"]+)"$', init)
app = re.search(r'(?m)^appVersion: "?([^"\n]+?)"?$', chart)
pins = [d.split("==", 1)[1] for d in hook.get("dependencies", []) if d.startswith("forgd-verdict==")]
found = {
    "pyproject.toml version": core.get("version"),
    "src/forgd_verdict/__init__.py __version__": dunder and dunder.group(1),
    "packaging/forgd-verdict-hook/pyproject.toml version": hook.get("version"),
    "packaging/forgd-verdict-hook/pyproject.toml forgd-verdict== pin": pins[0] if pins else None,
    "deploy/helm/forgd-verdict/Chart.yaml appVersion": app and app.group(1),
}
wrong = [f"{name} is {value!r}" for name, value in found.items() if value != version]
if wrong:
    raise SystemExit(f"main is not at {version}: " + "; ".join(wrong)
                     + ". Merge the release pull request and pull main first.")
CHECK

  git tag -a "v$VERSION" -m "v$VERSION"

  say "pushing v$VERSION"
  git push -q origin "refs/tags/v$VERSION"

  cat <<EOF

Tagged v$VERSION and pushed the tag. The tag publishes the release: it runs
.github/workflows/release.yml, which pushes the base and ingest images and
the Helm chart to GHCR and the two wheels to PyPI, once the release and
pypi environments are approved.

  gh run watch \$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
EOF
}

"$COMMAND"
