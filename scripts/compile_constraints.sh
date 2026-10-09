#!/usr/bin/env bash
# Regenerate the hashed requirement files the images, scripts/build_wheels.sh
# and the hook's laptop install (deploy/MDM.md) install from:
#
#   deploy/constraints/build.txt   [build-system] requires of pyproject.toml
#                                  and packaging/forgd-verdict-hook/pyproject.toml
#   deploy/constraints/base.txt    --target base: the server, azure, aws, gcp,
#                                  dashboard and connector extras
#   deploy/constraints/ingest.txt  --target ingest: base's set, ml-pii and
#                                  the spaCy model in ingest.in, with every
#                                  package base.txt pins at base's version
#   deploy/constraints/hook.txt    the core's runtime dependencies for
#                                  the hook on a laptop, resolved for
#                                  every OS, architecture and CPython
#                                  >=3.11 (--universal)
#
# Usage: compile_constraints.sh [--check | --upgrade]
#
#   (none)     add, drop or move pins to match pyproject.toml; a pin that
#              still satisfies it is kept
#   --upgrade  re-resolve every pin to the newest version allowed
#   --check    exit 1, with the diff, if the committed files differ from
#              what the default mode would write; the files are restored
#
# Resolved for CPython 3.13 on x86_64 manylinux_2_28, without uv's project
# config, as pip in the image resolves. The same pins must also resolve for
# aarch64, or the run fails. --generate-hashes lists every file of each
# pinned version, so the hashes cover both architectures' wheels.
# hook.txt's pins must also install from wheels alone on each laptop
# target, macOS arm64 and Windows amd64, at CPython 3.11 and 3.13, because
# deploy/MDM.md installs it with --no-build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR=deploy/constraints
cd "$ROOT"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

mode=${1:-}
case "$mode" in
  ""|--check|--upgrade) ;;
  *) echo "unknown argument: $mode" >&2; exit 2 ;;
esac

COMMON=(--no-config --quiet --generate-hashes --only-binary :all: --python-version 3.13
        --custom-compile-command scripts/compile_constraints.sh)
BASE_EXTRAS=(--extra server --extra azure --extra aws --extra gcp
             --extra dashboard --extra connector)
upgrade=""
[ "$mode" = --upgrade ] && COMMON+=(--upgrade) && upgrade=1

compile() {  # compile PLATFORM BUILD BASE INGEST
  python3 -c 'import sys, tomllib; print("\n".join(dict.fromkeys(r for p in sys.argv[1:] for r in tomllib.load(open(p, "rb"))["build-system"]["requires"])))' \
      pyproject.toml packaging/forgd-verdict-hook/pyproject.toml \
    | uv pip compile "${COMMON[@]}" --python-platform "$1" - -o "$2"
  uv pip compile "${COMMON[@]}" --python-platform "$1" pyproject.toml "${BASE_EXTRAS[@]}" \
    -o "$3"
  uv pip compile "${COMMON[@]}" --python-platform "$1" pyproject.toml "${BASE_EXTRAS[@]}" \
    --extra ml-pii "$DIR/ingest.in" -c "$3" -o "$4"
}

pins() { grep -E '^[A-Za-z0-9]' "$1" | sed 's/ .*//'; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ "$mode" = --check ]; then
  for f in build base ingest hook; do cp "$DIR/$f.txt" "$tmp/$f.committed"; done
  trap 'for f in build base ingest hook; do cp "$tmp/$f.committed" "$DIR/$f.txt"; done; rm -rf "$tmp"' EXIT
fi

compile x86_64-manylinux_2_28 "$DIR/build.txt" "$DIR/base.txt" "$DIR/ingest.txt"
uv pip compile --no-config --quiet --generate-hashes --universal --python-version 3.11 \
  --custom-compile-command scripts/compile_constraints.sh ${upgrade:+--upgrade} pyproject.toml -o "$DIR/hook.txt"

# The aarch64 resolve starts from the x86_64 pins, so a difference means
# a pin that aarch64 cannot install, not a newer release.
for f in build base ingest; do cp "$DIR/$f.txt" "$tmp/$f.arm"; done
compile aarch64-manylinux_2_28 "$tmp/build.arm" "$tmp/base.arm" "$tmp/ingest.arm"
fail=0
for laptop in aarch64-apple-darwin x86_64-pc-windows-msvc; do
  for py in 3.11 3.13; do
    if ! uv pip compile --no-config --quiet --only-binary :all: --python-platform "$laptop" \
        --python-version "$py" "$DIR/hook.txt" -o "$tmp/hook-$laptop-$py.txt" \
        || ! diff <(pins "$DIR/hook.txt") <(pins "$tmp/hook-$laptop-$py.txt") >&2; then
      echo "$DIR/hook.txt: a pin has no wheel for $laptop on CPython $py" >&2
      fail=1
    fi
  done
done
for f in build base ingest; do
  if ! diff <(pins "$DIR/$f.txt") <(pins "$tmp/$f.arm") >&2; then
    echo "$DIR/$f.txt: aarch64 resolves different pins" >&2
    fail=1
  fi
done

if [ "$mode" = --check ]; then
  for f in build base ingest hook; do
    if ! diff -u "$tmp/$f.committed" "$DIR/$f.txt" >&2; then
      echo "$DIR/$f.txt is out of date; run scripts/compile_constraints.sh" >&2
      fail=1
    fi
  done
fi
exit "$fail"
