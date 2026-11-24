#!/usr/bin/env bash
# Run lint and both test passes as .github/workflows/ci.yml does: lint, the
# parallel pass, then the serial pass, each with the dev extra. CI runs more
# jobs than these (Terraform validate, the helm lint, the CLI smoke test, the
# image builds, the audit) and splits the serial pass into shards; this runs
# the serial tests in one pass.
#
# It runs in the project environment (`uv run --extra dev`); CI installs into
# a fresh one. It warns for each of helm, gitleaks and terraform missing from
# PATH, whose tests then skip here. Each step's full output goes to a log
# file; the terminal gets one line per step and a failing step's last lines.
#
# Usage: scripts/test_like_ci.sh [--no-serial] [--logs DIR]
set -uo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/test_like_ci.sh [--no-serial] [--logs DIR]

Runs, in order, the lint and test steps ci.yml runs:
  lint      check_workflows.py, ruff, import_graph.py --check
  parallel  pytest -q -n auto -m "not serial"
  serial    pytest -q -m serial   (CI shards this; here it is one pass;
                                   skipped with --no-serial)

Options:
  --no-serial   skip the serial pass (about 15 minutes)
  --logs DIR    write each step's full output to DIR (default: a new temp dir)
  -h, --help    show this help

Exit status: 0 when every step passes, 1 when one fails, 2 on bad usage.

Warns when helm, gitleaks or terraform is missing: CI has them, so their
tests run there and skip here.
USAGE
}

serial=1
logs=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-serial) serial=0; shift ;;
    --logs) logs="${2:?--logs needs a directory}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.." || exit 2
logs="${logs:-$(mktemp -d "${TMPDIR:-/tmp}/forgd-verdict-ci.XXXXXX")}"
mkdir -p "$logs"
failed=0

for tool in helm gitleaks terraform; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "warning: $tool is not on PATH; its tests will skip here and run in CI" >&2
  fi
done

# step NAME COMMAND...: run COMMAND, log it, print one line.
step() {
  local name="$1"; shift
  local log="$logs/$name.log"
  if "$@" >"$log" 2>&1; then
    printf 'ok    %-9s %s\n' "$name" "$(tail -n 1 "$log")"
  else
    printf 'FAIL  %-9s see %s\n' "$name" "$log"
    tail -n 15 "$log" | sed 's/^/      /'
    failed=1
  fi
}

# shellcheck disable=SC2329  # called by name through step
run_lint() {
  uv run --extra dev python scripts/check_workflows.py &&
    uv run --extra dev ruff check src tests loadtest.py deploy/assert_presidio.py &&
    uv run --extra dev python scripts/import_graph.py --check
}

step lint run_lint
step parallel uv run --extra dev pytest -q -n auto -m "not serial"
if [[ $serial -eq 1 ]]; then
  step serial uv run --extra dev pytest -q -m serial
fi

echo "logs: $logs"
exit "$failed"
