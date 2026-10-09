#!/bin/sh
# Copies the licence files of every module linked into a Go binary, and the
# Go standard library's, into OUT_DIR, and writes OUT_DIR/index.tsv.
#
#   collect_go_licenses.sh BINARY OUT_DIR
#
# The module list is `go version -m BINARY`, so it is what was linked, not
# what go.mod requires. Each module's files come from the module cache, and
# a replaced module's from its replacement. Exits non-zero if any module has
# no licence file at its root.
set -eu

bin=$1
out=$2
cache=$(go env GOMODCACHE)
mkdir -p "$out"
printf 'module\tversion\tfiles\n' > "$out/index.tsv"
missing=0

copy() {  # copy NAME VERSION SRC_DIR
  dest="$out/$1@$2"
  mkdir -p "$dest"
  found=""
  for f in "$3"/LICENSE* "$3"/LICENCE* "$3"/COPYING* "$3"/NOTICE* "$3"/PATENTS*; do
    [ -f "$f" ] || continue
    cp "$f" "$dest/"
    found="$found${found:+ }$(basename "$f")"
  done
  if [ -z "$found" ]; then
    echo "no licence file for $1 $2 in $3" >&2
    missing=1
  fi
  printf '%s\t%s\t%s\n' "$1" "$2" "$found" >> "$out/index.tsv"
}

# The module cache escapes each upper-case letter as `!` and its lower case.
escape() {
  printf '%s' "$1" | LC_ALL=C sed 's/[[:upper:]]/!&/g' | LC_ALL=C tr '[:upper:]' '[:lower:]'
}

copy go-stdlib "$(go env GOVERSION)" "$(go env GOROOT)"

# Lines are `dep PATH VERSION SUM`, each optionally followed by
# `=> REPLACEMENT VERSION SUM` when the module is replaced.
go version -m "$bin" > "$out/go-version-m.txt"
awk '
  $1 == "dep" { if (m != "") print m, v; m = $2; v = $3; next }
  $1 == "=>"  { m = $2; v = $3; next }
  END         { if (m != "") print m, v }
' "$out/go-version-m.txt" > "$out/modules.txt"

while read -r mod ver; do
  case "$mod" in
    ./*|../*|/*) echo "local replacement $mod is not supported" >&2; exit 1 ;;
  esac
  dir="$cache/$(escape "$mod")@$(escape "$ver")"
  [ -d "$dir" ] || { echo "$mod $ver is not in the module cache: $dir" >&2; exit 1; }
  copy "$mod" "$ver" "$dir"
done < "$out/modules.txt"
rm "$out/modules.txt"

[ "$missing" = 0 ]
