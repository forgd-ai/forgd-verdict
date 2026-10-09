#!/usr/bin/env bash
# Check that every commit in <base>..<head> carries a Developer Certificate
# of Origin sign-off: a `Signed-off-by:` trailer naming the commit's author,
# exactly as `git commit -s` writes it. `Co-authored-by:` trailers need no
# sign-off of their own, as with the DCO GitHub App.
#
# Two kinds of commit are exempt:
# - Dependabot commits: the author email is exactly
#   `49699333+dependabot[bot]@users.noreply.github.com` and PR_AUTHOR_LOGIN
#   is `dependabot[bot]`. The dco workflow sets PR_AUTHOR_LOGIN from the
#   login of the account that opened the pull request. Unset, as in a local
#   run, no commit is exempt this way;
# - two-parent merge commits whose `git show --remerge-diff` is empty, that
#   is, merges that add nothing beyond what an automatic merge of their
#   parents produces. A merge that resolves a conflict or carries a change
#   of its own is checked like any other commit.
#
# Requires git 2.36 or later for --remerge-diff, and exits 2 on older git.
#
# Usage: [PR_AUTHOR_LOGIN=dependabot[bot]] scripts/check_dco.sh <base> <head>
#
# Exits 1 if any commit lacks the sign-off, naming each one and the trailer
# it needs.
set -euo pipefail

BASE="${1:?usage: check_dco.sh <base> <head>}"
HEAD="${2:?usage: check_dco.sh <base> <head>}"
DEPENDABOT_EMAIL='49699333+dependabot[bot]@users.noreply.github.com'

git_version="$(git version | sed -n 's/^git version \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
read -r git_major git_minor <<<"$git_version"
if [ -z "${git_major:-}" ] || [ "$git_major" -lt 2 ] ||
   { [ "$git_major" -eq 2 ] && [ "$git_minor" -lt 36 ]; }; then
  echo "dco: git 2.36 or later is required for --remerge-diff; found: $(git version)" >&2
  exit 2
fi

checked=0
missing=0
while IFS= read -r sha; do
  short="$(git rev-parse --short "$sha")"
  subject="$(git log -1 --format=%s "$sha")"
  checked=$((checked + 1))
  if [ "${PR_AUTHOR_LOGIN:-}" = "dependabot[bot]" ] &&
     [ "$(git log -1 --format=%ae "$sha")" = "$DEPENDABOT_EMAIL" ]; then
    echo "ok     $short $subject (dependabot)"
    continue
  fi
  parents="$(git rev-list --no-walk --parents "$sha" | wc -w)"
  if [ "$parents" -eq 3 ]; then
    remerge="$(git show --remerge-diff --format= "$sha")"
    if [ -z "$remerge" ]; then
      echo "ok     $short $subject (clean merge)"
      continue
    fi
  fi
  signoffs="$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | sed 's/[[:space:]]*$//')"
  needed="$(git log -1 --format='%an <%ae>' "$sha")"
  absent=()
  while IFS= read -r person; do
    printf '%s\n' "$signoffs" | grep -qxF -- "$person" || absent+=("$person")
  done <<<"$needed"
  if [ "${#absent[@]}" -eq 0 ]; then
    echo "ok     $short $subject"
  else
    for person in "${absent[@]}"; do
      echo "FAIL   $short $subject: no 'Signed-off-by: $person'"
    done
    missing=$((missing + 1))
  fi
done < <(git rev-list --reverse "$BASE..$HEAD")

echo "dco: $checked commit(s) checked, $missing without every sign-off"
if [ "$missing" -gt 0 ]; then
  echo "Sign off with \`git commit --amend -s\` for the last commit, or" \
       "\`git rebase --signoff $BASE\` for every commit on the branch." >&2
  exit 1
fi
