#!/usr/bin/env bash
# Marks Farsi pages whose English source changed after they were translated.
#
# Each page in docs/fa/ names the English revision it was translated from in
# its front matter (source_rev). A page is stale when the matching English
# file in docs/ has commits after that revision, has uncommitted changes, or
# the revision is missing or unknown. The result is written to
# site/data/translations.json, which drives the "may be out of date" banner.
#
# Usage:
#   scripts/translation-status.sh                 write site/data/translations.json
#   scripts/translation-status.sh --stamp FILE... set source_rev of the given
#                                                 Farsi pages to the latest
#                                                 commit of their English file
set -euo pipefail
cd "$(dirname "$0")/.."

front_matter_rev() {
  awk '/^---$/ { n++; next } n == 1 && /^source_rev:/ { sub(/^source_rev:[ ]*/, ""); gsub(/"/, ""); print; exit }' "$1"
}

if [ "${1:-}" = "--stamp" ]; then
  shift
  [ "$#" -gt 0 ] || { echo "usage: $0 --stamp docs/fa/PAGE.md..." >&2; exit 2; }
  for fa in "$@"; do
    en="docs/$(basename "$fa")"
    rev=$(git log -1 --format=%H -- "$en")
    [ -n "$rev" ] || { echo "$en has no commits yet; commit it first" >&2; exit 1; }
    awk -v rev="$rev" '/^---$/ { n++ } n == 1 && /^source_rev:/ { print "source_rev: " rev; next } { print }' "$fa" >"$fa.tmp"
    mv "$fa.tmp" "$fa"
    echo "stamped $fa at ${rev:0:12}"
  done
  exit 0
fi

mkdir -p site/data
json=""
for fa in docs/fa/*.md; do
  [ -e "$fa" ] || continue
  name=$(basename "$fa")
  en="docs/$name"
  [ -f "$en" ] || continue

  stale=true
  rev=$(front_matter_rev "$fa")
  if [ -n "$rev" ] && git cat-file -e "$rev^{commit}" 2>/dev/null; then
    behind=$(git rev-list --count "$rev..HEAD" -- "$en")
    if [ "$behind" -eq 0 ] && git diff --quiet HEAD -- "$en"; then
      stale=false
    fi
  fi
  json="${json:+$json,}\"docs/$name\":{\"stale\":$stale}"
done
printf '{%s}\n' "$json" >site/data/translations.json
echo "wrote site/data/translations.json"
