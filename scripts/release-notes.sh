#!/bin/sh
# Prints the CHANGELOG.md section for one version, without the heading.
# Usage: scripts/release-notes.sh 0.3.0
# The release workflow uses the output as the GitHub release notes.
set -eu

version="${1:?usage: release-notes.sh VERSION}"
version="${version#v}"
changelog="$(dirname "$0")/../CHANGELOG.md"

notes="$(awk -v v="$version" '
  /^## \[/ { if (found) exit; if (index($0, "## [" v "]") == 1) { found = 1; next } }
  found { print }
' "$changelog")"

if [ -z "$notes" ]; then
  echo "release-notes.sh: no CHANGELOG.md section for $version" >&2
  exit 1
fi
printf '%s\n' "$notes"
