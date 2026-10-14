#!/usr/bin/env sh
# Print the CHANGELOG.md section for one version. Usage:
# release-notes.sh 0.12.1 > notes.md
#
# Links to published packages are *not* added here. They used to be, as three
# hardcoded lines, and two of them had been dead since the crates.io job was
# removed — nothing publishes to crates.io, so docs.rs has nothing to build
# from either. release.yml appends a link per package it actually published,
# which is also what lets a fork that skips npm produce honest notes.
# Exits 1 when the version has no section, so a tag without changelog
# coverage fails the release job instead of shipping empty notes.
set -eu
ver="$1"
section="$(awk -v ver="$ver" '
  /^## \[/ { inside = ($0 ~ "^## \\[" ver "\\]") ; next }
  inside && /^\[/ { next }
  inside { print }
' CHANGELOG.md)"
# Trim leading/trailing blank lines.
section="$(printf '%s\n' "$section" | sed -e '/./,$!d' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}')"
if [ -z "$section" ]; then
  echo "::error::CHANGELOG.md has no section for $ver" >&2
  exit 1
fi
printf '%s\n' "$section"
