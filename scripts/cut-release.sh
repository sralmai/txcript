#!/usr/bin/env sh
# Cut a release: work out the version, write the changelog section, bump
# every manifest, land the commit and its tag on main, and see the publish
# through.
#
# Usage:
#   cut-release.sh [X.Y.Z] [options]
#   cut-release.sh --resolve-version [X.Y.Z]   # print the version and stop
#
#   --dry-run    build the release commit, show it, and throw it away
#   --yes        skip the confirmation prompt
#   --no-watch   push and return without following the release run
#
# One script rather than two paths that drift: prepare-release.yml runs this
# too, so what CI does and what you can do by hand are the same thing. The
# only difference is who pushes.
#
# Why it ends by *checking* for a release run rather than assuming one: a
# push from a person or from a GitHub App starts release.yml, but a push
# made with GITHUB_TOKEN does not — that is GitHub's recursion guard. So we
# wait to see a run appear and dispatch one if it does not, which covers all
# three without needing to know which we were.
set -eu

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }

version=""
explicit=false
resolve_only=false
dry_run=false
assume_yes=false
watch=true

for arg in "$@"; do
  case "$arg" in
    --resolve-version) resolve_only=true ;;
    --dry-run) dry_run=true ;;
    --yes|-y) assume_yes=true ;;
    --no-watch) watch=false ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $arg" >&2; usage >&2; exit 2 ;;
    *)
      [ -z "$version" ] || { echo "two versions given: $version and $arg" >&2; exit 2; }
      version="${arg#v}"
      explicit=true
      ;;
  esac
done

# The repository that owns the published package names. A fork is anything
# else, and has to opt out of the npm publish before it can release.
UPSTREAM=skillsynchq/txcript

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }

cd "$(git rev-parse --show-toplevel)" || die "not in a git repository"

# --- what the version may be ------------------------------------------

# The rules live here alone so the plan and the tag cannot disagree about
# them. git-cliff derives the bump from the conventional-commit titles.
resolve_version() {
  # Without a reachable version tag git-cliff treats the whole history as
  # unreleased: it derives 0.1.0 and would write every commit ever made into
  # the changelog section. A fork cloned without tags lands here, and the
  # symptom ("0.1.0 is below the current X.Y.Z") does not name the cause.
  if ! git describe --tags --match 'v*' --abbrev=0 >/dev/null 2>&1; then
    die "no version tag is reachable from HEAD, so the bump cannot be derived.
Import the tags once, from wherever this history came from, e.g.:
  git fetch https://github.com/skillsynchq/txcript 'refs/tags/v*:refs/tags/v*'
  git push origin --tags"
  fi
  if [ -z "$version" ]; then
    version="$(git-cliff --bumped-version 2>/dev/null)" || die "git-cliff could not derive a version"
    version="${version#v}"
  fi
  echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "not a version: $version"
  current="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "(.*)"/\1/')"
  [ "$version" != "$current" ] || die "$version is already the current version"
  [ "$(printf '%s\n%s\n' "$current" "$version" | sort -V | tail -1)" = "$version" ] \
    || die "$version is below the current $current"
  ! git rev-parse -q --verify "refs/tags/v$version" >/dev/null \
    || die "tag v$version already exists"
}

if [ "$resolve_only" = true ]; then
  command -v git-cliff >/dev/null 2>&1 || die "git-cliff is not installed"
  resolve_version
  echo "$version"
  exit 0
fi

# --- preflight --------------------------------------------------------

# node is deliberately not here: nothing on this path needs it. The version
# bump is sed and cargo, the changelog is awk.
for tool in git gh cargo git-cliff; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "$tool is not installed. \`nix develop\` has all of these; otherwise
install it directly (git-cliff: \`brew install git-cliff\`, or
\`cargo install git-cliff\`)."
done
gh auth status >/dev/null 2>&1 || die "gh is not authenticated: run \`gh auth login\`"

# In CI the checkout is already exactly what we want to release, and is
# usually a detached head. Locally, releasing anything but an up-to-date,
# clean main is a mistake worth refusing rather than warning about.
if [ "${CI:-}" != "true" ]; then
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [ "$branch" = main ] || die "on $branch, not main"
  [ -z "$(git status --porcelain)" ] || die "the working tree is not clean"
  git fetch -q origin main || die "could not fetch origin/main"
  [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
    || die "main is not up to date with origin/main"

  state="$(gh run list --branch main --workflow ci.yml -L 1 --json conclusion --jq '.[0].conclusion' 2>/dev/null || echo '')"
  if [ "$state" != success ]; then
    echo "warning: the latest ci run on main is '${state:-unknown}', not success" >&2
    assume_yes=false
  fi

  # A fork that has not opted out of the npm publish watches release.yml
  # fail on a package name it does not own — and by then the tag is pushed.
  # Not fatal: the opt-out may be unreadable with this token, and being
  # wrong about it should not block a release.
  repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || echo '')"
  if [ -n "$repo" ] && [ "$repo" != "$UPSTREAM" ]; then
    optout="$(gh variable get PUBLISH_NPM --json value --jq .value 2>/dev/null || echo '?')"
    if [ "$optout" != false ]; then
      echo "warning: $repo is not $UPSTREAM and PUBLISH_NPM is '${optout}', not 'false'." >&2
      echo "         The npm job will try to publish a name this fork may not own," >&2
      echo "         and a failed publish blocks the GitHub Release." >&2
      echo "         Set it with: gh variable set PUBLISH_NPM --body false" >&2
      assume_yes=false
    fi
  fi
fi

resolve_version
tag="v$version"

# --- the plan ---------------------------------------------------------

git-cliff --unreleased --tag "$tag" --strip all 2>/dev/null > /tmp/cut-release-section.$$ \
  || die "git-cliff could not generate the changelog section"

# Not `-s`: with nothing to release git-cliff still writes the `## [x.y.z]`
# heading, so a non-empty file proves nothing. An empty section is cut
# happily, lands a tag, and then fails release.yml at "CHANGELOG.md has no
# section for x.y.z" — after the tag is pushed and irreversible. Count the
# entries instead.
entries="$(grep -vcE '^(## \[|[[:space:]]*$)' /tmp/cut-release-section.$$ || true)"
if [ "${entries:-0}" -eq 0 ]; then
  rm -f /tmp/cut-release-section.$$
  die "nothing has landed since the last tag, so the release section would be
empty and release.yml would reject the tag. Merge something first."
fi

say "Release $tag from $(git rev-parse --short HEAD)"
echo
cat /tmp/cut-release-section.$$
echo

if [ "$assume_yes" != true ] && [ "$dry_run" != true ]; then
  printf 'Cut %s? [y/N] ' "$tag"
  read -r reply </dev/tty || reply=n
  case "$reply" in
    y|Y|yes|YES) ;;
    *) rm -f /tmp/cut-release-section.$$; die "cancelled" ;;
  esac
fi

# --- build the commit, and land it ------------------------------------

# Rebuilt from scratch on each attempt: if main moves under us the commit
# has to be the one that belongs on the new head, not a replay of the old.
build_commit() {
  git tag -d "$tag" 2>/dev/null || true
  git-cliff --unreleased --tag "$tag" --strip all 2>/dev/null > section.md
  scripts/changelog-insert.sh section.md
  rm -f section.md
  scripts/bump-version.sh "$version"
  git add Cargo.toml Cargo.lock cli/Cargo.toml package.json CHANGELOG.md
  git commit -q -m "chore(release): $tag"
  git tag -a "$tag" -m "$tag"
}

if [ "$dry_run" = true ]; then
  say "dry run: building the commit, then undoing it"
  before="$(git rev-parse HEAD)"
  build_commit
  git --no-pager show --stat HEAD
  git tag -d "$tag" >/dev/null
  git reset -q --hard "$before"
  rm -f /tmp/cut-release-section.$$
  say "dry run complete; nothing was pushed and the tree is back to $(git rev-parse --short HEAD)"
  exit 0
fi

rm -f /tmp/cut-release-section.$$
pushed=false
attempt=1
while [ "$attempt" -le 5 ]; do
  git fetch -q origin main
  git reset -q --hard origin/main
  # Without an explicit version the bump must still be the one that was
  # shown above; a feat landing mid-run would quietly change it.
  if [ "$explicit" != true ]; then
    now="$(git-cliff --bumped-version 2>/dev/null || echo "v$version")"
    [ "${now#v}" = "$version" ] \
      || die "main moved and the derived version is now ${now#v}, not $version; rerun"
  fi
  build_commit
  if git push --atomic origin HEAD:main "refs/tags/$tag"; then
    say "pushed $tag on $(git rev-parse --short HEAD) (attempt $attempt)"
    pushed=true
    break
  fi
  say "main moved during attempt $attempt; rebuilding on the new head"
  attempt=$((attempt + 1))
done
[ "$pushed" = true ] || die "could not land the release commit after 5 attempts"

# --- see the publish through ------------------------------------------

# A push by a person or a GitHub App starts release.yml; one made with
# GITHUB_TOKEN does not. Rather than track which we are, watch for the run
# and ask for it only if it never shows up.
say "waiting for the release run on $tag"
run=""
waited=0
while [ "$waited" -lt 90 ]; do
  run="$(gh run list --workflow release.yml --event push -L 20 \
    --json databaseId,headBranch --jq "[.[] | select(.headBranch==\"$tag\")][0].databaseId" 2>/dev/null || echo '')"
  [ -z "$run" ] || break
  sleep 10
  waited=$((waited + 10))
done

if [ -z "$run" ]; then
  say "no run appeared in ${waited}s; dispatching release.yml on $tag"
  gh workflow run release.yml --ref "$tag" || die "could not dispatch release.yml"
  sleep 10
  run="$(gh run list --workflow release.yml -L 10 \
    --json databaseId,headBranch --jq "[.[] | select(.headBranch==\"$tag\")][0].databaseId" 2>/dev/null || echo '')"
fi

if [ "$watch" != true ]; then
  say "release run: ${run:-not found yet}"
  exit 0
fi

[ -n "$run" ] || die "the tag is pushed but no release run could be found; start one with \`gh workflow run release.yml --ref $tag\`"
say "watching run $run"
gh run watch "$run" --exit-status || die "the release run failed; the tag $tag is already pushed, so fix forward"

say "released $tag"
gh release view "$tag" --json url --jq .url 2>/dev/null || true
