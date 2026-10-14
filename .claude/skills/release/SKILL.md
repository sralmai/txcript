---
name: release
description: Cut a txcript release — dispatch the prepare-release workflow, approve the plan, watch the tag publish to npm and GitHub Releases, and verify. Use when asked to release, publish, or ship a new version of txcript.
argument-hint: [version]
---

# Release txcript

A release is cut by `scripts/cut-release.sh`: it computes the
version from the conventional-commit PR titles merged since the last tag,
generates the `CHANGELOG.md` section, bumps every manifest, lands one commit
plus its tag on main, and then follows the publish. The tag runs `release`,
which publishes the npm package and the CLI binaries, then creates the
GitHub Release from the changelog section.

`prepare-release` runs that same script, so dispatching the workflow and
running it by hand do the same thing and cannot drift. Use the workflow when
you want the `release` environment's approval gate; use the script when you
want to watch it happen.

There is no crates.io job: `share_s3` depends on two `publish = false`
crates, so the manifest cannot be published as it stands. Nothing reaches
crates.io or docs.rs, and the release notes link only what a run actually
published.

Main is releasable by construction: `ci` proves the npm bundle packs and
the CLI builds in release mode on every PR, and the ruleset requires PRs to
be up to date before merge. There is no crate dry-run there either, for the
same reason.

## Inputs

`$ARGUMENTS`: optional version. Without one, the workflow derives it: a
`feat` PR since the last tag is a minor bump, otherwise patch, and a breaking
change stays a minor bump until 1.0. Preview locally with
`git-cliff --bumped-version` and `git-cliff --unreleased --tag vX.Y.Z --strip all`.

## Procedure

From an up-to-date, clean `main`:

```sh
scripts/cut-release.sh --dry-run   # build the commit, show it, undo it
scripts/cut-release.sh             # the real thing
scripts/cut-release.sh 0.15.0      # with the version pinned
```

It refuses anything but a clean main level with `origin/main`, warns when
the latest `ci` run is not green, prints the changelog section it is about
to write, and asks before doing anything. Approving the prompt is the one
irreversible decision: an npm version can be deprecated but never reused.

It then lands `chore(release): vX.Y.Z` and the tag atomically — rebuilding
on the new head if main moved, and failing if the derived version changed
because of what landed — waits for `release` to start, and follows it to the
release URL. Needs `git-cliff`, `gh`, `cargo` and `node` on PATH.

Via the workflow instead, for the approval gate:
`gh workflow run prepare-release.yml` (add `-f version=X.Y.Z`), read the
plan in the run summary, approve the Tag job on the `release` environment.
The jobs in `release` are verify, npm, binaries for five targets, and the
GitHub Release.

## On a fork

A fork owns neither the npm name nor the release App, and both are optional:

- Set the repository variable `PUBLISH_NPM` to `false`. The npm job is
  skipped, and the GitHub Release stops waiting on it. A *failed* npm
  publish still blocks the release upstream; only a skipped one passes.
- Leave `RELEASE_APP_ID` unset. `prepare-release` pushes as GITHUB_TOKEN
  instead, which works as long as main carries no ruleset to bypass, and
  dispatches `release` itself afterwards — a GITHUB_TOKEN tag push does not
  start a workflow on its own.
- The `release` environment gates nothing until it has a required reviewer,
  so add one if the approval step matters. The script's own prompt is the
  gate when you run it by hand.
- A fork cloned without tags cannot derive a bump — git-cliff would read the
  whole history as unreleased. The script says so and stops. Import them
  once: `git fetch <upstream> 'refs/tags/v*:refs/tags/v*' && git push origin --tags`.

Expect no npm link in the notes, and binaries plus the GitHub Release as the
whole output.

## Verify

- npm: `npm view txcript version`. Skipped on a fork.
- Release: `gh release view vX.Y.Z` shows the changelog notes and ten assets
  (five archives, five checksums), plus an npm link when npm published.
- `cargo binstall --git https://github.com/skillsynchq/txcript txcript-cli`
  installs the new binary.

## When something fails

- `verify` fails on a manifest mismatch: the tag was pushed by hand without
  a bump. Delete nothing; run `prepare-release` for the next patch.
- A publish job fails after the tag exists: fix forward. The npm version may
  already be taken, so the next run needs a new version.
- `release` can be rerun on an existing tag with
  `gh workflow run release.yml --ref vX.Y.Z`; the GitHub Release step fails
  if the release already exists, which is the intended guard.

## Report

State the version, the prepare and release run URLs, the release URL, and
the npm verification result — or that npm was skipped, on a fork.
