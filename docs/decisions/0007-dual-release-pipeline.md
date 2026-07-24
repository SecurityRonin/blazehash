# 7. Dual release pipeline — release-plz for the library, a `v[0-9]*` tag for the binary

Date: 2026-07-24
Status: Accepted

## Context

blazehash publishes two things on two cadences: a **library** (`blazehash-core`,
which other fleet crates link) and a **binary application** (`blazehash`,
distributed as `cargo install` + Homebrew/apt/winget with an MSI and signed
release). The fleet release law (`ronin-issen/CLAUDE.md`, "Releases are automated
and reviewed" + "Library crate publishing — release-plz") assigns these to
different mechanisms: libraries release via a conventional-commit-driven,
PR-reviewed release-plz bump-and-publish; app/CLI binaries ship from a signed
`v[0-9]*` tag driving `release.yml`. A repo that is both runs both.

The trap the two mechanisms create is tag collision: release-plz's default
single-crate tag is a bare `v{{ version }}`, which would match the binary
pipeline's `v*` trigger and fire a binary build on a library release.

## Decision

1. **release-plz owns `blazehash-core`.** `.github/workflows/release-plz.yml`
   (commit `97e74e7`) opens a version-bump PR from conventional commits and, on
   merge, publishes the crate and cuts its tag. `release-plz.toml` sets
   `release_commits = "^(feat|fix|perf|refactor|doc|revert)"` to kill the
   changelog-churn loop.
2. **The `blazehash` app is `release = false` in release-plz** — its version bump,
   crates.io publish, and binary distribution are owned by `release.yml` on a
   manual `v[0-9]*` tag, decoupled from library publishing (`release-plz.toml`
   header comment).
3. **Per-package tag names avoid the collision.** `release-plz.toml` sets
   `git_tag_name = "{{ package }}-v{{ version }}"`, so a library tag is
   `blazehash-core-v0.2.6` — a letter follows `v`.
4. **The binary trigger requires a digit after `v`.** `release.yml` triggers on
   `v[0-9]*`, not `v*` (commit `3bf5af7`). A `<name>-v…` library tag never
   matches; only a bare `vX.Y.Z` binary tag does. Both controls are required — the
   `git_tag_name` prefix (release-plz side) and the `v[0-9]*` trigger (release.yml
   side).

## Consequences

- A `blazehash-core` release is a reviewed PR merge that publishes the library and
  never triggers a binary build; a `blazehash` binary release is a deliberate
  signed `v[0-9]*` tag push.
- crates.io versions are irreversible, so the reviewed release PR is the one
  human checkpoint before a library publish; the signed tag is the checkpoint
  before a binary release.
