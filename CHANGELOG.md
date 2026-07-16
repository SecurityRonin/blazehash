# Changelog

All notable changes to the `blazehash` binary are documented here. The lean
`blazehash-core` library is versioned and released separately.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.6] - 2026-07-16

### Security

- Made the `remote` feature (opendal cloud/object-storage backends) opt-in
  rather than default. The default `cargo build` no longer pulls the opendal
  stack, removing its vulnerable transitive tree from the shipped default binary
  and from `cargo deny`:
  - RUSTSEC-2026-0118 / RUSTSEC-2026-0119 (hickory DNS: unbounded NSEC3 loop /
    O(n²) name compression) — via `opendal → mongodb → hickory-resolver`.
  - RUSTSEC-2026-0194 / RUSTSEC-2026-0195 (quick-xml: quadratic duplicate-attribute
    check / unbounded namespace allocation) — via `opendal`/`reqsign`.
  - Also drops the sqlx/tikv/rustls/sled advisory surface that was previously
    ignored in `deny.toml`.
  Build with `--features remote` to restore the cloud backends (release binaries
  enable it).
- Updated `crossbeam-epoch` 0.9.18 → 0.9.20, clearing RUSTSEC-2026-0204 (invalid
  pointer dereference in `fmt::Pointer` for `Atomic`/`Shared`). This crate remains
  in the graph via `rayon`/`yara-x`, so the fix is a lockfile update rather than a
  feature change.

### Changed

- `deny.toml` now audits the default feature set (every feature except `remote` /
  `rocksdb-storage`) instead of `all-features`, so `cargo deny check` reflects what
  a default `cargo build` ships. Removed the six advisory ignores that only existed
  to paper over the opendal tree (adler, instant, number_prefix, sled, sqlx,
  indicatif).
