# 8. Read archives via the pure-Rust `zip-forensic-core`; keep third-party `zip` only for test fixtures

Date: 2026-07-24
Status: Accepted

## Context

The `archive` feature hashes files inside ZIP/TAR containers. Two fleet
disciplines shape how that reader is chosen: "prefer our own crates"
(`ronin-issen/CLAUDE.md`, Dependency Preference) and the `unsafe`/C-FFI aversion
(a C-binding dependency has zero compiler-visible memory safety and breaks the
pure-Rust posture). The mainstream `zip` crate is capable but, with its default
features, pulls C-backed codecs; SecurityRonin publishes `zip-forensic-core`, a
pure-Rust, read-only ZIP reader.

A reader alone cannot *write* the archives the test suite needs as fixtures, and
`zip-forensic-core` deliberately has no writer.

## Decision

1. **The production ZIP reader is `zip-forensic-core`.** `Cargo.toml` declares
   `zip-forensic-core = { version = "0.1", optional = true }` under the `archive`
   feature; commit `f54decc` ("migrate zip reader to pure-Rust zip-forensic-core")
   replaced the third-party reader. It is a fleet-owned, pure-Rust, read-only
   crate — no C-FFI, and read-only-safe by construction (it cannot mutate an
   evidence archive).
2. **The third-party `zip` crate is confined to `[dev-dependencies]`**, used only
   to *write* fixture archives the tests then read back, and pinned
   `default-features = false, features = ["deflate"]` to stay C-FFI-free
   (`Cargo.toml` dev-dep comment).
3. **TAR uses `tar` + `flate2`** under the same `archive` feature.

## Consequences

- The shipped archive-hashing path depends on a fleet crate, is pure Rust, and
  cannot write to the source archive — consistent with prefer-our-own and the
  read-only evidence contract.
- The dev-only `zip` writer keeps fixtures self-contained without adding a C-FFI
  or write capability to the production graph.
