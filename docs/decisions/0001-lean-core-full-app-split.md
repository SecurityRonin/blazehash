# 1. Split a lean `blazehash-core` engine from the full `blazehash` application

Date: 2026-07-24
Status: Accepted

## Context

`blazehash` is a batteries-included forensic hasher: GPU acceleration, cloud
storage, SQLite/Parquet/DuckDB output, YARA, TUI, MCP server, signing, and
timestamping all compile into one binary (`Cargo.toml` `[features]`). That full
dependency graph is appropriate for the shipped tool, but the *hash algorithms
themselves* — BLAKE3, the SHA/MD5 family, the fuzzy hashers (ssdeep, TLSH), the
checksums — are a small, dependency-light primitive that other fleet crates want
to link **without** dragging in wgpu, opendal, DuckDB, or clap.

The fleet rule (`ronin-issen/CLAUDE.md`, "Lean library core, full binary")
names this exact repo as the reference: a capability crate that is both a heavy
end-user tool and a primitive other libraries link is split the way readers are
split — a lean `<x>-core` library plus the full `<x>` app that depends on it. One
Cargo `default` cannot be simultaneously lean-for-libraries and full-for-the-binary;
the split, not feature-juggling, is the answer.

Historically the algorithms lived in the single `blazehash` crate. Commit
`091ae32` ("refactor: split lean blazehash-core lib from full blazehash binary")
extracted them; `3ba700a` cut `blazehash 0.2.5` as the post-split app.

## Decision

1. **Workspace with two published crates.** `Cargo.toml` declares
   `members = ["core"]`. `core/` is crate **`blazehash-core`** — the `Algorithm`
   enum, `hash_bytes`, and the `fuzzy` module, pulling in only the hashing
   dependencies (`core/Cargo.toml` lists no GPU/cloud/DB/CLI deps). The root crate
   is **`blazehash`** — the full application (`src/lib.rs` + `src/main.rs`).
2. **The app re-exports the engine so existing paths keep resolving.**
   `src/lib.rs` does `pub use blazehash_core::{algorithm, fuzzy};`, so
   `blazehash::algorithm::…` and the crate's own `crate::algorithm::…` references
   are unchanged by the move.
3. **Import path stays `blazehash_core`.** `core/Cargo.toml` sets
   `[lib] name = "blazehash_core"`; the app keeps `[lib] name = "blazehash"`.
4. **Shared hash-crate versions are declared once** in the root
   `[workspace.dependencies]` (DRY); each member writes `<dep>.workspace = true`.
5. The app depends on the engine by version with a workspace path for in-flight
   development: `blazehash-core = { version = "0.2.4", path = "core" }`.

## Consequences

- Fleet libraries that need only a hash primitive (e.g. `ext4fs-core`,
  `ewf-forensic` per the constitution) depend on `blazehash-core` and never touch
  the GPU+cloud app stack — no `default-features = false` gymnastics required.
- The two crates version and release independently (see
  [ADR 0007](0007-dual-release-pipeline.md)): `blazehash-core` via release-plz,
  the `blazehash` binary via a `v[0-9]*` tag.
- The engine can hold a stricter safety posture than the app
  ([ADR 0003](0003-split-unsafe-posture.md)): `blazehash-core` is pure computation
  and `forbid(unsafe)`, while the app carries the platform I/O `unsafe`.
