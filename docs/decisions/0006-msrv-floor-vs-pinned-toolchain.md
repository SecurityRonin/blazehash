# 6. Declared MSRV 1.88, separate from the pinned 1.96.0 dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet policy (`ronin-issen/CLAUDE.md`, "Rust MSRV & Toolchain Policy")
separates two numbers that are easy to conflate:

- the **dev toolchain** (`rust-toolchain.toml`) — one pinned stable everyone
  builds/fmt/clippy with, to end "which Rust am I on" drift; and
- the **declared MSRV** (`rust-version` in `Cargo.toml`) — a downstream-facing
  compatibility promise, set by repo role.

Apps declare MSRV = the pinned toolchain (nothing pins a library dependency
against them); published libraries keep a low, CI-verified floor. blazehash is
both: the `blazehash` app and the `blazehash-core` library. The complication is
that `blazehash-core`'s dependency set (the RustCrypto/BLAKE3/fuzzy stack and
their transitive deps) already requires a modern compiler, so the lean engine
cannot honestly promise the 1.75/1.80 floor a zero-dependency KNOWLEDGE leaf
would.

## Decision

1. **Pin the dev toolchain to current stable.** `rust-toolchain.toml` pins
   `channel = "1.96.0"` with `components = ["rustfmt", "clippy"]` declared in the
   toml (single source of truth for CI and local), per the fleet toolchain
   standard (commit `c8055c9`).
2. **Declare MSRV 1.88 for both crates.** `Cargo.toml` and `core/Cargo.toml` set
   `rust-version = "1.88"`. This is the honest floor the dependency graph
   actually compiles on, below the pinned dev toolchain but a real, testable
   promise. The MSRV was raised deliberately when the graph required it (commit
   `bc40d84`, "resolve Windows build failure and MSRV bump").
3. **Release cross-builds must honor the pin.** Per the fleet `E0463` gotcha, the
   `release.yml` toolchain action installs the pinned `1.96.0` (not a floating
   `stable`) so cross-targets land on the toolchain cargo actually builds with.

## Consequences

- `blazehash-core`'s declared MSRV (1.88) is higher than the fleet's low-floor
  libraries because its hashing dependencies demand it — a dependency-driven
  floor, not a chosen-low one. *Rationale reconstructed from structure and the
  dep graph; the git history records the bump (`bc40d84`) but not the specific
  crate that forced 1.88.*
- Bumping the dev toolchain is a deliberate fleet-wide pass; bumping the declared
  MSRV is treated as near-breaking and only done when the code genuinely needs a
  newer feature.
