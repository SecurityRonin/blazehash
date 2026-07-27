# 11. Floor the `duckdb-output` dependency at DuckDB 1.5.5 (crate 1.10505.0) for the MSVC 14.51 fmt break

Date: 2026-07-27
Status: Accepted

## Context

The `duckdb-output` feature emits a `.duckdb` manifest via the `duckdb` crate with
the `bundled` feature (`Cargo.toml`; `src/format/duckdb_fmt.rs`), which vendors and
compiles DuckDB's C++ engine at build time rather than linking a system library.
`duckdb-output` is in the `default` feature set, so it is exercised by CI's
`cargo test --all-features` on every platform.

GitHub's `windows-latest` runner moved to Visual Studio 2026, whose MSVC 14.51
toolset **removed `stdext::checked_array_iterator`**. The DuckDB engine bundled by
`duckdb` 1.10501.0 (engine 1.5.1) vendors an old `fmt` whose `format.h:326` still
declares `checked_ptr = stdext::checked_array_iterator<T*>`. The C++ compile of
`libduckdb-sys` therefore fails on the new MSVC with `C2653` ("'stdext' is not a
class or namespace name") and a cascade of syntax errors, reddening the
`test (windows-latest)` job. macOS/Linux (clang) are unaffected, so the failure is
Windows-MSVC-specific.

The manifest requirement `^1.4.4` already *allowed* a fixed version, but the
committed `Cargo.lock` (batteries-included repos commit the lock —
[ADR 0002](0002-batteries-included-remote-opt-in.md) and the fleet lock rule) held
CI at the broken 1.10501.0. This is the classic "lock behind the requirement"
staleness layer: a green-looking requirement with a broken resolved version.

## Decision

1. **Bump the lock and raise the manifest floor to the first fixed release.** DuckDB
   dropped the removed `stdext` usage in PR #23261 / #23239, shipped in engine 1.5.5
   = crate **1.10505.0**. `Cargo.toml` pins `duckdb = { version = "1.10505.0",
   features = ["bundled"], optional = true }` with an inline comment recording the
   MSVC 14.51 cause, and `Cargo.lock` is updated to match (commit `4233c08`,
   branch `fix/windows-ci-duckdb-msvc-fmt`).
2. **Fix the cause, do not suppress the signal.** The build break is repaired by
   moving to the fixed dependency — not by skipping the `duckdb-output` test on
   Windows, dropping the feature from `--all-features`, or excluding the runner
   (fleet "Root-Cause Over Suppression"). The floor is verified against the bundled
   sources: 1.10501.0's `format.h` contains the removed symbol at line 326 (matching
   the CI error line); 1.10505.0's `format.h` has zero references.
3. **Scope is the app only.** `duckdb-output` is a `blazehash` (app) feature; the
   published `blazehash-core` library has no `duckdb` dependency, so this floor does
   not touch the engine's MSRV or its downstream compatibility promise
   ([ADR 0001](0001-lean-core-full-app-split.md),
   [ADR 0006](0006-msrv-floor-vs-pinned-toolchain.md)).

## Consequences

- Windows-MSVC CI compiles `libduckdb-sys` again; `cargo test --all-features` is
  green across all three platforms.
- The floor is a lower bound, not a ceiling — Renovate/`cargo update` may advance
  `duckdb` further; the requirement only forbids regressing below the MSVC-safe
  engine.
- The decision is a dependency floor tied to a real, documented upstream toolchain
  discontinuity (a removed MSVC extension), so it is a domain fact, not an arbitrary
  pin: it may be revisited only if DuckDB's minimum-supported MSVC changes again.
- *State note: the floor bump lands via commit `4233c08` on branch
  `fix/windows-ci-duckdb-msvc-fmt`; on `main` at the time of writing `Cargo.toml`
  still reads the pre-fix `duckdb = "1.4.4"`. This ADR records the decision; the two
  changes converge when both branches merge.*
