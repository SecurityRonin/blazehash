# 2. Batteries-included by default; `remote` cloud storage is the one opt-in exception

Date: 2026-07-24
Status: Accepted

## Context

An examiner at an evidence workstation cannot `cargo build --features …` to turn
on a capability mid-case; a feature that is not compiled in is a capability that
is not there when it matters. The fleet default (`ronin-issen/CLAUDE.md`,
"Batteries-Included — Compile Everything In") is therefore to ship every
capability in one static binary, and to fix a *gate* rather than amputate a
feature when full features trip it.

That rule carries exactly one exception: "a genuinely optional, rarely-wanted
heavy subsystem MAY be a named non-default feature as long as the shipping binary
turns it on." blazehash's cloud/object-storage backend (`opendal`, ~60 services)
is that subsystem. It drags in a transitive tree with live advisories that no
hashing workload exercises: hickory DNS (`RUSTSEC-2026-0118/0119`), quick-xml
(`RUSTSEC-2026-0194/0195`), and sqlx/tikv/rustls chains (`CHANGELOG` 0.2.6).
Commit `441cfd0` ("gate opendal cloud stack behind opt-in `remote` feature") made
the call.

## Decision

1. **`default` compiles in the forensic capability set** —
   `default = ["forensic-image", "gpu", "sqlite", "parquet-output",
   "duckdb-output", "pq", "qr", "archive"]` (`Cargo.toml` `[features]`), and the
   release pipeline builds exactly this set: `release.yml` runs
   `cargo build --release` and `cargo deb` with no `--features`. YARA, report,
   docker, ots, tui, and hashdb are additional named features *outside* `default`;
   they are not compiled into the distributed binaries and reach a user only if
   the binary is rebuilt with them enabled.
2. **`remote` is opt-in.** `remote = ["dep:opendal", "dep:tokio",
   "dep:suppaftp", "dep:ssh2"]` is *not* in `default`, and the release pipeline
   passes no `--features`, so the distributed binaries — like a plain
   `cargo build` — build remote-free and the security audit stays opendal-free.
   Enabling the cloud stack requires building with `--features remote`. The
   Linux-only `services-monoiofs` opendal target is likewise gated behind
   `remote`, so the default build pulls no cloud stack on any OS.
3. **The audit reflects what a default build ships.** `deny.toml` sets
   `all-features = false` and enumerates every feature *except* `remote` /
   `rocksdb-storage`, so `cargo deny check` audits exactly the default binary
   rather than papering over the opendal advisories with a blanket ignore
   (`CHANGELOG` 0.2.6 removed six such ignores: adler, instant, number_prefix,
   sled, sqlx, indicatif).
4. **Non-`opendal` remote protocols use lighter, cross-platform crates**:
   FTP/FTPS via blocking `suppaftp` (rustls), SFTP via vendored `ssh2`/libssh2 —
   chosen to avoid opendal's async-tls conflicts and Unix-only openssh crate
   (`Cargo.toml` comments; commit `3cec42e`).

## Consequences

- The default `cargo build`, the distributed binaries, and the CI security gate
  carry no cloud-storage advisory surface; `--features remote` adds
  S3/GCS/Azure/SFTP/60+ backends for anyone who builds with it.
- The README feature table still lists `remote` as "on"; that row is stale
  relative to `Cargo.toml` (the feature moved to opt-in in 0.2.6) and should be
  corrected — noted here so the discrepancy is not mistaken for a second decision.
- Adding a capability to the `default` set benefits every packaged install at
  once; a capability left as a non-default feature reaches users only if they
  rebuild with it enabled.
