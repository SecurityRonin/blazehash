# blazehash — Product Requirements

*Reverse-written from the shipped code, README, and git history (2026-07-24). Every
current-state claim is grounded in a same-session read of `Cargo.toml`, `src/`, and
`docs/`. The load-bearing engineering decisions live as ADRs
[0001](decisions/0001-lean-core-full-app-split.md)–[0011](decisions/0011-duckdb-msvc-fmt-floor.md)
under [`docs/decisions/`](decisions/). Product tier: blazehash ships a binary an
examiner runs (the `blazehash` CLI, plus a `tui` mode and an `mcp` server), so it
carries a full PRD per the fleet PRD & ADR standard.*

## Executive Summary

**blazehash is a drop-in superset of hashdeep for the modern forensic examiner.**
Every hashdeep flag and output format works unchanged, so existing scripts keep
running; on top of that the distributed static binary adds BLAKE3 by default, 25+
hash/checksum/fuzzy algorithms, manifest signing (Ed25519 and post-quantum
CRYSTALS-Dilithium), Merkle tamper-evidence seals, EWF/E01 image verification, and
SQLite/Parquet/DuckDB output — its `default` feature set. Further overlays —
Bitcoin-anchored (OpenTimestamps) timestamps, YARA scanning with ATT&CK
enrichment, NSRL known-good filtering, and native cloud/remote storage — are
named Cargo features *outside* `default`; the release pipeline builds
default-only (`release.yml`), so they reach a user only in a build made with those
features enabled.

The product answers one question an evidence hash must answer completely: given a
file or a tree, produce a manifest that proves **what** (cryptographic hashes),
**who** (a signature), **when** (a blockchain timestamp), **structure** (a Merkle
root over every file), and **context** (case/examiner metadata), and lets a second
party verify all of it weeks or months later.

It ships as two crates: the lean `blazehash-core` engine (hash algorithms only,
linkable by other fleet crates) and the full `blazehash` application
([ADR 0001](decisions/0001-lean-core-full-app-split.md)).

## Problem & Users

hashdeep is the forensic community's trusted recursive hasher, but it stops at
hashing: it produces a manifest of hashes and audits against one. A modern
examiner's evidence-integrity workflow needs more from the same pass — a signed,
timestamped, tamper-evident manifest that stands up months later; threat-hunting
overlays (known-good filtering, YARA, entropy); and the ability to hash data that
lives in S3 or Google Drive, not only on a local disk. Today that means stitching
several tools together, each with its own manifest format and no shared chain of
custody.

**Primary users:**

- **DFIR analysts / incident responders** acquiring and verifying evidence, who
  need a court-defensible manifest (case/examiner metadata, signature, timestamp)
  from one command and drop-in compatibility with their hashdeep-based tooling.
- **Threat hunters** sweeping a mounted image or live tree for known-bad files,
  YARA matches, and high-entropy (packed/encrypted) content.
- **Fleet developers** who link `blazehash-core` for a hash primitive without the
  application's heavy dependency graph.

## What It Does

Grounded in `src/` and `src/cli.rs`:

- **Recursive, parallel hashing** with memory-mapped and direct (uncached) I/O
  (`src/hash.rs`), across 25+ algorithms — BLAKE3 (default,
  [ADR 0010](decisions/0010-blake3-default-hashdeep-superset.md)), the SHA-1/2/3,
  MD5, Tiger, Whirlpool, BLAKE2, SM3, Streebog, RIPEMD, K12, checksums
  (CRC/CRC32C/Adler), fast hashes (xxh3), and fuzzy/similarity hashes (ssdeep,
  TLSH) — the last two in `blazehash-core::fuzzy`.
- **hashdeep-compatible audit** (`-a -k`), piecewise hashing, resume, and
  `--fail-on-unknown` (`src/audit.rs`, `src/piecewise.rs`, `src/resume.rs`).
- **Chain-of-custody proofs:** Ed25519 signing (`src/signing.rs`), N-of-M
  cosigning (`src/cosign.rs`), post-quantum ML-DSA signing (`src/pq_signing.rs`,
  `pq` feature), Merkle seals + inclusion proofs (`src/merkle.rs`), and
  OpenTimestamps Bitcoin anchoring (`src/ots.rs`, `ots` feature).
- **Threat overlays:** NSRL known-good filtering and known-bad flagging
  (`src/nsrl/`, `hashdb` feature), YARA scanning with ATT&CK technique lookup
  (`src/yara_scan.rs` + `src/attack.rs`, `yara` feature;
  [ADR 0009](decisions/0009-embed-attack-table-drop-forensicnomicon-dep.md)),
  Shannon entropy, and VirusTotal batch lookup (`src/vt.rs`).
- **Forensic-image and device input:** EWF/E01 verification (`src/forensic_image/`,
  `forensic-image` feature) and raw block-device sizing (`src/device.rs`).
- **Output formats:** the hashdeep text formats plus SQLite, Parquet, DuckDB
  (`duckdb-output`, bundled engine floored for the MSVC toolchain —
  [ADR 0011](decisions/0011-duckdb-msvc-fmt-floor.md)), JSON/JSONL, STIX 2.1, and
  ECS NDJSON (`src/format/`, `src/output.rs`).
- **Remote storage:** S3/GCS/Azure and other object stores via opendal, plus HDFS, SQL, FTP/SFTP, and
  Google Drive hash-without-download (`src/remote/`, `remote` feature —
  [ADR 0002](decisions/0002-batteries-included-remote-opt-in.md)).
- **Interfaces:** the `blazehash` CLI, an interactive `tui` dashboard
  (`src/tui.rs`, `tui` feature), an `mcp` server for AI-assisted workflows
  (`src/mcp.rs`), an HTML chain-of-custody report (`report` feature), live
  monitoring (`src/watch.rs`), duplicate detection, and manifest diff/merge/update
  (`src/folder_diff.rs`, `src/manifest*.rs`).

## Scope

- Be a **strict superset of hashdeep**: every hashdeep flag and output format
  works exactly as before; existing scripts run unmodified.
- Ship **batteries-included by default**: the distributed packages compile in the
  `default` forensic capability set — hashing across 25+ algorithms, EWF/E01 image
  verification, post-quantum signing, QR, archive, and SQLite/Parquet/DuckDB
  output — so an examiner runs the common workflow with no rebuild. Heavier or
  rarely-needed capabilities (YARA, OpenTimestamps, NSRL/`hashdb`, HTML `report`,
  `tui`, and cloud/`remote` storage) are named features outside `default` and are
  not in the distributed binary
  ([ADR 0002](decisions/0002-batteries-included-remote-opt-in.md)).
- Deliver a **single static binary** installable via Homebrew, apt, winget, or
  `cargo install`, with a signed Windows MSI and reproducible release
  ([ADR 0007](decisions/0007-dual-release-pipeline.md)).
- Expose the hash algorithms as a **lean, separately-linkable library**
  (`blazehash-core`) for the rest of the fleet
  ([ADR 0001](decisions/0001-lean-core-full-app-split.md)).

## Non-Goals

- **Not a disk/filesystem forensic reader.** blazehash hashes files and verifies
  images; it does not parse NTFS/ext4/APFS structures (that is the fleet's
  `*-forensic` readers). Its EWF handling verifies image integrity, it does not
  interpret the contained filesystem.
- **Not an antivirus or a YARA engine of record.** YARA and VirusTotal are
  overlays for triage; findings are hashes/matches, not verdicts.
- **Not a cryptographic-primitive implementer.** All hashing and signing use
  audited crates (RustCrypto, BLAKE3, ed25519-dalek, ml-dsa); blazehash writes no
  hand-rolled crypto.
- **Cloud/remote storage is not in the default build.** It is an opt-in heavy
  subsystem ([ADR 0002](decisions/0002-batteries-included-remote-opt-in.md)); the
  distributed release binaries do not enable it, and building with
  `--features remote` is required to add it.

## Validation Approach

- **Algorithm correctness** rests on audited upstream crates (RustCrypto, BLAKE3,
  tlsh2) whose own test vectors are the oracle; blazehash's tests assert the wrap
  and dispatch, plus `Digest`-compatible wrappers for the XOF/checksum algorithms
  (commit `028ef1a`).
- **hashdeep parity** is validated against real hashdeep output (the README's
  performance and compatibility tables compare the two directly).
- **Integration tests** (`tests/`, `assert_cmd`) drive the CLI end-to-end,
  including signing, sealing, audit, and remote-URI parsing, with fixture archives
  written by a C-FFI-free dev-only `zip`
  ([ADR 0008](decisions/0008-pure-rust-zip-forensic-core.md)).
- **Supply-chain gates:** `cargo deny` audits the default feature set (not
  `--all-features`), so the security posture reflects what a default build ships
  ([ADR 0002](decisions/0002-batteries-included-remote-opt-in.md),
  [ADR 0004](decisions/0004-adler2-root-cause-over-suppression.md)); `cargo vet`
  runs in CI (commit `b893602`).

## Related Decisions

| ADR | Decision |
|-----|----------|
| [0001](decisions/0001-lean-core-full-app-split.md) | Lean `blazehash-core` engine split from the full `blazehash` app |
| [0002](decisions/0002-batteries-included-remote-opt-in.md) | Batteries-included default; `remote` is the one opt-in exception |
| [0003](decisions/0003-split-unsafe-posture.md) | Engine forbids `unsafe`; app carries bounded platform `unsafe` |
| [0004](decisions/0004-adler2-root-cause-over-suppression.md) | Fix advisories at the root cause (`adler` → `adler2`) |
| [0005](decisions/0005-apache-2-0-relicense.md) | Apache-2.0 relicense (patent grant) |
| [0006](decisions/0006-msrv-floor-vs-pinned-toolchain.md) | MSRV 1.88, separate from the pinned 1.96.0 dev toolchain |
| [0007](decisions/0007-dual-release-pipeline.md) | release-plz for the library, `v[0-9]*` tag for the binary |
| [0008](decisions/0008-pure-rust-zip-forensic-core.md) | Pure-Rust `zip-forensic-core` reader; dev-only `zip` for fixtures |
| [0009](decisions/0009-embed-attack-table-drop-forensicnomicon-dep.md) | Embed the ATT&CK table; no compile-time forensicnomicon dep |
| [0010](decisions/0010-blake3-default-hashdeep-superset.md) | BLAKE3 is the default algorithm; hashdeep flags still select the rest |
| [0011](decisions/0011-duckdb-msvc-fmt-floor.md) | Floor `duckdb-output` at DuckDB 1.5.5 (crate 1.10505.0) for the MSVC 14.51 fmt break |
