# 3. Split `unsafe` posture — the engine forbids it, the app carries bounded platform `unsafe`

Date: 2026-07-24
Status: Accepted

## Context

The fleet default is `unsafe_code = "forbid"` (`ronin-issen/CLAUDE.md`, "Rust Lint
Posture" and the "`unsafe` Is an Avoidable Cost-Benefit Exception" law): a
provable "zero places a crafted input can corrupt memory," downgraded to `deny` +
a bounded per-site `#[allow]` only when a real benefit justifies it.

blazehash has two very different bodies of code. The hash engine
(`blazehash-core`) is pure computation over byte slices — no OS handles, no
memory mapping, no FFI. The application, by contrast, needs OS-level machinery a
forensic hasher genuinely benefits from: memory-mapped and direct (uncached) I/O
for throughput, a libc `ioctl` to read a block device's sector size, and Windows
syscalls to enumerate the MFT and alternate data streams. Those are not
expressible in safe Rust.

## Decision

1. **`blazehash-core` forbids `unsafe`.** The workspace declares
   `[workspace.lints.rust] unsafe_code = "forbid"` (`Cargo.toml`), and
   `core/Cargo.toml` opts in with `[lints] workspace = true`. The engine is
   therefore provably free of memory-unsafe code.
2. **The `blazehash` app does not inherit that lint** — the root `[package]` has
   no `[lints] workspace = true` — because it legitimately needs bounded `unsafe`:
   - `src/hash.rs`: `memmap2::Mmap::map`, raw direct-I/O buffers, and
     `libc::fcntl(F_NOCACHE)` for high-throughput hashing.
   - `src/folder_diff.rs`: `memmap2::Mmap::map`.
   - `src/device.rs`: `libc::ioctl(BLKSSZGET)` for device sector size.
   - `src/walk_windows_mft.rs` / `src/ads.rs`: Windows `FindFirstStreamW`,
     MFT/`$MFT` handle reads, and `ShellExecuteExW` via `windows-sys`.
   Each is a small, pure-Rust-or-thin-FFI block at the OS boundary, matching the
   "pure-Rust bounded unsafe for perf is accepted far more readily than a C-FFI
   chain" trade-off in the constitution.
3. **This is not a `*-core`/`*-forensic` untrusted-image parser.** The Paranoid
   Gatekeeper `forbid`/fuzz mandate targets crates that parse attacker-controlled
   disk images; blazehash consumes files to hash, and the memory-unsafe surface is
   OS I/O, not format parsing. The engine that *is* pure computation carries the
   `forbid` guarantee; the app carries the I/O `unsafe`.

## Consequences

- `blazehash-core` can wear a genuine `unsafe_code = forbid` posture and can be
  linked by fleet libraries that require it.
- The app is honestly **not** `forbid(unsafe)`; per the fleet README badge rule it
  must not claim the "unsafe-forbidden" badge for the binary — the accurate
  statement is "engine forbids unsafe; app uses bounded OS-level unsafe."
- Should the app's `unsafe` sites need auditing, they are enumerable by
  `rg 'unsafe' src/` and are confined to the five modules above.
