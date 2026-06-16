# blazehash-core

[![Crates.io](https://img.shields.io/crates/v/blazehash-core.svg)](https://crates.io/crates/blazehash-core)
[![Docs.rs](https://docs.rs/blazehash-core/badge.svg)](https://docs.rs/blazehash-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](../LICENSE)

**The lean hash-algorithm engine behind [`blazehash`](https://crates.io/crates/blazehash) — 27 hash, checksum, and fuzzy algorithms with no heavy dependencies.**

Add it and hash bytes with any supported algorithm in two lines:

```rust
use blazehash_core::algorithm::{hash_bytes, Algorithm};

let digest = hash_bytes(Algorithm::Blake3, b"hello world");
println!("{digest}"); // 64-hex-char BLAKE3 digest
```

## What's in here

- **`algorithm`** — the [`Algorithm`](https://docs.rs/blazehash-core/latest/blazehash_core/algorithm/enum.Algorithm.html) enum,
  [`hash_bytes`](https://docs.rs/blazehash-core/latest/blazehash_core/algorithm/fn.hash_bytes.html), and parsing/naming helpers.
- **`fuzzy`** — ssdeep and tlsh fuzzy hashers plus similarity scoring.

Cryptographic hashes (BLAKE3, SHA-1/2/3, MD5, Tiger, Whirlpool, BLAKE2, SM3,
Streebog, RIPEMD-160, SHAKE, KangarooTwelve), non-cryptographic checksums
(CRC32C, CRC64, XXH3, Adler-32), and fuzzy hashes (ssdeep, tlsh) are all
covered.

This crate is the dependency-lean half of the `blazehash` workspace: it pulls
in only the hashing crates — no GPU, cloud, database, YARA, TUI, CLI, or
signing machinery. Reach for the full [`blazehash`](https://crates.io/crates/blazehash)
crate (and the `blazehash` binary) when you want the batteries-included
forensic file hasher.

[Privacy Policy](https://securityronin.github.io/blazehash/privacy/) · [Terms of Service](https://securityronin.github.io/blazehash/terms/) · © 2026 Security Ronin Ltd
