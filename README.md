# blazehash

[![Crates.io](https://img.shields.io/crates/v/blazehash.svg)](https://crates.io/crates/blazehash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml)
[![Release](https://github.com/SecurityRonin/blazehash/actions/workflows/release.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/releases)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**The hashdeep you've been waiting for.**

BLAKE3 at 1,640 MB/s — 2.8× hashdeep's ceiling. GPU-accelerated SHA-256. Ed25519-signed chain of custody. EWF/E01 image verification. Drop-in compatible.

```bash
blazehash -r /mnt/evidence -c blake3,sha256 -o manifest.hash --sign
```

**[Full documentation](https://securityronin.github.io/blazehash/)**

---

## Install

### Cargo (all platforms)

```bash
cargo install blazehash
```

### macOS

```bash
brew tap SecurityRonin/tap && brew install blazehash
```

### Debian / Ubuntu / Kali

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/securityronin/blazehash/setup.deb.sh' | sudo bash
sudo apt install blazehash
```

### Windows

```powershell
winget install SecurityRonin.blazehash
```

---

## Quick Start

**Hash a folder and save the results:**

```bash
blazehash -r /path/to/folder -o manifest.hash
```

**Check if anything changed:**

```bash
blazehash -r /path/to/folder -a -k manifest.hash
```

**Sign the manifest for chain of custody:**

```bash
blazehash sign manifest.hash
```

**[See the full docs](https://securityronin.github.io/blazehash/)** for getting started, CLI reference, real-world recipes, and more.

---

## Feature Comparison

### Beyond hashdeep's scope

Features not available in hashdeep that blazehash adds.

| Feature | Notes |
|---------|-------|
| **EWF / E01 image verification** | Verify forensic images acquired with FTK Imager, EnCase, or similar — `blazehash --verify-image evidence.E01` |
| **Resume interrupted runs** | Pick up where you left off on a 4 TB acquisition without starting over |
| **NTFS Alternate Data Streams** | Hash ADS alongside main file content on Windows (`--ads`) |
| **Manifest signing (Ed25519)** | Cryptographic proof of chain of custody, self-contained in the manifest |
| **Folder diff** | Compare two directory trees by content, size+time, or name |

### Parity with hashdeep

Everything you already rely on works as-is. Your scripts need no changes.

| Feature | blazehash | hashdeep |
|---------|:---------:|:--------:|
| Audit mode (`-a -k`) | Y | Y |
| Piecewise hashing (`-p`) | Y | Y |
| hashdeep-compatible output | Y | Y |
| DFXML / CSV / JSON output | Y | partial |
| MD5 / SHA-1 / SHA-256 / Tiger / Whirlpool | Y | Y |

### Additional capabilities

| Feature | Notes |
|---------|-------|
| BLAKE3 (default) | ~1,640 MB/s; not in hashdeep |
| GPU-accelerated SHA-256 / MD5 | Automatic when hardware is available |
| NSRL known-good filtering | `--nsrl` with SQLite or Bloom filter — **see warning below** |
| Fuzzy / similarity hashing | ssdeep + TLSH; useful for variant detection |
| Duplicate detection | `blazehash dedup` |
| Direct I/O (no page cache) | `--no-cache`; preserves RAM on large acquisitions |
| MCP server | `blazehash mcp` for AI-assisted forensic workflows |

> **Bloom filter warning — read before using `--nsrl` with a `.bloom` file.**
> Bloom filters are probabilistic: they guarantee no false negatives (a known-good
> file is never reported as unknown) but they **can produce false positives**
> (an unknown file may be silently excluded as if it were known-good).
> False positive rate depends on filter size and hash count — the default build
> targets 0.1% FPR, meaning roughly 1 in 1,000 unknown files may be suppressed.
> **Never use a Bloom filter when completeness is required** — use the SQLite
> index (`--nsrl file.db`) instead. The `.bloom` format is provided for memory-
> constrained environments only.

---

## Performance

Measured on Apple M4 Pro, macOS 15.7.5, warm cache, n=7 runs.
Full methodology and raw data: **[docs/benchmarks.md](docs/benchmarks.md)**.

### Large files — where blazehash is faster

| Workload | blazehash | hashdeep | Speedup |
|----------|----------:|----------:|--------:|
| 1 GiB, SHA-256 | 2,182 ms | 2,485 ms | **1.14x** |
| 1 GiB, MD5 | 1,447 ms | 2,135 ms | **1.48x** |
| 1 GiB, SHA-1 | 879 ms | 1,803 ms | **2.05x** † |
| 1 GiB, BLAKE3 | 655 ms | *not supported* | — |

† SHA-1 advantage relies on ARM NEON instructions (`sha1c/sha1m/sha1p`) on
Apple Silicon and will not reproduce on x86-64.

### Small files — where hashdeep is faster

| Workload | blazehash | hashdeep | Speedup |
|----------|----------:|----------:|--------:|
| 100 × 2 KiB, SHA-256 | 268 µs/file | 137 µs/file | **0.51x** |
| 1,000 × 2 KiB, SHA-256 | 70 µs/file | 51 µs/file | **0.73x** |
| 5,000 × 2 KiB, SHA-256 | 49 µs/file | 39 µs/file | **0.78x** |

Rayon thread dispatch costs ~20-40 µs per file, which dominates for 2 KiB
files. For many-small-file triage workloads, hashdeep's single-threaded C loop
has lower overhead. This is a documented limitation.

### BLAKE3 vs hashdeep's fastest

hashdeep's best algorithm on this hardware is SHA-1 at 595 MB/s.
blazehash's BLAKE3 runs at **1,640–1,780 MB/s** — 2.8× faster and
cryptographically stronger, with no length-extension vulnerability.

---

## Why This Exists

[hashdeep](https://github.com/jessek/hashdeep) — written by Jesse Kornbluth and Simson Garfinkel — gave the forensic community its canonical file hashing and audit tool. Court-tested workflows have depended on it for over a decade. It is public domain, auditable, and honest.

**blazehash** is a continuation, not a replacement. Every hashdeep flag works as expected. The output format is compatible. Your existing scripts keep working. We add what the community needs next: BLAKE3, EWF image verification, manifest signing, NSRL filtering, fuzzy hashing, deduplication, and more.

---

## Acknowledgements

**Jesse Kornbluth** created [hashdeep](https://github.com/jessek/hashdeep) and gave it to the forensic community as a public domain tool.

**Simson Garfinkel** co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML standard.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn.

## Author

**Albert Hui** ([@h4x0r](https://github.com/h4x0r)) · [@SecurityRonin](https://github.com/SecurityRonin)

## License

[MIT License](LICENSE)
