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

| Feature | blazehash | hashdeep | b3sum | sha256sum |
|---------|:---------:|:--------:|:-----:|:---------:|
| Audit mode | Y | Y | — | — |
| Manifest signing (Ed25519) | Y | — | — | — |
| Manifest diff | Y | — | — | — |
| Duplicate detection | Y | — | — | — |
| NSRL known-good filtering | Y | — | — | — |
| Fuzzy / similarity hashing | Y | — | — | — |
| Piecewise hashing | Y | Y | — | — |
| Resume interrupted runs | Y | — | — | — |
| EWF / E01 image verification | Y | — | — | — |
| NTFS ADS hashing | Y | — | — | — |
| MCP server (AI-assisted) | Y | — | — | — |
| Multithreaded hashing | Y | — | Y | — |
| GPU acceleration | Y | — | — | — |
| Direct I/O (no page cache) | Y | — | — | — |
| BLAKE3 | Y | — | Y | — |
| 14 algorithms simultaneous | Y | — | — | — |
| hashdeep / DFXML / CSV / JSON | Y | partial | — | — |

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

But hashdeep hasn't had a release since v4.4. It doesn't support BLAKE3, NTFS ADS, or EWF images. It has no manifest signing, no NSRL filtering, no fuzzy hashing, no deduplication, no MCP server.

**blazehash** is a continuation, not a replacement. Every hashdeep flag works as expected. The output format is compatible. Your existing scripts keep working. We add what the community needs.

---

## Acknowledgements

**Jesse Kornbluth** created [hashdeep](https://github.com/jessek/hashdeep) and gave it to the forensic community as a public domain tool.

**Simson Garfinkel** co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML standard.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn.

## Author

**Albert Hui** ([@h4x0r](https://github.com/h4x0r)) · [@SecurityRonin](https://github.com/SecurityRonin)

## License

[MIT License](LICENSE)
