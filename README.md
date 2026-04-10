# blazehash

[![Crates.io](https://img.shields.io/crates/v/blazehash.svg)](https://crates.io/crates/blazehash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml)
[![Release](https://github.com/SecurityRonin/blazehash/actions/workflows/release.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/releases)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Forensic file hashing for the modern era.** BLAKE3 by default. Multithreaded. Memory-mapped. [Up to 3.4× faster](docs/benchmarks.md) than hashdeep — and [~5× faster](docs/benchmarks.md#the-blake3-advantage) when you switch to BLAKE3.

Point this at a folder. Get a cryptographically verified manifest. Sign it. Done.

```bash
blazehash -r /mnt/evidence -c blake3,sha256 -o manifest.hash --sign
```

```
blazehash v0.3.0 — BLAKE3 + SHA-256, 16 threads, mmap I/O
[*] Scanning /mnt/evidence recursively
[+] 847,293 files hashed (2.14 TiB) in 38.7s
[+] Manifest written to manifest.hash
[+] Public key: a3f8e2... (record this for verification)
[+] Signature:  manifest.hash.sig
```

---

## Table of Contents

- [Install](#install)
- [Quick Start](#quick-start)
- [Core Workflows](#core-workflows)
  - [Hash a folder](#hash-a-folder)
  - [Verify nothing changed](#verify-nothing-changed-audit)
  - [Sign your manifest](#sign-your-manifest)
  - [Verify a signature](#verify-a-signature)
- [Filtering Files](#filtering-files)
- [Output Formats](#output-formats)
- [Find Duplicates](#find-duplicates-dedup)
- [Compare Two Manifests](#compare-two-manifests-diff)
- [NSRL Known-Good Filtering](#nsrl-known-good-filtering)
- [Fuzzy / Similarity Hashing](#fuzzy--similarity-hashing)
- [Forensic Disk Images](#forensic-disk-images)
- [Advanced](#advanced)
- [MCP Server](#mcp-server)
- [Algorithms](#algorithms)
- [Feature Comparison](#feature-comparison)
- [Performance](#performance)
- [Why This Exists](#why-this-exists)
- [Acknowledgements](#acknowledgements)

---

## Install

### Debian / Ubuntu / Kali

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/securityronin/blazehash/setup.deb.sh' | sudo bash
sudo apt install blazehash
```

### macOS

```bash
brew tap SecurityRonin/tap && brew install blazehash
```

### Windows

```powershell
winget install SecurityRonin.blazehash
```

Or download the `.msi` from [GitHub Releases](https://github.com/SecurityRonin/blazehash/releases).

### Cargo (all platforms)

```bash
cargo install blazehash
```

---

## Quick Start

**Not a forensics expert? Start here.** Three commands cover 90% of use cases.

### 1. Hash a folder and save the results

```bash
blazehash -r /path/to/folder -o manifest.hash
```

This walks the folder recursively, hashes every file with BLAKE3, and writes a `manifest.hash` file listing each file's path, size, and hash. Takes seconds on modern hardware.

### 2. Check if anything changed

```bash
blazehash -r /path/to/folder -a -k manifest.hash
```

`-a` is audit mode. It re-hashes the folder and compares against your saved manifest. Exit code 0 means everything matches. Exit code 1 means something changed — and the output tells you exactly what.

### 3. Sign the manifest so others can verify it came from you

```bash
blazehash sign manifest.hash
```

You'll be prompted for a password. The same password always produces the same signing key — no key files to manage. The public key is printed to the screen; record it for chain-of-custody.

```
[+] Public key: a3f8e2c1d4b7... ← write this down
[+] Signature:  manifest.hash.sig
```

> **What just happened?** blazehash used your password to derive an Ed25519 signing key (via Argon2id), signed the manifest, and wrote a `.sig` file alongside it. Anyone with your public key can verify the manifest hasn't been tampered with.

---

## Core Workflows

### Hash a folder

```bash
# BLAKE3 only (fastest, default)
blazehash -r /mnt/evidence

# Multiple algorithms at once
blazehash -r /mnt/evidence -c blake3,sha256,md5

# Save to a file
blazehash -r /mnt/evidence -c blake3 -o results.hash

# Hash and sign in one step
blazehash -r /mnt/evidence -c blake3 -o results.hash --sign
```

### Hash from stdin

```bash
cat suspicious.bin | blazehash --stdin -c sha256,md5
```

Useful when piping data through another tool before hashing.

### Verify nothing changed (audit)

```bash
# Basic audit
blazehash -r /mnt/evidence -a -k known.hash

# Auto-detect the manifest (looks for *.hash in current directory)
blazehash -r /mnt/evidence -a
```

Audit output uses hashdeep-compatible prefixes:
```
[ok] /evidence/document.pdf         — hash matches
[!]  /evidence/tampered.docx        — hash CHANGED
[-]  /evidence/deleted.png          — file MISSING
[+]  /evidence/new_file.exe         — file ADDED (not in manifest)
[*]  /evidence/moved.txt            — file MOVED (same hash, different path)
[~]  /evidence/variant.exe          — FUZZY MATCH sim=87% (similar, not identical)
```

### Sign your manifest

```bash
# Sign a specific manifest
blazehash sign manifest.hash

# The BLAZEHASH_SIGN_PASSWORD env var skips the prompt (for CI/scripts)
BLAZEHASH_SIGN_PASSWORD=secret blazehash sign manifest.hash
```

> **How signing works:** Your password is fed through Argon2id (a memory-hard key derivation function) with a fixed application salt to produce a 32-byte Ed25519 seed. Same password → same key, every time, on any machine. No key files to store or transfer.

### Verify a signature

```bash
blazehash verify-sig manifest.hash --expected-pubkey a3f8e2c1d4b7...
```

Exit code 0 = valid. Exit code 1 = tampered or wrong key.

```
[+] Signature valid — manifest.hash
```

**Audit auto-verifies** when you supply `--expected-pubkey`:

```bash
blazehash -r /mnt/evidence -a -k manifest.hash --expected-pubkey a3f8e2c1d4b7...
```

If `manifest.hash.sig` exists and the signature is invalid, audit aborts before comparing any hashes. Use `--ignore-sig` to skip this check.

---

## Filtering Files

Control which files get hashed without changing your directory structure.

```bash
# Only files larger than 1 MB
blazehash -r /mnt/evidence --min-size 1M

# Only files smaller than 100 MB
blazehash -r /mnt/evidence --max-size 100M

# Only files modified after a date
blazehash -r /mnt/evidence --newer 2024-01-01

# Only hash specific file types (glob patterns)
blazehash -r /mnt/evidence --include "*.exe" --include "*.dll"

# Exclude log files and temp directories
blazehash -r /mnt/evidence --exclude "*.log" --exclude "**/.tmp/*"

# Combine filters
blazehash -r /mnt/evidence --include "*.docx" --newer 2024-06-01 --min-size 10K
```

Glob patterns support `**` for recursive matching: `--exclude "logs/**"` excludes everything under any `logs/` directory.

---

## Output Formats

```bash
# hashdeep format (default) — compatible with hashdeep, audit-ready
blazehash -r /mnt/evidence --format hashdeep -o manifest.hash

# DFXML — Digital Forensics XML, Autopsy-compatible
blazehash -r /mnt/evidence --format dfxml -o report.xml

# sha256sum / md5sum — compatible with sha256sum(1) and md5sum(1)
blazehash -r /mnt/evidence -c sha256 --format sha256sum -o hashes.sha256
blazehash -r /mnt/evidence -c md5   --format sha256sum -o hashes.md5

# CSV — for spreadsheets and databases
blazehash -r /mnt/evidence --format csv -o results.csv

# JSON / JSONL — for programmatic processing
blazehash -r /mnt/evidence --format json  -o results.json
blazehash -r /mnt/evidence --format jsonl -o results.jsonl
```

> **DFXML** (Digital Forensics XML) is the format used by Autopsy, The Sleuth Kit, and other forensic platforms. Use it when importing results into case management software.

### Raw / DD sidecar verification

Forensic disk images acquired with `dd` or similar tools often ship with `.md5`, `.sha256`, or `.sha512` sidecar files. blazehash verifies them automatically:

```bash
blazehash --verify-image disk.raw
# Looks for disk.md5, disk.sha256, disk.sha512, disk.blake3 alongside disk.raw
```

---

## Find Duplicates (dedup)

```bash
# Find duplicate files in a directory
blazehash dedup /mnt/evidence

# Find duplicates across a saved manifest
blazehash dedup manifest.hash

# Print only the redundant copies (safe to delete — canonical copy is kept)
blazehash dedup /mnt/evidence --dedup-dupes

# Print one representative per group (what to keep)
blazehash dedup /mnt/evidence --dedup-unique
```

Exit code 0 = no duplicates. Exit code 1 = duplicates found.

```
## 3 copies:
  /evidence/file_a.bin
  /evidence/backup/file_a.bin    ← redundant
  /evidence/copy2/file_a.bin     ← redundant

[+] 1,247 files — 1,244 unique, 1 duplicate group, 2 redundant copies (0.3 GiB reclaimable)
```

---

## Compare Two Manifests (diff)

```bash
# What changed between two hashing sessions?
blazehash diff before.hash after.hash

# Auto-detect manifests (finds *.hash in current directory)
blazehash diff
```

Output:
```
[+] /evidence/new_file.exe          — ADDED
[-] /evidence/deleted_file.pdf      — REMOVED
[!] /evidence/tampered.docx         — MODIFIED
[*] /evidence/renamed.txt           — MOVED (was: /evidence/original.txt)
```

Exit code 0 = identical. Exit code 1 = differences found.

---

## NSRL Known-Good Filtering

The [NIST National Software Reference Library](https://www.nist.gov/system-and-organization-controls-assessments/national-software-reference-library) (NSRL) catalogs hashes of known-good software files (OS, applications). Filtering them out lets analysts focus on files that actually need examination.

```bash
# Annotate known-good files with [K]
blazehash -r /mnt/evidence -c sha256 --nsrl NSRL.db

# Remove known-good files from output entirely
blazehash -r /mnt/evidence -c sha256 --nsrl NSRL.db --nsrl-exclude

# Use a pre-built bloom filter for faster lookups
blazehash -r /mnt/evidence -c sha256 --nsrl nsrl.bloom

# Build a bloom filter from the NSRL SQLite database (one-time setup)
blazehash nsrl build-bloom NSRL.db --output nsrl.bloom
```

> **Bloom filters** are probabilistic data structures — very fast and compact, with a tiny false-positive rate (0.1% by default). If you use `--nsrl-exclude` with a bloom filter, blazehash warns you that evidence might be suppressed due to false positives. Use the SQLite database for exclusion in production.

```
[K] /Windows/System32/ntdll.dll   (NSRL known-good)
[K] /Windows/System32/kernel32.dll (NSRL known-good)
[K] 2,847 files matched NSRL — focusing on 412 remaining files
```

---

## Fuzzy / Similarity Hashing

Fuzzy hashes detect *similar* files — malware variants, modified documents, partially overwritten data — where cryptographic hashes would show a complete mismatch.

```bash
# Compute ssdeep alongside BLAKE3
blazehash -r /evidence -c blake3,ssdeep

# Compute both fuzzy algorithms
blazehash -r /evidence -c ssdeep,tlsh

# Find fuzzy matches in audit mode
blazehash -r /evidence -a -k known.hash -c ssdeep --fuzzy-threshold 70

# Show top 3 matches per suspicious file
blazehash -r /evidence -a -k known.hash -c ssdeep --fuzzy-top 3
```

Fuzzy matches appear as `[~]` in audit output:
```
[~] payload.exe  FUZZY MATCH sim=87%  ← malware/variant_a.exe
[~] modified.docx  FUZZY MATCH sim=94%  ← original.docx
```

| Algorithm | Best for |
|-----------|----------|
| ssdeep | Detecting file fragments, near-duplicate documents, malware variants |
| tlsh | Larger files (>50 bytes), better locality sensitivity |

---

## Forensic Disk Images

### E01 / EWF images

```bash
# Verify an EnCase E01 image (compares stored hashes against recomputed)
blazehash --verify-image case.E01

# Multi-segment images work automatically
blazehash --verify-image case.E01   # finds case.E01, case.E02, case.E03 ...
```

Supports E01, Ex01, L01, and Lx01 formats.

### Raw / DD images with sidecar files

```bash
# Verify using sidecar hash files produced by dc3dd, FTK, or similar
blazehash --verify-image disk.raw
# Automatically checks disk.md5, disk.sha256, disk.sha512, disk.blake3
```

---

## Advanced

### New algorithms: CRC32C, XXH3, SHAKE

```bash
# CRC32C — ultra-fast non-cryptographic checksum (storage integrity)
blazehash -r /mnt/data -c crc32c

# XXH3-128 — extremely fast, 128-bit non-cryptographic hash
blazehash -r /mnt/data -c xxh3

# SHAKE-128 — extendable-output XOF, 256-bit output
blazehash -r /mnt/data -c shake128

# SHAKE-256 — extendable-output XOF, 512-bit output
blazehash -r /mnt/data -c shake256
```

> **Note:** CRC32C, XXH3, and SHAKE variants are not included in hashdeep-compatible manifests by default because they aren't part of hashdeep's algorithm set. Use them for integrity checking within blazehash workflows.

### Direct I/O — bypass the OS page cache

```bash
blazehash -r /mnt/evidence --no-cache
```

Reads directly from disk without touching the OS cache. Forensic use case: hashing a live system without disturbing in-memory evidence. Uses `F_NOCACHE` on macOS, `O_DIRECT` on Linux, `FILE_FLAG_NO_BUFFERING` on Windows.

### NTFS Alternate Data Streams (Windows)

```bash
blazehash -r C:\Evidence --ads
```

Hashes NTFS Alternate Data Streams alongside the main file content. No-op on non-Windows systems. Useful for finding hidden data embedded in ADS.

### Resume interrupted runs

```bash
blazehash -r /mnt/evidence -o manifest.hash --resume
```

Reads the partial manifest, skips already-hashed files, continues where it left off. Essential for multi-terabyte acquisitions.

### Piecewise / chunk hashing

```bash
blazehash -r /mnt/evidence -p 1G
```

Each file produces one hash entry per chunk. Useful for verifying partial transfers or detecting targeted modifications within large files.

### Size-only mode (fast pre-scan)

```bash
blazehash -r /mnt/evidence -s
```

Lists files with sizes, no hashing. Useful for a quick inventory before committing to a full hash run.

### GPU-accelerated hashing

When compiled with the `gpu` feature, blazehash auto-offloads SHA-256 and MD5 to the GPU for large files. Calibrate first:

```bash
blazehash bench --gpu               # measure GPU vs CPU crossover, write config
blazehash bench --gpu --no-calibrate  # use conservative defaults
blazehash -r /mnt/evidence -c sha256 --no-gpu  # force CPU
```

---

## MCP Server

The `blazehash mcp` command starts an [MCP](https://modelcontextprotocol.io/) server for AI-assisted forensic hashing. Connect it to Claude, Cursor, or any MCP-compatible AI agent.

```bash
# Register with Claude Code
claude mcp add blazehash -- blazehash mcp
```

```json
// Claude Desktop: claude_desktop_config.json
{
  "mcpServers": {
    "blazehash": {
      "command": "blazehash",
      "args": ["mcp"]
    }
  }
}
```

| Tool | Description |
|------|-------------|
| `blazehash_hash` | Hash files/directories (default: BLAKE3) |
| `blazehash_audit` | Audit files against a manifest — detect changes, moves, missing files |
| `blazehash_verify_image` | Verify forensic disk image integrity (E01/EWF) |
| `blazehash_algorithms` | List all supported hash algorithms |
| `blazehash_hash_bytes` | Hash raw inline data (hex or base64) |

---

## Algorithms

| Algorithm | Flag | Default | Type | Notes |
|-----------|------|:-------:|------|-------|
| BLAKE3 | `blake3` | **Y** | Cryptographic | Fastest secure hash; NEON/AVX-512/AVX2 |
| SHA-256 | `sha256` | — | Cryptographic | NIST standard; court-accepted everywhere |
| SHA-512 | `sha512` | — | Cryptographic | Faster than SHA-256 on 64-bit CPUs |
| SHA-3-256 | `sha3-256` | — | Cryptographic | Keccak sponge; post-quantum basis |
| SHA-1 | `sha1` | — | Cryptographic | **Legacy only** — broken since SHAttered (2017) |
| MD5 | `md5` | — | Cryptographic | **Legacy only** — collisions trivial since 2004 |
| Tiger | `tiger` | — | Cryptographic | hashdeep compatibility; 192-bit |
| Whirlpool | `whirlpool` | — | Cryptographic | hashdeep compatibility; 512-bit |
| SHAKE-128 | `shake128` | — | Cryptographic XOF | 256-bit fixed output |
| SHAKE-256 | `shake256` | — | Cryptographic XOF | 512-bit fixed output |
| CRC32C | `crc32c` | — | Non-cryptographic | Fast storage integrity check; not for evidence |
| XXH3-128 | `xxh3` | — | Non-cryptographic | Extremely fast 128-bit hash; not for evidence |
| ssdeep | `ssdeep` | — | Fuzzy / similarity | CTPH; detects near-duplicates and variants |
| tlsh | `tlsh` | — | Fuzzy / similarity | Locality-sensitive; better for large files |

**Choosing an algorithm:**

- **Court submission** — `sha256` is universally accepted; add `blake3` for speed
- **Speed-first** — `blake3` alone saturates NVMe on a single thread
- **hashdeep compatibility** — `md5,sha256` (or `md5,sha1,sha256,tiger,whirlpool`)
- **Similarity detection** — add `ssdeep` or `tlsh` alongside your crypto hash
- **Storage checksums** — `crc32c` or `xxh3` (not for evidence integrity)

---

## Feature Comparison

### Forensic Features

| Feature | blazehash | hashdeep | b3sum | sha256sum |
|---------|:---------:|:--------:|:-----:|:---------:|
| Audit mode | ✓ | ✓ | — | — |
| Manifest signing (Ed25519) | ✓ | — | — | — |
| Manifest diff | ✓ | — | — | — |
| Duplicate detection | ✓ | — | — | — |
| NSRL known-good filtering | ✓ | — | — | — |
| Fuzzy / similarity hashing | ✓ | — | — | — |
| Piecewise hashing | ✓ | ✓ | — | — |
| Resume interrupted runs | ✓ | — | — | — |
| Recursive hashing | ✓ | ✓ | — | — |
| EWF / E01 image verification | ✓ | — | — | — |
| Raw/DD sidecar verification | ✓ | — | — | — |
| NTFS ADS hashing | ✓ | — | — | — |
| MCP server (AI-assisted) | ✓ | — | — | — |

### Performance

| Feature | blazehash | hashdeep | b3sum | sha256sum |
|---------|:---------:|:--------:|:-----:|:---------:|
| Multithreaded hashing | ✓ | — | ✓ | — |
| Memory-mapped I/O | ✓ | — | ✓ | — |
| SIMD / hardware acceleration | ✓ | — | ✓ | — |
| Parallel file walking | ✓ | — | — | — |
| GPU acceleration | ✓ | — | — | — |
| Direct I/O (no page cache) | ✓ | — | — | — |

### Output Formats

| Format | blazehash | hashdeep | b3sum | sha256sum |
|--------|:---------:|:--------:|:-----:|:---------:|
| hashdeep (HASHDEEP-1.0) | ✓ | ✓ | — | — |
| BLAZEHASH-1.0 | ✓ | — | — | — |
| DFXML | ✓ | — | — | — |
| sha256sum / md5sum | ✓ | — | — | ✓ |
| CSV | ✓ | — | — | — |
| JSON / JSONL | ✓ | — | — | — |

### Algorithms

| Algorithm | blazehash | hashdeep | b3sum | sha256sum |
|-----------|:---------:|:--------:|:-----:|:---------:|
| BLAKE3 | ✓ | — | ✓ | — |
| SHA-256 | ✓ | ✓ | — | ✓ |
| SHA-512, SHA-3 | ✓ | ✓ | — | — |
| SHA-1, MD5, Tiger, Whirlpool | ✓ | ✓ | — | — |
| SHAKE-128 / SHAKE-256 | ✓ | — | — | — |
| CRC32C, XXH3 | ✓ | — | — | — |
| ssdeep, tlsh (fuzzy) | ✓ | — | — | — |
| Multiple simultaneous | ✓ | ✓ | — | — |

---

## Performance

Benchmarked on Apple M4 Pro (14-core, 48 GB RAM), warm cache. Full methodology: **[docs/benchmarks.md](docs/benchmarks.md)**.

| Workload | blazehash | hashdeep v4.4 | Speedup |
|----------|----------:|----------:|--------:|
| 256 MiB file, SHA-256 | 854 ms | 930 ms | **1.09×** |
| 256 MiB file, SHA-1 | 275 ms | 572 ms | **2.08×** |
| 256 MiB file, 5 algos | 3.1 s | 3.5 s | **1.14×** |
| 1,000 small files, SHA-256 | 20 ms | 69 ms | **3.43×** |
| Recursive walk (500 files) | 27 ms | 45 ms | **1.68×** |
| **256 MiB file, BLAKE3** | **187 ms** | *not supported* | **~5× vs hashdeep SHA-256** |

All hashes are bit-identical to hashdeep for shared algorithms (MD5, SHA-1, SHA-256, Tiger, Whirlpool). [Verified by cross-tool tests](docs/benchmarks.md#correctness).

### How it's fast

| Technique | Effect |
|-----------|--------|
| BLAKE3 default | Internally parallelizes each file across a Merkle tree of 1 KiB chunks |
| Memory-mapped I/O | OS pages in file data directly; eliminates one `memcpy` per read |
| Multithreaded file walking | All cores used; small files parallelized across threads |
| Streaming architecture | No file ever fully loaded into memory regardless of size |
| Hardware intrinsics | AVX-512/AVX2/SSE4.1 on x86; NEON on ARM; SHA-NI for SHA-256 |
| Direct I/O (`--no-cache`) | `F_NOCACHE` / `O_DIRECT` / `FILE_FLAG_NO_BUFFERING` per platform |
| Transparent huge pages | `madvise(MADV_HUGEPAGE)` on Linux for files > 2 MiB |
| Windows IOCP async I/O | tokio + IOCP for concurrent file dispatch on Windows |
| GPU acceleration | SHA-256 / MD5 via WGSL compute shaders (wgpu); auto-threshold |

---

## Why This Exists

[hashdeep](https://github.com/jessek/hashdeep) — written by [Jesse Kornbluth](https://github.com/jessek) and [Simson Garfinkel](https://simson.net/) — gave the forensic community its canonical file hashing and audit tool. For over a decade, court-tested workflows have depended on it. It's public domain, auditable, and honest.

But hashdeep hasn't had a release since v4.4. It doesn't support BLAKE3. It doesn't use multiple cores. It can't sign manifests. It can't filter by NSRL. It can't detect duplicates or diff two sessions.

**blazehash** is a continuation, not a replacement. Every hashdeep flag works exactly as you expect. The output format is compatible. Your existing scripts and court-tested procedures keep working. We add what the community needs: speed, modern algorithms, signing, NSRL filtering, and the subcommands that forensic practitioners actually reach for.

---

## Acknowledgements

**Jesse Kornbluth** created [hashdeep](https://github.com/jessek/hashdeep) and gave it to the forensic community as a public domain tool. blazehash would not exist without that foundation.

**Simson Garfinkel** co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML standard.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn — designed the hash function that makes blazehash fast enough to matter.

## References

- [hashdeep](https://github.com/jessek/hashdeep) — Jesse Kornbluth & Simson Garfinkel
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) — the hash function
- [SHAttered](https://shattered.io/) — SHA-1 collision (Stevens et al., 2017)
- [ewf](https://crates.io/crates/ewf) — Pure Rust EWF/E01 reader
- [NIST NSRL](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl) — National Software Reference Library

## Author

**Albert Hui** ([@h4x0r](https://github.com/h4x0r)) · [@SecurityRonin](https://github.com/SecurityRonin)

Digital forensics practitioner and tool developer.

## License

[MIT License](LICENSE)
