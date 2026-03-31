# blazehash

[![Crates.io](https://img.shields.io/crates/v/blazehash.svg)](https://crates.io/crates/blazehash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml)
[![Release](https://github.com/SecurityRonin/blazehash/actions/workflows/release.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/releases)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

hashdeep for the modern era. BLAKE3 by default. Multithreaded. Memory-mapped. Drop-in compatible with every hashdeep flag, plus new ones. [**Up to 3.4x faster**](docs/benchmarks.md) than hashdeep on the same algorithms — and [**~5x faster**](docs/benchmarks.md#the-blake3-advantage) when you switch to BLAKE3.

Point this at a case directory. Get a cryptographically verified manifest in seconds, not hours.

```bash
blazehash -r /mnt/evidence -c blake3,sha-256 -o results.hash
```

```
blazehash v0.2.0 — BLAKE3 + SHA-256, 16 threads, mmap I/O
[*] Scanning /mnt/evidence recursively
[+] 847,293 files hashed (2.14 TiB) in 38.7s
[+] Throughput: 56.6 GiB/s (BLAKE3) · 4.2 GiB/s (SHA-256)
[+] Manifest written to results.hash
```

## Why This Tool Exists

[hashdeep](https://github.com/jessek/hashdeep) is one of the most important tools in digital forensics. Written by [Jesse Kornblum](https://github.com/jessek) and [Simson Garfinkel](https://simson.net/), it gave the forensic community a reliable, auditable way to hash files and verify evidence integrity. Its audit mode, recursive hashing, and known-hash matching set the standard that every forensic lab depends on. hashdeep is a work of the US Government and has been freely available to the community since its inception.

We owe Jesse a debt of gratitude. hashdeep solved a real problem and solved it well.

But hashdeep was written in an era of spinning disks, single-core CPUs, and MD5 as a default. The world moved on. Evidence volumes grew from gigabytes to terabytes. NVMe drives can push 7 GB/s. CPUs ship with 16+ cores. NIST deprecated SHA-1. And BLAKE3 — designed from the ground up for parallelism and hardware acceleration — can hash at memory bandwidth speeds.

hashdeep hasn't had a release since v4.4. It doesn't support BLAKE3. It doesn't use multiple cores. It doesn't memory-map files. It can't resume interrupted runs. It can't export to JSON.

**blazehash** intends to bring hashdeep into modern times. Every hashdeep flag works exactly as you expect. The output format is compatible. Your existing scripts, your audit workflows, your court-tested procedures — they all keep working. We just make them faster, add the algorithms the community needs, and fill the gaps hashdeep never got to.

This is not a replacement. It is a continuation.

## Performance

Benchmarked on Apple M4 Pro (14-core, 48 GB RAM). Both tools run on warm cache. Full methodology and results: **[docs/benchmarks.md](docs/benchmarks.md)**.

| Workload | blazehash | hashdeep v4.4 | Speedup |
|----------|----------:|----------:|--------:|
| 256 MiB file, SHA-256 | 854 ms | 930 ms | **1.09x** |
| 256 MiB file, SHA-1 | 275 ms | 572 ms | **2.08x** |
| 256 MiB file, 5 algos combined | 3.1 s | 3.5 s | **1.14x** |
| 1000 small files, SHA-256 | 20 ms | 69 ms | **3.43x** |
| Recursive walk (500 files) | 27 ms | 45 ms | **1.68x** |
| Piecewise (64 MiB, 1M chunks) | 163 ms | 339 ms | **2.08x** |
| **256 MiB file, BLAKE3** | **187 ms** | *not supported* | **~5x vs hashdeep SHA-256** |

**BLAKE3 at 1.37 GB/s** is blazehash's default — unavailable in hashdeep. For practitioners switching from `hashdeep -c sha256`: expect nearly **5x** end-to-end speedup (faster algorithm + faster implementation).

All hashes are bit-identical to hashdeep for shared algorithms (MD5, SHA-1, SHA-256, Tiger, Whirlpool). [Verified by automated cross-tool tests](docs/benchmarks.md#correctness).

## Install

### Debian / Ubuntu / Kali

Download the `.deb` for your architecture from [GitHub Releases](https://github.com/SecurityRonin/blazehash/releases):

```bash
sudo apt install ./blazehash_*_amd64.deb     # x86_64
sudo apt install ./blazehash_*_arm64.deb     # ARM64
```

### macOS (Homebrew)

```bash
brew tap SecurityRonin/tap
brew install blazehash
```

### Windows

Download the `.msi` installer from [GitHub Releases](https://github.com/SecurityRonin/blazehash/releases). The installer adds `blazehash` to your system PATH automatically.

### Cargo (all platforms)

```bash
cargo install blazehash
```

### As a library

blazehash is also available as a Rust library for embedding hashing capabilities into your own tools:

```toml
[dependencies]
blazehash = "0.2"
```

See [crates.io](https://crates.io/crates/blazehash) for API documentation.

## Usage

blazehash is a **superset** of hashdeep. All hashdeep flags work, plus new ones.

### Hash a directory (BLAKE3, default)

```bash
blazehash -r /mnt/evidence
```

### Multiple algorithms

```bash
blazehash -r /mnt/evidence -c blake3,sha256,md5
```

### Audit mode (verify against known hashes)

```bash
blazehash -r /mnt/evidence -a -k known_hashes.txt
blazehash -r /mnt/evidence -a -k hashdeep_manifest.txt      # hashdeep format
blazehash -r /mnt/evidence -a -k hashes.csv                  # CSV
blazehash -r /mnt/evidence -a -k hashes.json                 # JSON / JSONL
blazehash -r /mnt/evidence -a -k hashes.b3                   # b3sum format
blazehash -r /mnt/evidence -a -k hashes.sha256               # sha256sum format
```

Accepts known-hash files in hashdeep format. Audit reports match hashdeep output exactly: files matched, files not matched, files moved, files new.

### Export formats

```bash
blazehash -r /mnt/evidence --format hashdeep     # default, hashdeep-compatible
blazehash -r /mnt/evidence --format csv           # CSV with headers
blazehash -r /mnt/evidence --format json          # JSON array
blazehash -r /mnt/evidence --format jsonl         # one JSON object per line
```

### Resume interrupted runs

```bash
blazehash -r /mnt/evidence -o manifest.hash --resume
```

Picks up where it left off. Reads the partial manifest, skips already-hashed files, continues from the next file.

### Piecewise / chunk hashing

```bash
blazehash -r /mnt/evidence -p 1G     # hash in 1 GiB chunks
```

Piecewise hashing (hashdeep `-p` flag). Each file produces multiple hash entries, one per chunk. Useful for verifying partial transfers or detecting targeted modifications within large files.

### Verify forensic disk images

```bash
blazehash --verify-image image.E01    # verify E01/EWF image integrity
```

Recomputes the full-media MD5 (and SHA-1 if stored) and compares against hashes embedded in the image. Supports E01, Ex01, L01, and multi-segment EWF images. Powered by the [ewf](https://crates.io/crates/ewf) crate.

### Size-only mode (fast pre-scan)

```bash
blazehash -r /mnt/evidence -s         # list files with sizes, no hashing
```

## MCP server

The `blazehash mcp` command starts an [MCP](https://modelcontextprotocol.io/) server for AI-assisted forensic hashing over JSON-RPC stdio.

| Tool | Description |
|------|-------------|
| `blazehash_hash` | Hash files/directories with configurable algorithms (default: BLAKE3) |
| `blazehash_audit` | Audit files against a known manifest — detect changes, moves, missing files |
| `blazehash_verify_image` | Verify forensic disk image integrity (E01/EWF) |
| `blazehash_algorithms` | List all 8 supported hash algorithms |
| `blazehash_hash_bytes` | Hash raw inline data (hex or base64 encoded) |

### Register with Claude Code

```bash
claude mcp add blazehash -- blazehash mcp
```

### Claude Desktop configuration

```json
{
  "mcpServers": {
    "blazehash": {
      "command": "blazehash",
      "args": ["mcp"]
    }
  }
}
```

## Algorithms

| Algorithm | Flag | Default | Apple Silicon (M4) | x86_64 | Quantum Resilient | Notes |
|-----------|------|---------|-------------------|--------|-------------------|-------|
| BLAKE3 | `blake3` | **Y** | NEON, internal tree parallelism | AVX-512, AVX2, SSE4.1 | Pre-quantum | 4x faster than SHA-256, designed for parallelism |
| SHA-256 | `sha256` | -- | ARM SHA2 extensions (`sha256h/h2/su0/su1`) | SHA-NI | Pre-quantum | NIST standard, court-accepted everywhere |
| SHA-3-256 | `sha3-256` | -- | NEON Keccak-f[1600] | AVX2 lane-parallel | Post-quantum candidate basis | Keccak sponge, different construction from SHA-2 |
| SHA-512 | `sha512` | -- | Native 64-bit, NEON 2x interleave | AVX2 | Pre-quantum | Faster than SHA-256 on 64-bit CPUs |
| SHA-1 | `sha1` | -- | ARM SHA1 extensions (`sha1c/p/m/h/su0/su1`) | SHA-NI | Broken | Legacy only, collision attacks published (SHAttered, 2017) |
| MD5 | `md5` | -- | NEON vectorized | SSE2/AVX2 multi-buffer | Broken | Legacy only, collision attacks trivial since 2004 |
| Tiger | `tiger` | -- | 64-bit optimized lookup tables | 64-bit optimized | Pre-quantum | hashdeep compatibility, 192-bit output |
| Whirlpool | `whirlpool` | -- | Table-based, 64-bit native | Table-based, 64-bit native | Pre-quantum | hashdeep compatibility, 512-bit output |

BLAKE3 is the default because it is the fastest cryptographic hash on modern hardware while maintaining a 256-bit security level. For court submissions where opposing counsel may challenge algorithm choice, `sha256` remains the safe bet.

## How It's Fast

| Technique | What it does |
|-----------|-------------|
| BLAKE3 default | Hash function designed for parallelism — internally splits each file into 1 KiB chunks and hashes them across a Merkle tree |
| Memory-mapped I/O | Lets the OS page in file data directly, bypassing userspace read buffers. Eliminates a `memcpy` per read call |
| Multithreaded file walking | Directory traversal and hashing run on a thread pool (defaults to all cores). Large files are parallelized internally by BLAKE3; many small files are parallelized across threads |
| Streaming architecture | Files are hashed as they stream in. No file is ever fully loaded into memory, regardless of size |
| Hardware intrinsics | BLAKE3 uses AVX-512/AVX2/SSE4.1 on x86 and NEON on ARM. SHA-256 uses SHA-NI where available |

## Feature Comparison

How blazehash compares to hashdeep, b3sum, sha256sum, and other forensic hashing tools.

### Algorithms

| Feature | blazehash | hashdeep | b3sum | sha256sum | md5deep |
|---------|:---------:|:--------:|:-----:|:---------:|:-------:|
| BLAKE3 | **Y** | -- | **Y** | -- | -- |
| SHA-256 | **Y** | **Y** | -- | **Y** | -- |
| SHA-3-256 | **Y** | -- | -- | -- | -- |
| SHA-512 | **Y** | **Y** | -- | -- | -- |
| SHA-1 | **Y** | **Y** | -- | -- | -- |
| MD5 | **Y** | **Y** | -- | -- | **Y** |
| Tiger | **Y** | **Y** | -- | -- | -- |
| Whirlpool | **Y** | **Y** | -- | -- | -- |
| Multiple simultaneous | **Y** | **Y** | -- | -- | -- |

### Performance

| Feature | blazehash | hashdeep | b3sum | sha256sum | md5deep |
|---------|:---------:|:--------:|:-----:|:---------:|:-------:|
| Multithreaded hashing | **Y** | -- | **Y** | -- | -- |
| Memory-mapped I/O | **Y** | -- | **Y** | -- | -- |
| SIMD / HW acceleration | **Y** | -- | **Y** | -- | -- |
| Parallel file walking | **Y** | -- | -- | -- | -- |

### Forensic Features

| Feature | blazehash | hashdeep | b3sum | sha256sum | md5deep |
|---------|:---------:|:--------:|:-----:|:---------:|:-------:|
| Audit mode | **Y** | **Y** | -- | `-c` flag | -- |
| Piecewise hashing | **Y** | **Y** | -- | -- | -- |
| Resume interrupted | **Y** | -- | -- | -- | -- |
| Known-hash matching | **Y** | **Y** | -- | -- | **Y** |
| Recursive hashing | **Y** | **Y** | -- | -- | **Y** |
| Forensic image verification (E01) | **Y** | -- | -- | -- | -- |
| MCP server (AI-assisted analysis) | **Y** | -- | -- | -- | -- |

### Output Formats

| Feature | blazehash | hashdeep | b3sum | sha256sum | md5deep |
|---------|:---------:|:--------:|:-----:|:---------:|:-------:|
| hashdeep format | **Y** | **Y** | -- | -- | -- |
| CSV | **Y** | -- | -- | -- | -- |
| JSON / JSONL | **Y** | -- | -- | -- | -- |

### Platform & Implementation

| | blazehash | hashdeep | b3sum | sha256sum | md5deep |
|---------|:---------:|:--------:|:-----:|:---------:|:-------:|
| Cross-platform | **Y** | **Y** | **Y** | **Y** | **Y** |
| Language | Rust | C++ | Rust | C (coreutils) | C++ |
| Maintained (2025+) | **Y** | -- (v4.4, 2014) | **Y** | **Y** | -- |
| Static Linux binary | **Y** | -- | **Y** | -- | -- |

## References

- [hashdeep](https://github.com/jessek/hashdeep) (Jesse Kornblum & Simson Garfinkel, forensic hashing and audit)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) (Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, Zooko Wilcox-O'Hearn)
- [SHAttered](https://shattered.io/) (SHA-1 collision, Stevens et al., 2017)
- [ewf](https://crates.io/crates/ewf) (Pure Rust EWF/E01 reader for forensic image verification)

## Acknowledgements

This project exists because of [Jesse Kornblum](https://github.com/jessek).

Jesse created [hashdeep](https://github.com/jessek/hashdeep) (and its predecessor md5deep) while working for the US Government, and gave it to the forensic community as a public domain tool. For over a decade, hashdeep has been the go-to utility for evidence hashing and integrity verification in forensic labs, law enforcement agencies, and courtrooms worldwide. Its audit mode — the ability to verify a set of files against a known-good manifest and report what matched, what moved, what changed, and what's new — remains one of the most elegant ideas in forensic tooling.

[Simson Garfinkel](https://simson.net/) co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML format.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn — designed a hash function that is both fast and correct. BLAKE3's internal parallelism and tree hashing structure are the reason blazehash can saturate NVMe bandwidth on a single file.

blazehash does not claim to replace hashdeep. It carries its torch forward.

## Author

**Albert Hui** ([@h4x0r](https://github.com/h4x0r)) of [@SecurityRonin](https://github.com/SecurityRonin)

Digital forensics practitioner and tool developer. Building open-source DFIR tools that close the gaps left by commercial software.

## License

Licensed under the [MIT License](LICENSE).
