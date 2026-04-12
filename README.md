# blazehash

[![Crates.io](https://img.shields.io/crates/v/blazehash.svg)](https://crates.io/crates/blazehash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml)
[![Release](https://github.com/SecurityRonin/blazehash/actions/workflows/release.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/releases)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Hashdeep, at 2026 speed.**

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
| NSRL known-good filtering | `--nsrl file.db` (SQLite) or `--nsrl-hsh NSRLFile.hsh` (flat .hsh hashset) |
| Fuzzy / similarity hashing | ssdeep + TLSH; useful for variant detection |
| Shannon entropy | `--entropy` column (0.0–8.0); values >7.2 suggest encrypted/packed content |
| YARA rule scanning | `--yara rules.yar` during walk (requires `--features yara`) |
| Duplicate detection | `blazehash dedup` |
| Manifest merge | `blazehash merge a.hash b.hash -o merged.hash` — last-write-wins |
| Incremental update | `blazehash update manifest.hash <path>` — rehash only changed/new files |
| Live monitoring | `blazehash watch <path> -k manifest.hash` — alert on changes against baseline |
| VirusTotal lookup | `blazehash vt manifest.hash` — batch lookup (requires `VT_API_KEY`) |
| HTML chain-of-custody report | `blazehash report manifest.hash --examiner "Name" --case "ID" -o report.html` (requires `--features report`) |
| OCI/Docker layer hashing | `blazehash image nginx:latest` (requires `--features docker`) |
| SQLite output | `--format sqlite` (requires `--features nsrl`) |
| Parquet output | `--format parquet` (requires `--features parquet-output`) |
| Direct I/O (no page cache) | `--no-cache`; preserves RAM on large acquisitions |
| MCP server | `blazehash mcp` for AI-assisted forensic workflows |
| Chain-of-custody metadata | `--case` / `--examiner` embed case ID and analyst name in the manifest header |
| Shell completions | `blazehash completions <bash\|zsh\|fish>` generates shell completion scripts |
| Progress bar | `--progress` shows a live progress bar; auto-enabled on TTY |
| HashDB bad list | `--hashdb-bad <file>` flags matching files `[BAD]` (requires `--features hashdb`) |
| Unified diff output | `blazehash diff --patch` emits unified diff format |
| Raw device hashing | `--sector-size <n>` enables direct block-device hashing (e.g. `/dev/sda`) |
| STIX 2.1 output | `--format stix` produces STIX 2.1 JSON bundles |
| ECS NDJSON output | `--format ecs` produces Elastic Common Schema NDJSON for Elastic/Splunk ingestion |
| Multi-party signing | `blazehash cosign` / `verify-msig --threshold N` — M-of-N co-signing |
| OpenTimestamps notarization | `blazehash ots stamp/verify` — Bitcoin-anchored timestamp (requires `--features ots`) |
| Interactive TUI | `blazehash tui` — live progress dashboard (requires `--features tui`) |


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

## Optional Features

Some capabilities require opt-in Cargo feature flags:

```bash
cargo install blazehash --features yara,report,docker,parquet-output
```

| Feature flag | What it enables |
|---|---|
| `nsrl` | SQLite NSRL database support and `--format sqlite` output |
| `yara` | `--yara <rules.yar>` YARA rule scanning during walk |
| `report` | `blazehash report` HTML chain-of-custody report generation |
| `docker` | `blazehash image` OCI/Docker container layer hashing |
| `parquet-output` | `--format parquet` Apache Parquet output |
| `ots` | `blazehash ots stamp/verify` OpenTimestamps Bitcoin-anchored notarization |
| `tui` | `blazehash tui` interactive terminal progress dashboard |

---

## Feature Batch 3 — New Capabilities

### Chain-of-custody metadata

Embed a case identifier and examiner name directly in the manifest header with `--case` and `--examiner`. These fields appear in every downstream output format and HTML report.

```bash
blazehash hash -r /evidence -o evidence.hash --case "CASE-2026-001" --examiner "Jane Smith"
```

### Shell completions

Generate tab-completion scripts for bash, zsh, or fish:

```bash
blazehash completions bash > /etc/bash_completion.d/blazehash
blazehash completions zsh  > ~/.zsh/completions/_blazehash
blazehash completions fish > ~/.config/fish/completions/blazehash.fish
```

### Progress bar

`--progress` displays a live file-count and throughput bar. It is auto-enabled when stdout is a TTY, so CI pipelines stay clean without any extra flags.

```bash
blazehash hash -r /large-dir --progress
```

### HashDB bad list

Supply a newline-delimited file of known-bad SHA-256 or SHA-1 hashes. Any file whose hash matches is flagged `[BAD]` in the manifest and report output. Requires `--features hashdb`.

```bash
blazehash hash -r /suspect --hashdb-bad known_malware.txt
```

### Unified diff output

`blazehash diff --patch` emits a standard unified diff between two manifests, suitable for piping into `patch` or storing in version control.

```bash
blazehash diff baseline/ current/ --patch
```

### Raw device hashing

Hash block devices directly by specifying `--sector-size`. Reads bypass the filesystem entirely, so deleted and slack-space data is included in the manifest.

```bash
blazehash hash /dev/sda --sector-size 512 -o disk.hash
```

### STIX 2.1 output

`--format stix` serialises the manifest as a STIX 2.1 JSON bundle, ready for ingestion into threat-intel platforms and SIEM tools that support the OASIS standard.

```bash
blazehash hash -r /evidence --format stix -o evidence.stix.json
```

### ECS NDJSON output

`--format ecs` writes one Elastic Common Schema record per file as newline-delimited JSON, compatible with Filebeat, Logstash, and Splunk HEC out of the box.

```bash
blazehash hash -r /evidence --format ecs -o evidence.ndjson
```

### Multi-party signing

Multiple analysts can co-sign the same manifest. `verify-msig` enforces an M-of-N quorum so the manifest is only considered valid when enough parties have signed.

```bash
BLAZEHASH_SIGN_PASSWORD=alice blazehash cosign evidence.hash
BLAZEHASH_SIGN_PASSWORD=bob   blazehash cosign evidence.hash
blazehash verify-msig evidence.hash --threshold 2
```

### OpenTimestamps notarization

`blazehash ots stamp` submits the manifest SHA-256 to the OpenTimestamps calendar and anchors it in the Bitcoin blockchain. `blazehash ots verify` confirms the timestamp later. Requires `--features ots`.

```bash
blazehash ots stamp  evidence.hash
blazehash ots verify evidence.hash
```

### Interactive TUI

`blazehash tui` opens a terminal dashboard showing per-file progress, throughput, and a running manifest preview. Press `q` or `Esc` to exit. Requires `--features tui`.

```bash
blazehash tui -r /large-dir
```

---

## Acknowledgements

**Jesse Kornbluth** created [hashdeep](https://github.com/jessek/hashdeep) and gave it to the forensic community as a public domain tool.

**Simson Garfinkel** co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML standard.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn.

## Author

**Albert Hui** ([@h4x0r](https://github.com/h4x0r)) · [@SecurityRonin](https://github.com/SecurityRonin)

## License

[MIT License](LICENSE)
