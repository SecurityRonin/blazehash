<p align="center">
  <img src="assets/blazehash-icon-256.png" alt="blazehash" width="120" />
</p>

# blazehash

[![Crates.io](https://img.shields.io/crates/v/blazehash.svg)](https://crates.io/crates/blazehash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml)
[![Release](https://github.com/SecurityRonin/blazehash/actions/workflows/release.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/releases)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Hash. Sign. Timestamp. Prove.**

The only open-source forensic hashing tool that answers all four questions a court asks about digital evidence: *what* (cryptographic hashes), *who* (Ed25519 signing), *when* (Bitcoin-anchored timestamps), and *context* (case/examiner metadata) — in a single binary that's drop-in compatible with hashdeep.

Now with **50+ remote storage backends** (S3, GCS, Azure Blob, WebDAV, SFTP, HTTP/S) built in via Apache OpenDAL — hash evidence directly from cloud storage and write manifests back to any remote URI, no extra flags or plugins required.

```bash
# Acquire evidence with chain-of-custody metadata
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --progress

# Hash evidence on S3
blazehash hash s3://dfir-bucket/case-001/ -o s3://dfir-bucket/case-001.hash

# Hash local, write manifest to S3
blazehash hash /evidence/ -o s3://dfir-bucket/case-001.hash

# Sign the manifest
BLAZEHASH_SIGN_PASSWORD="..." blazehash sign evidence.hash

# Second examiner cosigns
BLAZEHASH_SIGN_PASSWORD="..." blazehash cosign evidence.hash

# Anchor to Bitcoin blockchain
blazehash ots stamp evidence.hash

# Verify everything, months later
blazehash verify-sig evidence.hash
blazehash verify-msig evidence.hash --threshold 2
blazehash ots verify evidence.hash
blazehash -r /mnt/evidence -a -k evidence.hash
```

Your evidence, proved.

**[Full documentation](https://securityronin.github.io/blazehash/)**

---

## Install

**macOS**
```bash
brew tap SecurityRonin/tap && brew install blazehash
```

**Debian / Ubuntu / Kali**
```bash
curl -1sLf 'https://dl.cloudsmith.io/public/securityronin/blazehash/setup.deb.sh' | sudo bash
sudo apt install blazehash
```

**Windows**
```powershell
winget install SecurityRonin.blazehash
```

**Cargo (all platforms)**
```bash
cargo install blazehash
```

---

## Three Things You Do With This

### Acquire evidence
Hash a drive or folder, sign it, timestamp it, generate an HTML report. One pipeline, court-ready output.

```bash
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --progress
blazehash sign evidence.hash
blazehash ots stamp evidence.hash
blazehash report evidence.hash -o report.html
```

[Acquisition guide](https://securityronin.github.io/blazehash/acquire/) | [Chain-of-custody guide](https://securityronin.github.io/blazehash/custody/)

### Verify integrity
Come back days, weeks, or months later. Verify nothing was tampered with.

```bash
blazehash -r /mnt/evidence -a -k evidence.hash
blazehash verify-sig evidence.hash
blazehash ots verify evidence.hash
```

### Hunt threats
Filter known-good (NSRL), flag known-bad (HashDB), scan with YARA, check VirusTotal, spot encrypted/packed files by entropy.

```bash
blazehash -r /mnt/suspect -c sha256 \
  --nsrl NSRL.db --nsrl-exclude \
  --hashdb-bad malware.txt \
  --yara rules.yar --entropy
```

[Threat hunting guide](https://securityronin.github.io/blazehash/hunt/) | [SIEM integration guide](https://securityronin.github.io/blazehash/siem/)

---

## Feature Comparison

| Feature | blazehash | hashdeep | b3sum | sha256sum |
|---------|:---------:|:--------:|:-----:|:---------:|
| Audit mode (`-a -k`) | Y | Y | -- | -- |
| Ed25519 manifest signing | Y | -- | -- | -- |
| N-of-M cosigning | Y | -- | -- | -- |
| Bitcoin timestamps (OTS) | Y | -- | -- | -- |
| Case/examiner metadata | Y | -- | -- | -- |
| HTML chain-of-custody report | Y | -- | -- | -- |
| EWF / E01 image verification | Y | -- | -- | -- |
| Manifest diff | Y | -- | -- | -- |
| Duplicate detection | Y | -- | -- | -- |
| NSRL known-good filtering | Y | -- | -- | -- |
| Fuzzy / similarity hashing | Y | -- | -- | -- |
| YARA rule scanning | Y | -- | -- | -- |
| VirusTotal batch lookup | Y | -- | -- | -- |
| Shannon entropy | Y | -- | -- | -- |
| Resume interrupted runs | Y | -- | -- | -- |
| NTFS ADS hashing | Y | -- | -- | -- |
| Live monitoring (watch) | Y | -- | -- | -- |
| MCP server (AI-assisted) | Y | -- | -- | -- |
| BLAKE3 (1,640 MB/s) | Y | -- | Y | -- |
| GPU-accelerated SHA-256/MD5 | Y | -- | -- | -- |
| 14 algorithms simultaneous | Y | -- | -- | -- |
| Direct I/O (no page cache) | Y | -- | -- | -- |
| STIX 2.1 / ECS NDJSON output | Y | -- | -- | -- |
| SQLite / Parquet / DuckDB output | Y | -- | -- | -- |
| Piecewise hashing | Y | Y | -- | -- |
| hashdeep / DFXML / CSV / JSON | Y | partial | -- | -- |
| Remote storage (S3/GCS/Azure/WebDAV) | Y | -- | -- | -- |

---

## Performance

Apple M4 Pro, macOS 15.7.5, warm cache, n=7 runs. Full methodology: **[docs/benchmarks.md](docs/benchmarks.md)**.

| Workload | blazehash | hashdeep | Speedup |
|----------|----------:|---------:|--------:|
| 1 GiB, SHA-256 | 2,182 ms | 2,485 ms | **1.14x** |
| 1 GiB, MD5 | 1,447 ms | 2,135 ms | **1.48x** |
| 1 GiB, SHA-1 | 879 ms | 1,803 ms | **2.05x** |
| 1 GiB, BLAKE3 | 655 ms | *n/a* | -- |

BLAKE3 runs at **1,640-1,780 MB/s** — 2.8x faster than hashdeep's best (SHA-1 at 595 MB/s) and cryptographically stronger.

Small-file caveat: hashdeep's single-threaded C loop has lower per-file overhead for files under ~10 KiB. See [benchmarks](docs/benchmarks.md) for details.

---

## Remote Storage

blazehash can read from and write to remote storage natively — no plugins, no extra flags, no cloud SDK setup beyond standard environment variables.

```bash
# Hash objects under an S3 prefix
blazehash hash s3://dfir-bucket/case-001/

# Hash S3 prefix, write manifest to S3
blazehash hash s3://dfir-bucket/case-001/ -o s3://dfir-bucket/case-001.hash

# Hash local evidence, write manifest to GCS
blazehash hash /mnt/evidence -o gcs://my-bucket/evidence.hash

# Hash local evidence, write manifest to Azure Blob
blazehash hash /mnt/evidence -o azblob://container/evidence.hash

# Audit a manifest stored on S3
blazehash -a -k s3://dfir-bucket/case-001.hash -r /mnt/evidence
```

**Supported URI schemes (default build, no flags needed):**

| Scheme | Backend |
|--------|---------|
| `s3://bucket/key` | AWS S3, MinIO, Cloudflare R2, Wasabi, Backblaze B2 |
| `gcs://bucket/key` | Google Cloud Storage |
| `azblob://container/key` | Azure Blob Storage |
| `webdav://host/path` | WebDAV (Nextcloud, Box, SharePoint) |
| `sftp://user@host/path` | SFTP |
| `http://` / `https://` | HTTP/S (read-only) |
| `file:///abs/path` | Explicit local filesystem |

Auth is picked up from standard environment variables (`AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_STORAGE_ACCOUNT`, etc.).

---

## Optional Feature Flags

```bash
cargo install blazehash --features yara,report,docker,parquet-output,ots
```

| Flag | Enables |
|------|---------|
| `nsrl` | SQLite NSRL database + `--format sqlite` |
| `yara` | `--yara <rules.yar>` scanning |
| `report` | `blazehash report` HTML generation |
| `docker` | `blazehash image` OCI/Docker hashing |
| `parquet-output` | `--format parquet` output |
| `ots` | `blazehash ots stamp/verify` Bitcoin timestamps |
| `tui` | `blazehash tui` interactive dashboard |
| `hashdb` | `--hashdb-bad` known-bad flagging |

---

## Subcommand Reference

| Subcommand | Description |
|------------|-------------|
| `sign` | Sign a manifest with a password-derived Ed25519 key |
| `cosign` | Add a second (or Nth) signature to a manifest |
| `verify-sig` | Verify an Ed25519 manifest signature |
| `verify-msig` | Verify N-of-M multi-signatures |
| `ots stamp` | Anchor a manifest to the Bitcoin blockchain |
| `ots verify` | Verify a Bitcoin timestamp proof |
| `report` | Generate an HTML chain-of-custody report |
| `diff` | Compare two manifests; report added/removed/changed |
| `merge` | Combine two or more manifests (last-write-wins on duplicates) |
| `update` | Incrementally rehash only changed/new files |
| `watch` | Live monitoring — alert on changes against a baseline |
| `dedup` | Find and group content-identical files |
| `duplicates` | Emit all manifest entries whose hash appears more than once |
| `unique-hash` | Keep only the first entry per unique hash value |
| `repair` | Normalize manifest formatting; drop malformed lines |
| `sym-diff` | Symmetric difference of two manifests by path (A⊕B) |
| `first` | Keep first occurrence of each path (complement to `uniq`) |
| `annotate` | Add or replace a `## note:` header in a manifest |
| `shuffle` | Randomly reorder manifest entries (`--seed N` for reproducibility) |
| `reverse` | Reverse manifest entry order |
| `balance` | Split into N equal parts (`--parts N`) |
| `interleave` | Merge two manifests in alternating A B A B order |
| `sort` | Sort manifest entries by path or hash |
| `sample` | Random sample of N entries |
| `head` | First N entries |
| `search` | Search entries by path glob or hash prefix |
| `export` | Re-export manifest to CSV, JSONL, or TSV |
| `convert` | Import md5sum/sha256sum/hashdeep/SFV manifests |
| `lint` | Validate manifest structure and report errors |
| `redact` | Replace paths with deterministic UUIDs, preserve hashes |
| `vt` | Batch VirusTotal lookup for all hashes |
| `image` | Hash OCI/Docker container image layers |
| `mcp` | Start the MCP server for AI-assisted workflows |
| `bench` | Benchmarks and GPU calibration |
| `tui` | Interactive terminal dashboard |
| `nsrl build-bloom` | Build a bloom filter from an NSRL SQLite database |
| `completions` | Generate shell completions (bash/zsh/fish) |

---

## Why This Exists

[hashdeep](https://github.com/jessek/hashdeep) — written by Jesse Kornbluth and Simson Garfinkel — gave the forensic community its canonical file hashing and audit tool. Court-tested workflows have depended on it for over a decade. It is public domain, auditable, and honest.

**blazehash** is a continuation, not a replacement. Every hashdeep flag works as expected. The output format is compatible. Your existing scripts keep working. We add what the community needs next: BLAKE3, GPU acceleration, Ed25519 signing with multi-party cosigning, Bitcoin-anchored timestamps, NSRL filtering, YARA scanning, and the subcommands forensic practitioners actually reach for.

---

## Acknowledgements

**Jesse Kornbluth** created [hashdeep](https://github.com/jessek/hashdeep) and gave it to the forensic community as a public domain tool.

**Simson Garfinkel** co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML standard.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn.

## Author

**Albert Hui** ([@h4x0r](https://github.com/h4x0r)) · [@SecurityRonin](https://github.com/SecurityRonin)

## License

[MIT License](LICENSE)
