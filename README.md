<p align="center">
  <img src="assets/blazehash-banner.png" alt="blazehash" width="520" />
</p>

[![Crates.io](https://img.shields.io/crates/v/blazehash.svg)](https://crates.io/crates/blazehash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml)
[![Release](https://github.com/SecurityRonin/blazehash/actions/workflows/release.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/releases)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Hash. Sign. Timestamp. Prove.**

You're already using hashdeep. blazehash is what it looks like with everything you've been asking for: BLAKE3 at **1,640 MB/s**, Ed25519 signing, Bitcoin-anchored timestamps, YARA scanning, and native cloud storage — while every hashdeep flag and output format works exactly as before.

```bash
brew tap SecurityRonin/tap && brew install blazehash
```

**[Full documentation →](https://securityronin.github.io/blazehash/)**

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

**Cargo**
```bash
cargo install blazehash
```

---

## Three Things You Do With This

### Acquire evidence — court-ready in one pipeline

```bash
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --progress
blazehash sign evidence.hash
blazehash ots stamp evidence.hash
blazehash report evidence.hash -o report.html
```

One manifest proves *what* (cryptographic hashes), *who* (Ed25519 signature), *when* (Bitcoin blockchain anchor), and *context* (case/examiner metadata).

[Acquisition guide →](https://securityronin.github.io/blazehash/acquire/)

### Verify integrity — weeks or months later

```bash
blazehash -r /mnt/evidence -a -k evidence.hash
blazehash verify-sig evidence.hash
blazehash ots verify evidence.hash
```

### Hunt threats

```bash
blazehash -r /mnt/suspect -c sha256 \
  --nsrl NSRL.db --nsrl-exclude \
  --hashdb-bad malware.txt \
  --yara rules.yar --yara-max-size 512 --entropy
```

`--yara-max-size <MB>` sets the per-file size limit for YARA scanning (default: 256 MB). Files above the threshold are stream-hashed normally but YARA is skipped with a warning.

[Threat hunting guide →](https://securityronin.github.io/blazehash/hunt/)

---

## What's New vs hashdeep

Every hashdeep flag works. Your existing scripts keep working. These are the additions:

| | blazehash | hashdeep |
|--|:-:|:-:|
| BLAKE3 (1,640 MB/s) | Y | — |
| Ed25519 manifest signing | Y | — |
| N-of-M cosigning | Y | — |
| Bitcoin timestamps (OTS) | Y | — |
| Case/examiner metadata | Y | — |
| HTML chain-of-custody report | Y | — |
| NSRL known-good filtering | Y | — |
| YARA rule scanning + ATT&CK tag lookup | Y | — |
| VirusTotal batch lookup | Y | — |
| Shannon entropy | Y | — |
| Fuzzy / similarity hashing | Y | — |
| Duplicate detection | Y | — |
| Manifest diff / merge / update | Y | — |
| Live monitoring (watch) | Y | — |
| Remote storage (S3/GCS/Azure/WebDAV) | Y | — |
| Google Drive hash-without-download | Y | — |
| GPU-accelerated SHA-256/MD5 | Y | — |
| MCP server (AI-assisted workflows) | Y | — |
| EWF / E01 image verification | Y | — |
| SQLite / Parquet / DuckDB output | Y | — |
| STIX 2.1 / ECS NDJSON output | Y | — |

---

## Performance

Apple M4 Pro, macOS 15.7.5, warm cache. Full methodology: **[docs/benchmarks.md](docs/benchmarks.md)**.

| Workload | blazehash | hashdeep | Speedup |
|----------|----------:|---------:|--------:|
| 1 GiB, SHA-256 | 2,182 ms | 2,485 ms | **1.14x** |
| 1 GiB, MD5 | 1,447 ms | 2,135 ms | **1.48x** |
| 1 GiB, SHA-1 | 879 ms | 1,803 ms | **2.05x** |
| 1 GiB, BLAKE3 | 655 ms | *n/a* | — |

BLAKE3 runs at **1,640–1,780 MB/s** — 2.8x faster than hashdeep's best algorithm.

---

## Remote Storage

Evidence doesn't live only on disk. blazehash speaks 50+ storage protocols natively — the same command works whether the data is local, on S3, in Google Drive, or on an SFTP server.

```bash
# Hash an S3 prefix directly
blazehash s3://dfir-bucket/case-001/

# Hash locally, write the signed manifest to S3 in one step
blazehash -r /mnt/evidence -c blake3,sha256 -o s3://dfir-bucket/case-001.hash
blazehash sign s3://dfir-bucket/case-001.hash

# Audit weeks later — manifest stays in the cloud
blazehash -a -k s3://dfir-bucket/case-001.hash -r /mnt/evidence

# Hash a Google Drive file without downloading it
blazehash gdrive://1ABCdef...
blazehash https://drive.google.com/file/d/1ABCdef.../view

# Hash over SFTP — no staging, no temp files
blazehash sftp://admin@192.168.1.10/cases/image.dd
```

Credentials come from standard environment variables — `AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_STORAGE_ACCOUNT` — so existing tooling and CI secrets work without changes. For Google Drive, run `blazehash gdrive auth login` once.

Supported: S3, GCS, Azure Blob/Files/ADLS, Backblaze B2, Tencent COS, Huawei OBS, Alibaba OSS, OpenStack Swift, OneDrive, Dropbox, Google Drive, pCloud, Yandex Disk, SFTP, FTP, WebDAV, WebHDFS, Redis, MongoDB, PostgreSQL, and [30+ more →](https://securityronin.github.io/blazehash/remote/)

---

## Optional Feature Flags

Distributed packages (brew/apt/winget) include all features. For `cargo install`, use `--all-features` to get everything:

```bash
cargo install blazehash --all-features
```

| Flag | Default | Enables |
|------|:-------:|---------|
| `remote` | on | Remote storage + Google Drive |
| `nsrl` | on | SQLite NSRL database |
| `parquet-output` | on | `--format parquet` output |
| `yara` | off | YARA rule scanning with ATT&CK tag lookup |
| `report` | off | `blazehash report` HTML generation |
| `docker` | off | `blazehash image` OCI/Docker hashing |
| `ots` | off | `blazehash ots` Bitcoin timestamps |
| `tui` | off | `blazehash tui` interactive dashboard |
| `hashdb` | off | `--hashdb-bad` known-bad flagging |

---

## Acknowledgements

**Jesse Kornbluth** created [hashdeep](https://github.com/jessek/hashdeep) and gave it to the forensic community as a public domain tool.

**Simson Garfinkel** co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML standard.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn.
