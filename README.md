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

Read from and write to remote storage natively using standard URI schemes:

```bash
# Hash objects under an S3 prefix
blazehash s3://dfir-bucket/case-001/

# Hash local evidence, write manifest to S3
blazehash /mnt/evidence -o s3://dfir-bucket/case-001.hash

# Audit a manifest stored on S3
blazehash -a -k s3://dfir-bucket/case-001.hash -r /mnt/evidence

# Hash a Google Drive file by URL or gdrive:// URI
blazehash gdrive://1ABC...
blazehash https://drive.google.com/file/d/1ABC.../view
```

**Cloud object storage**

| Scheme | Backend |
|--------|---------|
| `s3://bucket/key` | AWS S3, MinIO, Cloudflare R2, Wasabi, Backblaze B2 (S3-compat) |
| `gcs://bucket/key` | Google Cloud Storage |
| `azblob://container/key` | Azure Blob Storage |
| `azdls://filesystem/path` | Azure Data Lake Storage Gen2 |
| `azfile://share/path` | Azure Files |
| `b2://bucket/key` | Backblaze B2 (native API) |
| `cos://bucket/key` | Tencent Cloud COS |
| `obs://bucket/key` | Huawei Cloud OBS |
| `oss://bucket/key` | Alibaba Cloud OSS |
| `swift://container/path` | OpenStack Swift |
| `upyun://bucket/key` | Upyun CDN storage |

**Cloud drives**

| Scheme | Backend |
|--------|---------|
| `gdrive://file-id` | Google Drive (OAuth2; run `blazehash gdrive auth login` once) |
| `onedrive://path` | Microsoft OneDrive (`ONEDRIVE_ACCESS_TOKEN`) |
| `dropbox://path` | Dropbox (`DROPBOX_ACCESS_TOKEN`) |
| `aliyun-drive://path` | Aliyun Drive (`ALIYUN_DRIVE_ACCESS_TOKEN`) |
| `yandex-disk://path` | Yandex Disk (`YANDEX_DISK_ACCESS_TOKEN`) |
| `pcloud://path` | pCloud (`PCLOUD_USERNAME` / `PCLOUD_PASSWORD`) |
| `koofr://path` | Koofr (`KOOFR_EMAIL` / `KOOFR_PASSWORD`) |
| `seafile://server/repo/path` | Seafile (`SEAFILE_USERNAME` / `SEAFILE_PASSWORD`) |

**Developer / ML / infra**

| Scheme | Backend |
|--------|---------|
| `github://owner/repo/path` | GitHub (`GITHUB_TOKEN`) |
| `huggingface://owner/repo/path` | HuggingFace datasets / models (`HUGGINGFACE_TOKEN`) |
| `vercel-blob://key` | Vercel Blob (`BLOB_READ_WRITE_TOKEN`) |
| `alluxio://host:port/path` | Alluxio data orchestration |
| `webhdfs://host:port/path` | WebHDFS REST (Hadoop, no JVM required) |
| `lakefs://repo/branch/path` | LakeFS data versioning (`LAKEFS_ACCESS_KEY_ID`) |
| `dbfs://path` | Databricks DBFS (`DATABRICKS_TOKEN`) |
| `ipfs://CID/path` | IPFS (via local or remote gateway) |
| `ipmfs:///path` | IPFS Mutable File System |

**Network KV / databases**

| Scheme | Backend |
|--------|---------|
| `redis://host/key` | Redis |
| `memcached://host/key` | Memcached |
| `etcd://host/key` | etcd |
| `tikv://pd-host/key` | TiKV |
| `mongodb://host/db/coll/key` | MongoDB |
| `mysql://host/db/key` | MySQL / MariaDB |
| `postgresql://host/db/key` | PostgreSQL |
| `sqlite://path/to.db/key` | SQLite |
| `cloudflare-kv://namespace/key` | Cloudflare KV (`CLOUDFLARE_API_TOKEN`) |
| `d1://database-id/key` | Cloudflare D1 (`CLOUDFLARE_API_TOKEN`) |

**Filesystem / protocols**

| Scheme | Backend |
|--------|---------|
| `sftp://user@host/path` | SFTP (`BLAZEHASH_SFTP_KEY_PATH` for key auth) |
| `ftp://user:pass@host/path` | FTP / FTPS |
| `webdav://host/path` | WebDAV (Nextcloud, Box, SharePoint) |
| `http://` / `https://` | HTTP/S (read-only) |
| `file:///abs/path` | Explicit local filesystem |

Auth is picked up from standard environment variables (see table above). Cloud provider SDKs also honour their standard env vars: `AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_STORAGE_ACCOUNT`, etc.

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
