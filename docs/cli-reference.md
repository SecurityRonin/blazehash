# CLI Reference

Complete reference for every blazehash flag and subcommand. Flags are organized by category.

---

## Positional arguments

### `paths`

Files or directories to hash.

```bash
blazehash file1.txt file2.txt /mnt/evidence
```

When no paths are given, blazehash reads from the current directory (or stdin with `--stdin`).

---

## Global flags

### `-c`, `--compute`

Hash algorithms, comma-separated. Default: `blake3`.

```bash
blazehash -r /mnt/evidence -c blake3,sha256,md5
```

Available algorithms: `blake3`, `sha256`, `sha512`, `sha3-256`, `sha1`, `md5`, `tiger`, `whirlpool`, `shake128`, `shake256`, `crc32c`, `xxh3`, `ssdeep`, `tlsh`.

### `-r`, `--recursive`

Recurse into directories.

```bash
blazehash -r /mnt/evidence
```

### `-o`, `--output`

Write output to a file instead of stdout. Accepts local paths and remote storage URIs (requires `--features remote`, on by default).

```bash
# Local file
blazehash -r /mnt/evidence -o manifest.hash

# AWS S3
blazehash -r /mnt/evidence -o s3://dfir-bucket/case-001.hash

# Google Cloud Storage
blazehash -r /mnt/evidence -o gcs://dfir-bucket/case-001.hash

# Azure Blob Storage
blazehash -r /mnt/evidence -o azblob://dfir-container/case-001.hash

# WebDAV (Nextcloud, Box, SharePoint)
blazehash -r /mnt/evidence -o webdav://files.example.com/dfir/case-001.hash

# HTTP/S PUT endpoint
blazehash -r /mnt/evidence -o https://ingest.example.com/upload/case-001.hash
```

### `-b`, `--bare`

Bare output — no header comments, no metadata lines. Just the hash entries.

```bash
blazehash -r /mnt/evidence -b
```

### `-s`, `--size-only`

List files with sizes only. No hashing. Useful for a quick inventory before committing to a full hash run.

```bash
blazehash -r /mnt/evidence -s
```

### `--format`

Output format. Default: `hashdeep`.

```bash
blazehash -r /mnt/evidence --format dfxml -o report.xml
```

| Format | Description |
|--------|-------------|
| `hashdeep` | hashdeep-compatible manifest (HASHDEEP-1.0 or BLAZEHASH-1.0 header) |
| `dfxml` | Digital Forensics XML — Autopsy/Sleuth Kit compatible |
| `sha256sum` | Compatible with `sha256sum(1)` and `md5sum(1)` |
| `csv` | Comma-separated values |
| `json` | JSON array |
| `jsonl` | Newline-delimited JSON (one object per line) |
| `sqlite` | SQLite database (requires `--features nsrl`) |
| `parquet` | Apache Parquet columnar file (requires `--features parquet-output`) |

### `--sign`

Sign the manifest after writing. Requires `--output`. You will be prompted for a password, or set `BLAZEHASH_SIGN_PASSWORD`.

```bash
blazehash -r /mnt/evidence -o manifest.hash --sign
```

### `--stdin`

Hash data from stdin instead of files.

```bash
cat suspicious.bin | blazehash --stdin -c sha256,md5
```

---

## Filtering flags

### `--min-size`

Only hash files larger than this size. Accepts suffixes: `K`, `M`, `G`.

```bash
blazehash -r /mnt/evidence --min-size 1M
```

### `--max-size`

Only hash files smaller than this size.

```bash
blazehash -r /mnt/evidence --max-size 100M
```

### `--newer`

Only hash files modified after a date. Format: `YYYY-MM-DD`.

```bash
blazehash -r /mnt/evidence --newer 2024-01-01
```

### `--include`

Include only files matching a glob pattern. Repeatable.

```bash
blazehash -r /mnt/evidence --include "*.exe" --include "*.dll"
```

Supports `**` for recursive matching.

### `--exclude`

Exclude files matching a glob pattern. Repeatable. Overrides `--include`.

```bash
blazehash -r /mnt/evidence --exclude "*.log" --exclude "**/.tmp/*"
```

---

## Audit flags

### `-a`, `--audit`

Enable audit mode. Re-hashes files and compares against a known manifest.

```bash
blazehash -r /mnt/evidence -a -k manifest.hash
```

Exit code `0` = all files match. Exit code `1` = mismatches found.

### `-k`, `--known`

Path to known hash manifest(s) for audit mode. Repeatable.

```bash
blazehash -r /mnt/evidence -a -k manifest1.hash -k manifest2.hash
```

When omitted in audit mode, blazehash looks for `*.hash` files in the current directory.

### `--fuzzy-threshold`

Minimum similarity percentage (0-100) to report a fuzzy match. Default: `50`.

```bash
blazehash -r /evidence -a -k known.hash -c ssdeep --fuzzy-threshold 70
```

### `--fuzzy-top`

Show the top N fuzzy matches per file. Default: `5`.

```bash
blazehash -r /evidence -a -k known.hash -c ssdeep --fuzzy-top 3
```

### `--expected-pubkey`

Expected public key hex for signature verification. Used with `verify-sig` or audit auto-verification.

```bash
blazehash -r /mnt/evidence -a -k manifest.hash --expected-pubkey a3f8e2c1d4b7...
```

When provided during audit, blazehash checks the manifest signature before comparing hashes. Invalid signature aborts the audit.

### `--ignore-sig`

Skip automatic signature verification during audit, even when a `.sig` file exists.

```bash
blazehash -r /mnt/evidence -a -k manifest.hash --ignore-sig
```

---

## Subcommands

### `sign`

Sign a manifest file with a password-derived Ed25519 key.

```bash
blazehash sign manifest.hash
```

Set `BLAZEHASH_SIGN_PASSWORD` to skip the interactive prompt:

```bash
BLAZEHASH_SIGN_PASSWORD=secret blazehash sign manifest.hash
```

The password is fed through Argon2id with a fixed application salt to produce a deterministic Ed25519 key. Same password = same key on any machine.

### `verify-sig`

Verify a manifest signature against an expected public key.

```bash
blazehash verify-sig manifest.hash --expected-pubkey a3f8e2c1d4b7...
```

Exit code `0` = valid. Exit code `1` = tampered or wrong key.

### `dedup`

Find duplicate files in a directory or manifest.

```bash
blazehash dedup /mnt/evidence
blazehash dedup manifest.hash
```

Exit code `0` = no duplicates. Exit code `1` = duplicates found.

#### `--dedup-unique`

Print one representative per duplicate group (what to keep).

```bash
blazehash dedup /mnt/evidence --dedup-unique
```

#### `--dedup-dupes`

Print only the redundant copies (safe to delete).

```bash
blazehash dedup /mnt/evidence --dedup-dupes
```

### `diff`

Compare two manifests and report changes.

```bash
blazehash diff before.hash after.hash
```

When no arguments are given, auto-detects `*.hash` files in the current directory.

Output uses the same `[+]`, `[-]`, `[!]`, `[*]` prefixes as audit mode. Exit code `0` = identical. Exit code `1` = differences.

### `bench`

Run benchmarks and GPU calibration.

#### `--gpu`

Run GPU calibration benchmark. Measures the crossover point where GPU hashing outperforms CPU and writes the result to a config file.

```bash
blazehash bench --gpu
```

#### `--no-calibrate`

Use conservative GPU defaults without running a benchmark or writing config.

```bash
blazehash bench --gpu --no-calibrate
```

### `mcp`

Start the MCP (Model Context Protocol) server for AI-assisted forensic hashing. See [MCP Server](mcp.md) for details.

```bash
blazehash mcp
```

### `nsrl build-bloom`

Build a bloom filter from an NSRL SQLite database for faster lookups.

```bash
blazehash nsrl build-bloom NSRL.db --output nsrl.bloom
```

### `merge`

Combine two or more manifests into one. Last-write-wins on duplicate paths.

```bash
blazehash merge a.hash b.hash -o merged.hash
```

### `update`

Incrementally rehash only changed or new files against an existing manifest.

```bash
blazehash update manifest.hash /path/to/folder
```

### `watch`

Live monitoring: continuously hash a path and alert on changes against a baseline manifest.

```bash
blazehash watch /path/to/folder -k manifest.hash
```

### `vt`

Batch VirusTotal lookup for all hashes in a manifest. Requires a VT API key via `--api-key` or the `VT_API_KEY` environment variable. Requires `--features vt`.

```bash
blazehash vt manifest.hash --api-key YOUR_KEY
VT_API_KEY=YOUR_KEY blazehash vt manifest.hash
```

### `report`

Generate an HTML chain-of-custody report from a manifest. Requires `--features report`.

```bash
blazehash report manifest.hash --examiner "Jane Smith" --case "CASE-2026-001" -o report.html
```

### `image`

Hash the layers of an OCI/Docker container image. Requires `--features docker`.

```bash
blazehash image nginx:latest
```

### `duplicates`

Emit all manifest entries whose hash value appears more than once (content-identical files).

```bash
blazehash duplicates manifest.hash
blazehash duplicates manifest.hash -o dupes.hash
```

### `unique-hash`

Keep only the first entry per unique hash value — complement to `duplicates`.

```bash
blazehash unique-hash manifest.hash -o deduped.hash
```

### `repair`

Normalize manifest formatting: strip blank lines, normalize separators to exactly two spaces, drop malformed data lines.

```bash
blazehash repair manifest.hash -o clean.hash
```

### `sym-diff`

Symmetric difference of two manifests by path — entries whose path appears in A or B but not both.

```bash
blazehash sym-diff before.hash after.hash
blazehash sym-diff before.hash after.hash -o changes.hash
```

### `first`

Keep the first occurrence of each path; drop subsequent duplicate path entries. Complement to `uniq` (which keeps the last).

```bash
blazehash first manifest.hash -o first.hash
```

### `annotate`

Add or replace a `## note:` header in a manifest. Requires `--note`.

```bash
blazehash annotate manifest.hash --note "Reviewed by Jane Smith"
blazehash annotate manifest.hash --note "Reviewed by Jane Smith" -o annotated.hash
```

### `shuffle`

Randomly reorder manifest entries. Use `--seed` for reproducible output.

```bash
blazehash shuffle manifest.hash
blazehash shuffle manifest.hash --seed 42 -o shuffled.hash
```

### `reverse`

Reverse the entry order of a manifest.

```bash
blazehash reverse manifest.hash -o reversed.hash
```

### `balance`

Split a manifest into N roughly equal parts. Requires `--parts`.

```bash
blazehash balance manifest.hash --parts 4
# → manifest_part001.hash ... manifest_part004.hash
```

### `interleave`

Merge two manifests in alternating A B A B order. Remaining entries from the longer manifest are appended.

```bash
blazehash interleave part-a.hash part-b.hash -o interleaved.hash
```

### `gdrive-collect`

Hash a Google Drive file without downloading it to disk. Accepts share links, open links, `gdrive://` URIs, and bare file IDs.

```bash
blazehash gdrive-collect https://drive.google.com/file/d/FILE_ID/view
blazehash gdrive-collect gdrive://FILE_ID
blazehash gdrive-collect FILE_ID
```

Output:

```
<hash>  gdrive://<file-id>
```

Auth: uses a cached OAuth token from `~/.config/blazehash/gdrive_token.json` if present, otherwise falls back to a public (unauthenticated) download.

### `gdrive auth login`

Open a browser OAuth consent flow and cache the resulting Google token.

```bash
blazehash gdrive auth login
```

The token is saved to `~/.config/blazehash/gdrive_token.json` and used automatically by subsequent `gdrive-collect` invocations.

#### `gdrive auth status`

Check whether a valid cached token exists.

```bash
blazehash gdrive auth status
```

---

## Remote storage

blazehash accepts remote URIs for both input paths and `-o` output. Supported schemes:

| Scheme | Backend |
|--------|---------|
| `s3://bucket/key` | AWS S3 and S3-compatible (MinIO, R2, Wasabi, B2) |
| `gcs://bucket/key` | Google Cloud Storage |
| `azblob://container/key` | Azure Blob Storage |
| `webdav://host/path` | WebDAV (Nextcloud, Box, SharePoint) |
| `sftp://user@host/path` | SFTP |
| `http://` / `https://` | HTTP/S (read-only) |
| `file:///abs/path` | Explicit local filesystem |

Auth is read from standard environment variables:

| Backend | Environment variables |
|---------|-----------------------|
| S3 | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`, `AWS_ENDPOINT_URL` |
| GCS | `GOOGLE_APPLICATION_CREDENTIALS` |
| Azure | `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_ACCESS_KEY` or `AZURE_STORAGE_SAS_TOKEN` |
| SFTP | `SFTP_PASSWORD` or `SFTP_KEY_PATH` |
| WebDAV | `WEBDAV_USERNAME`, `WEBDAV_PASSWORD` |

```bash
# Hash an S3 prefix
blazehash hash s3://dfir-bucket/case-001/

# Write manifest output to S3
blazehash hash /mnt/evidence -o s3://dfir-bucket/case-001.hash

# Audit against a manifest on S3
blazehash -r /mnt/evidence -a -k s3://dfir-bucket/case-001.hash
```

---

## NSRL flags

### `--nsrl`

Path to an NSRL database (`.db` SQLite) or bloom filter (`.bloom`) file. Annotates known-good files with `[K]` in output.

```bash
blazehash -r /mnt/evidence -c sha256 --nsrl NSRL.db
```

### `--nsrl-hsh`

Path to a NIST NSRL flat `.hsh` hashset file (alternative to the SQLite `--nsrl` database).

```bash
blazehash -r /mnt/evidence -c sha256 --nsrl-hsh NSRLFile.hsh
```

### `--nsrl-exclude`

Suppress known-good files from output entirely. Requires `--nsrl`.

```bash
blazehash -r /mnt/evidence -c sha256 --nsrl NSRL.db --nsrl-exclude
```

!!! warning
    When using `--nsrl-exclude` with a bloom filter, a small number of files may be suppressed due to false positives (~0.1%). Use the SQLite database for exclusion in production environments.

---

## Advanced flags

### `--entropy`

Compute and display the Shannon entropy of each file alongside its hash. Values range 0.0–8.0; scores above 7.2 suggest encrypted, compressed, or packed content.

```bash
blazehash -r /mnt/evidence --entropy
```

### `--yara`

Run YARA rule matching during the directory walk. Requires `--features yara`.

```bash
blazehash -r /mnt/evidence --yara rules.yar
```

### `--yara-max-size`

Maximum file size (in MiB) for YARA scanning. Default: `256`. Files larger than this threshold are still hashed but the YARA scan is skipped and a warning is written to stderr.

```bash
blazehash -r /mnt/evidence --yara rules.yar --yara-max-size 512
```

### `--no-cache`

Bypass the OS page cache. Reads directly from disk using platform-specific direct I/O (`F_NOCACHE` on macOS, `O_DIRECT` on Linux, `FILE_FLAG_NO_BUFFERING` on Windows).

```bash
blazehash -r /mnt/evidence --no-cache
```

Use this when hashing a live system without disturbing in-memory evidence.

### `--no-gpu`

Force CPU-only hashing, even when a GPU is available.

```bash
blazehash -r /mnt/evidence -c sha256 --no-gpu
```

### `--ads`

Hash NTFS Alternate Data Streams alongside main file content. Windows only; no-op on other platforms.

```bash
blazehash -r C:\Evidence --ads
```

### `--resume`

Resume from a partial manifest. Reads the existing output file, skips already-hashed files, and continues where it left off.

```bash
blazehash -r /mnt/evidence -o manifest.hash --resume
```

### `-p`, `--piecewise`

Piecewise (chunk) hashing. Each file produces one hash entry per chunk. Accepts size suffixes: `K`, `M`, `G`.

```bash
blazehash -r /mnt/evidence -p 1G
```

### `--verify-image`

Verify a forensic disk image. Supports E01/EWF (EnCase) images and raw/DD images with sidecar hash files.

```bash
blazehash --verify-image case.E01
blazehash --verify-image disk.raw
```

For E01 images, blazehash verifies the stored hashes against recomputed values. Multi-segment images (`.E01`, `.E02`, ...) are detected automatically.

For raw images, blazehash looks for sidecar files (`.md5`, `.sha256`, `.sha512`, `.blake3`) alongside the image.
