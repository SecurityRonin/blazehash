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

Available algorithms:

| Algorithm | Type | Notes |
|-----------|------|-------|
| `blake3` | Cryptographic | Default |
| `blake2b` | Cryptographic | 512-bit output |
| `blake2s` | Cryptographic | 256-bit output |
| `sha256` | Cryptographic | |
| `sha512` | Cryptographic | |
| `sha512-256` | Cryptographic | SHA-512 truncated to 256 bits |
| `sha512-224` | Cryptographic | SHA-512 truncated to 224 bits |
| `sha3-256` | Cryptographic | |
| `sha1` | Cryptographic | |
| `md5` | Cryptographic | |
| `tiger` | Cryptographic | |
| `whirlpool` | Cryptographic | |
| `sm3` | Cryptographic | Chinese national standard (GB/T 32905) |
| `streebog-256` | Cryptographic | GOST R 34.11-2012, 256-bit |
| `streebog-512` | Cryptographic | GOST R 34.11-2012, 512-bit |
| `ripemd160` | Cryptographic | |
| `k12` | Cryptographic | KangarooTwelve (parallel SHA-3 variant) |
| `shake128` | Cryptographic | Extendable output |
| `shake256` | Cryptographic | Extendable output |
| `crc32c` | Non-cryptographic | |
| `crc64` | Non-cryptographic | |
| `adler32` | Non-cryptographic | |
| `xxh3` | Non-cryptographic | |
| `ssdeep` | Fuzzy | |
| `tlsh` | Fuzzy | |

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

| Format | Description | Feature |
|--------|-------------|---------|
| `hashdeep` | hashdeep-compatible manifest (HASHDEEP-1.0 or BLAZEHASH-1.0 header) | default |
| `dfxml` | Digital Forensics XML — Autopsy/Sleuth Kit compatible | default |
| `sha256sum` | Compatible with `sha256sum(1)` and `md5sum(1)` | default |
| `csv` | Comma-separated values | default |
| `json` | JSON array | default |
| `jsonl` | Newline-delimited JSON (one object per line) | default |
| `ecs` | NDJSON in Elastic Common Schema (ECS) format | default |
| `stix` | STIX 2.1 bundle (JSON) | default |
| `sqlite` | SQLite database | `sqlite` (default-on) |
| `parquet` | Apache Parquet columnar file | `parquet-output` (default-on) |
| `duckdb` | DuckDB database file | `duckdb-output` (default-on) |

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

### `--fail-on-unknown`

Exit non-zero if any file on disk has no corresponding entry in the manifest (unknown files). Unknown files are logged with a `[?]` prefix; if any are found the process exits with code `1`.

```bash
blazehash -r /mnt/evidence -a -k manifest.hash --fail-on-unknown
```

Useful in sealed-environment audits where every file must be accounted for in the known manifest.

---

## Subcommands

### Acquisition

#### `watch`

Live monitoring: continuously hash a path and alert on changes against a baseline manifest.

```bash
blazehash watch /path/to/folder -k manifest.hash
```

#### `archive`

Hash all files inside a ZIP or TAR archive without extracting. Requires `--features archive` (default-on).

```bash
blazehash archive collection.zip -c blake3,sha256
blazehash archive evidence.tar.gz -c sha256
```

#### `image`

Hash the layers of an OCI/Docker container image. Requires `--features docker`.

```bash
blazehash image nginx:latest
```

#### Google Drive hashing

Hash a Google Drive file without downloading it to disk. Pass a `gdrive://` URI or a full Drive share URL directly as the path argument.

```bash
blazehash gdrive://FILE_ID
blazehash https://drive.google.com/file/d/FILE_ID/view
```

Output:

```
<hash>  gdrive://<file-id>
```

Auth: uses a cached OAuth token from `~/.config/blazehash/gdrive_token.json` if present, otherwise falls back to a public (unauthenticated) download. Run `blazehash gdrive auth login` once to authenticate.

#### `gdrive auth login`

Open a browser OAuth consent flow and cache the resulting Google token.

```bash
blazehash gdrive auth login
```

#### `gdrive auth status`

Check whether a valid cached token exists.

```bash
blazehash gdrive auth status
```

---

### Chain of Custody & Signing

#### `sign`

Sign a manifest file with a password-derived Ed25519 key.

```bash
blazehash sign manifest.hash
```

Set `BLAZEHASH_SIGN_PASSWORD` to skip the interactive prompt:

```bash
BLAZEHASH_SIGN_PASSWORD=secret blazehash sign manifest.hash
```

The password is fed through Argon2id with a fixed application salt to produce a deterministic Ed25519 key. Same password = same key on any machine.

#### `verify-sig`

Verify a manifest signature against an expected public key.

```bash
blazehash verify-sig manifest.hash --expected-pubkey a3f8e2c1d4b7...
```

Exit code `0` = valid. Exit code `1` = tampered or wrong key.

#### `cosign`

Add a co-signature to a manifest. Each examiner runs this with their own password; N-of-M signatures are required before `verify-msig` passes.

```bash
blazehash cosign manifest.hash
```

#### `verify-msig`

Verify that a manifest has reached the required N-of-M cosignature threshold.

```bash
blazehash verify-msig manifest.hash --threshold 2
```

#### `pq-sign`

Sign a manifest with a CRYSTALS-Dilithium (ML-DSA) post-quantum key. Requires `--features pq` (default-on).

```bash
blazehash pq-sign manifest.hash
```

#### `pq-verify-sig`

Verify a post-quantum ML-DSA signature. Requires `--features pq` (default-on).

```bash
blazehash pq-verify-sig manifest.hash
```

#### `ots stamp`

Anchor a manifest to the Bitcoin blockchain via OpenTimestamps. Creates `manifest.hash.ots`. Requires `--features ots`.

```bash
blazehash ots stamp manifest.hash
```

#### `ots verify`

Verify a previously created OpenTimestamps proof. Requires `--features ots`.

```bash
blazehash ots verify manifest.hash
```

#### `stamp`

Add or update the `## timestamp:` header in a manifest to the current UTC time.

```bash
blazehash stamp manifest.hash
```

#### `report`

Generate an HTML chain-of-custody report from a manifest. Requires `--features report`.

```bash
blazehash report manifest.hash --examiner "Jane Smith" --case "CASE-2026-001" -o report.html
```

#### `qr`

Generate a QR code image from a manifest's root hash. Requires `--features qr`.

```bash
blazehash qr manifest.hash -o manifest-qr.png
```

---

### Tamper Evidence & Selective Disclosure

#### `merkle`

Seal a manifest with a single tamper-evident root hash. Any change to any entry changes the root — you can publish just the root hash to prove the full set was sealed at a specific point in time.

```bash
blazehash merkle manifest.hash
```

#### `merkle-proof`

Prove that a specific file was part of a sealed manifest without revealing any other entries. Share only the proof and root hash — the other files stay private.

```bash
blazehash merkle-proof manifest.hash --path /evidence/file.dd
```

#### `merkle-verify`

Confirm that a file was present when the manifest was sealed. Verifies offline against the root hash — no access to the original manifest required.

```bash
blazehash merkle-verify --root <hex> --path /evidence/file.dd --proof <hex>
```

#### `disclose`

Produce a redacted copy that reveals only the files you choose while proving they belong to the original sealed manifest. Useful when you need to share partial evidence without exposing the full case file.

```bash
blazehash disclose manifest.hash --paths /evidence/critical.dd -o disclosed.hash
```

#### `prove-membership`

Assert that a specific file exists in a manifest — exits `0` if present, `1` if not. Useful in automated pipelines that need to verify a file was captured.

```bash
blazehash prove-membership manifest.hash --path /evidence/file.dd
```

---

### Integrity & Threat Intel

#### `verify`

Re-hash every file listed in a manifest and report mismatches (alias for audit mode without requiring `-a`).

```bash
blazehash verify manifest.hash
```

#### `vt`

Batch VirusTotal lookup for all hashes in a manifest. Requires a VT API key via `--api-key` or `VT_API_KEY`.

```bash
blazehash vt manifest.hash --api-key YOUR_KEY
VT_API_KEY=YOUR_KEY blazehash vt manifest.hash
```

#### `selfcheck`

Verify the integrity of the blazehash binary itself.

```bash
blazehash selfcheck
```

---

### Manifest Analysis

#### `diff`

Compare two manifests and report changes. Output uses `[+]`, `[-]`, `[!]`, `[*]` prefixes. Exit code `0` = identical, `1` = differences.

```bash
blazehash diff before.hash after.hash
```

#### `sym-diff`

Find files that changed between two evidence snapshots — entries that appear in one manifest but not the other. Useful for pinpointing what was added or removed between two collection points.

```bash
blazehash sym-diff before.hash after.hash -o changes.hash
```

#### `info`

Print manifest header metadata: version, algorithm list, case ID, examiner, timestamp.

```bash
blazehash info manifest.hash
```

#### `stats`

Print per-algorithm statistics: entry count, total size, unique hash count.

```bash
blazehash stats manifest.hash
```

#### `count`

Print the number of entries in a manifest.

```bash
blazehash count manifest.hash
```

#### `timeline`

Generate a chronological timeline of file activity from a manifest.

```bash
blazehash timeline manifest.hash
```

#### `tally`

Count entries grouped by extension, directory, or algorithm.

```bash
blazehash tally manifest.hash --tally-by ext
blazehash tally manifest.hash --tally-by dir
```

#### `missing`

List files in the manifest that do not exist on disk.

```bash
blazehash missing manifest.hash
```

---

### Manifest Filtering & Selection

#### `search`

Search entries by path substring or exact hash value.

```bash
blazehash search manifest.hash --search-path "suspicious"
blazehash search manifest.hash --search-hash "a3f8e2c1..."
```

#### `grep`

Filter entries whose path matches a regular expression.

```bash
blazehash grep manifest.hash --pattern "\.exe$" -o executables.hash
```

#### `filter`

Keep only entries computed with a specific algorithm.

```bash
blazehash filter manifest.hash --filter-algo sha256 -o sha256-only.hash
```

#### `head` / `tail`

Print the first or last N entries.

```bash
blazehash head manifest.hash --count 10
blazehash tail manifest.hash --count 10
```

#### `slice`

Extract a range of entries by offset and count.

```bash
blazehash slice manifest.hash --offset 100 --count 50 -o page2.hash
```

#### `sample`

Select N random entries.

```bash
blazehash sample manifest.hash --count 100 -o sample.hash
```

#### `contains`

Exit 0 if a path or hash exists in the manifest, exit 1 otherwise. Useful in shell scripts.

```bash
blazehash contains manifest.hash --search-hash "a3f8e2c1..."
```

#### `intersect`

Keep only entries whose path appears in both manifests (set intersection).

```bash
blazehash intersect a.hash b.hash -o common.hash
```

#### `subtract`

Remove entries from manifest A whose path appears in manifest B (set difference).

```bash
blazehash subtract a.hash b.hash -o diff.hash
```

#### `exclude`

Remove entries matching a path pattern.

```bash
blazehash exclude manifest.hash --exclude-pattern "*.log" -o filtered.hash
```

#### `path-only`

Print only the file paths (strips hashes and metadata).

```bash
blazehash path-only manifest.hash
```

#### `hash-only`

Print only the hash values (strips paths and metadata).

```bash
blazehash hash-only manifest.hash --hash-only-algo blake3
```

---

### Manifest Transformation

#### `merge`

Combine two or more manifests into one. Last-write-wins on duplicate paths.

```bash
blazehash merge a.hash b.hash -o merged.hash
```

#### `update`

Incrementally rehash only changed or new files against an existing manifest.

```bash
blazehash update manifest.hash /path/to/folder
```

#### `cat`

Concatenate two or more manifests. Like `merge` but preserves duplicate path entries.

```bash
blazehash cat a.hash b.hash c.hash -o combined.hash
```

#### `sort`

Sort entries by path, size, or hash.

```bash
blazehash sort manifest.hash --sort-by path -o sorted.hash
blazehash sort manifest.hash --sort-by size -o sorted.hash
```

#### `split`

Split a manifest into N parts by entry count.

```bash
blazehash split manifest.hash --parts 4
# → manifest_part001.hash ... manifest_part004.hash
```

#### `balance`

Split a manifest into N parts of roughly equal total file size — useful when distributing hashing work across multiple machines or verifiers.

```bash
blazehash balance manifest.hash --parts 4
```

#### `interleave`

Combine two manifests by alternating their entries (A, B, A, B, …). Useful for interlacing two partial collections into a single ordered pass before hashing or processing.

```bash
blazehash interleave part-a.hash part-b.hash -o interleaved.hash
```

#### `reverse`

Reverse the entry order of a manifest.

```bash
blazehash reverse manifest.hash -o reversed.hash
```

#### `shuffle`

Randomly reorder entries. Use `--seed` for reproducible output.

```bash
blazehash shuffle manifest.hash --seed 42 -o shuffled.hash
```

#### `normalize`

Normalize a manifest: remove blank lines, fix spacing, sort entries, deduplicate.

```bash
blazehash normalize manifest.hash -o clean.hash
```

#### `repair`

Minimal formatting fix: strip blank lines, normalize separators, drop malformed lines. Less aggressive than `normalize`.

```bash
blazehash repair manifest.hash -o clean.hash
```

#### `rename`

Rewrite path prefixes across all manifest entries.

```bash
blazehash rename manifest.hash --rename-from /mnt/evidence --rename-to /evidence
```

#### `tag`

Add or update header metadata fields in a manifest.

```bash
blazehash tag manifest.hash --set case_id="CASE-2026-002"
blazehash tag manifest.hash --unset examiner
```

#### `annotate`

Add or replace a `## note:` header in a manifest.

```bash
blazehash annotate manifest.hash --note "Reviewed by Jane Smith"
```

#### `pivot`

Produce a copy of a manifest keyed by a different algorithm — useful when you need to cross-reference a BLAKE3 manifest against a legacy SHA-256 database or hand it to a tool that only understands one algorithm.

```bash
blazehash pivot manifest.hash --pivot-algo sha256 -o sha256-keyed.hash
```

#### `apply-patch`

Apply a unified diff patch to a manifest.

```bash
blazehash apply-patch base.hash patch.diff -o updated.hash
```

---

### Deduplication

#### `dedup`

Find duplicate files in a directory or manifest. Exit code `0` = no duplicates, `1` = duplicates found.

```bash
blazehash dedup /mnt/evidence
blazehash dedup manifest.hash
blazehash dedup /mnt/evidence --dedup-unique   # one representative per group
blazehash dedup /mnt/evidence --dedup-dupes    # only the redundant copies
```

#### `duplicates`

Emit all manifest entries whose hash appears more than once.

```bash
blazehash duplicates manifest.hash -o dupes.hash
```

#### `unique-hash`

Keep only the first entry per unique hash — complement to `duplicates`.

```bash
blazehash unique-hash manifest.hash -o deduped.hash
```

#### `uniq`

Deduplicate entries by path — keep the last occurrence of each path.

```bash
blazehash uniq manifest.hash -o deduped.hash
```

#### `first`

Keep the first occurrence of each path — complement to `uniq`.

```bash
blazehash first manifest.hash -o first.hash
```

---

### Format Conversion & Import/Export

#### `convert`

Import a foreign manifest format (md5sum, sha256sum, hashdeep, SFV) and convert to blazehash format.

```bash
blazehash convert md5sums.txt -o manifest.hash
blazehash convert hashes.sfv -o manifest.hash
```

#### `export`

Export a manifest to CSV, JSONL, or TSV.

```bash
blazehash export manifest.hash --export-format csv -o hashes.csv
blazehash export manifest.hash --export-format jsonl -o hashes.jsonl
```

#### `checksum`

Convert a DFXML manifest to a sha256sum-compatible flat file.

```bash
blazehash checksum manifest.dfxml -o hashes.sha256
```

#### `lint`

Validate a manifest for formatting errors, duplicate paths, or missing fields.

```bash
blazehash lint manifest.hash
```

#### `redact`

Remove selected entries from a manifest (privacy redaction / selective disclosure).

```bash
blazehash redact manifest.hash --exclude-pattern "*.pii" -o redacted.hash
```

---

### Utilities

#### `nsrl build-bloom`

Build a bloom filter from an NSRL SQLite database for faster lookups.

```bash
blazehash nsrl build-bloom NSRL.db --output nsrl.bloom
```

#### `bench`

Run benchmarks and GPU calibration.

```bash
blazehash bench --gpu              # measure GPU vs CPU crossover, write config
blazehash bench --gpu --no-calibrate  # use conservative defaults, no config write
```

#### `tui`

Launch the interactive terminal dashboard. Requires `--features tui`.

```bash
blazehash tui manifest.hash
```

#### `mcp`

Start the MCP (Model Context Protocol) server for AI-assisted forensic hashing. See [MCP Server](mcp.md) for details.

```bash
blazehash mcp
```

#### `completions`

Generate shell completion scripts or a man page. Output goes to stdout.

```bash
blazehash completions bash   > /etc/bash_completion.d/blazehash
blazehash completions zsh    > ~/.zsh/completions/_blazehash
blazehash completions fish   > ~/.config/fish/completions/blazehash.fish
blazehash completions powershell >> $PROFILE
blazehash completions man    > blazehash.1 && man ./blazehash.1
```

---

## Remote storage

blazehash accepts remote URIs for both input paths and `-o` output — 50+ protocols supported.

**Full protocol reference:** [Remote Storage →](remote.md)

Common examples:

```bash
# Hash an S3 prefix
blazehash s3://dfir-bucket/case-001/

# Write manifest to S3
blazehash -r /mnt/evidence -o s3://dfir-bucket/case-001.hash

# Audit against a remote manifest
blazehash -r /mnt/evidence -a -k s3://dfir-bucket/case-001.hash

# Hash a Google Drive file
blazehash gdrive://1ABCdef...

# Hash over SFTP
blazehash sftp://admin@192.168.1.10/evidence/disk.dd
```

Supported schemes include: `s3`, `gcs`, `azblob`, `azdls`, `azfile`, `b2`, `cos`, `obs`, `oss`,
`swift`, `upyun`, `gdrive`, `onedrive`, `dropbox`, `aliyun-drive`, `yandex-disk`, `pcloud`,
`koofr`, `seafile`, `github`, `huggingface`, `vercel-blob`, `alluxio`, `hdfs`, `webhdfs`, `lakefs`,
`ipfs`, `ipmfs`, `redis`, `rediss`, `memcached`, `etcd`, `tikv`, `mongodb`, `mysql`, `postgresql`,
`sqlite`, `rocksdb` (opt-in), `cloudflare-kv`, `d1`, `sftp`, `ftp`, `ftps`, `webdav`, `http`,
`https`, `compfs`, `monoiofs` (Linux), `file`, `mem`.

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
