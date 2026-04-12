# Cookbook

Real-world scenarios with exact commands. Each recipe solves a specific problem.

---

## Complete chain-of-custody pipeline

Hash, sign, cosign, timestamp, report, verify -- the full workflow for court-ready evidence.

```bash
# Hash with metadata
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --no-cache --progress

# Sign
BLAZEHASH_SIGN_PASSWORD="..." blazehash sign evidence.hash

# Second examiner cosigns
BLAZEHASH_SIGN_PASSWORD="..." blazehash cosign evidence.hash

# Bitcoin timestamp
blazehash ots stamp evidence.hash

# HTML report
blazehash report evidence.hash \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence-report.html

# Verify everything
blazehash verify-sig evidence.hash
blazehash verify-msig evidence.hash --threshold 2
blazehash ots verify evidence.hash
blazehash -r /mnt/evidence -a -k evidence.hash
```

For the full walkthrough of each step, see [Building Court-Ready Evidence](custody.md).

---

## Document evidence before imaging

You have a hard drive mounted at `/mnt/evidence` and need to record its contents before creating a forensic image.

**Quick inventory (no hashing):**

```bash
blazehash -r /mnt/evidence -s -o inventory.txt
```

**Full hash with dual algorithms and signature:**

```bash
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o pre-image.hash
blazehash sign pre-image.hash
```

Record the public key in your case notes.

---

## Verify a received hard drive

You received a hard drive with an accompanying manifest and signature. Verify nothing was altered in transit.

```bash
blazehash verify-sig received.hash --expected-pubkey a3f8e2c1d4b7...
blazehash -r /mnt/received -a -k received.hash --expected-pubkey a3f8e2c1d4b7...
```

blazehash checks the signature first. If valid, re-hashes every file and compares against the manifest. Any mismatch, missing file, or unexpected file is reported.

---

## Detect file tampering on a live system

Hash without touching the OS page cache to avoid disturbing memory evidence:

```bash
blazehash -r /var/www -a -k baseline.hash --no-cache
```

`--no-cache` uses direct I/O, reading straight from disk without loading file contents into the OS cache.

---

## Find duplicate files in a case

```bash
blazehash dedup /mnt/evidence
```

Output groups duplicates together:

```
## 3 copies:
  /evidence/file_a.bin
  /evidence/backup/file_a.bin    <- redundant
  /evidence/copy2/file_a.bin     <- redundant

[+] 1,247 files -- 1,244 unique, 1 duplicate group, 2 redundant copies (0.3 GiB reclaimable)
```

**Just the duplicates (for scripting):**

```bash
blazehash dedup /mnt/evidence --dedup-dupes
```

**One representative per group (what to keep):**

```bash
blazehash dedup /mnt/evidence --dedup-unique
```

---

## Find malware variants with fuzzy hashing

**Hash known malware samples:**

```bash
blazehash -r /samples/known -c blake3,ssdeep -o known-malware.hash
```

**Scan the target:**

```bash
blazehash -r /mnt/evidence -a -k known-malware.hash -c ssdeep --fuzzy-threshold 70 --fuzzy-top 3
```

```
[~] payload.exe  FUZZY MATCH sim=87%  <- malware/variant_a.exe
[~] dropper.dll  FUZZY MATCH sim=73%  <- malware/loader.dll
```

!!! tip
    Use `ssdeep` for file fragments and near-duplicate documents. Use `tlsh` for larger files (>50 bytes) where locality sensitivity matters.

---

## Triage with NSRL + HashDB + YARA + entropy

Single command, maximum intelligence:

```bash
blazehash -r /mnt/suspect -c sha256 \
  --nsrl NSRL.db --nsrl-exclude \
  --hashdb-bad malware-hashes.txt \
  --yara rules.yar \
  --entropy \
  -o triage.hash --progress
```

Then check unknowns against VirusTotal:

```bash
VT_API_KEY="..." blazehash vt triage.hash
```

For the full threat hunting workflow, see [Hunt Threats](hunt.md).

---

## hashdeep-compatible output for existing workflows

```bash
blazehash -r /mnt/evidence -c md5,sha256 --format hashdeep -o manifest.hash
```

The output uses the `HASHDEEP-1.0` header and is directly consumable by hashdeep's audit mode.

---

## Export to a case management tool (DFXML)

```bash
blazehash -r /mnt/evidence -c sha256 --format dfxml -o report.xml
```

Other export formats:

```bash
# CSV for spreadsheets
blazehash -r /mnt/evidence --format csv -o results.csv

# JSON for programmatic processing
blazehash -r /mnt/evidence --format json -o results.json

# JSONL for streaming / line-by-line processing
blazehash -r /mnt/evidence --format jsonl -o results.jsonl

# sha256sum-compatible output
blazehash -r /mnt/evidence -c sha256 --format sha256sum -o hashes.sha256

# ECS NDJSON for Elastic / Splunk
blazehash -r /mnt/evidence --format ecs -o evidence.ndjson

# STIX 2.1 for threat intel platforms
blazehash -r /mnt/evidence --format stix -o evidence.stix.json

# Parquet for data lakes
blazehash -r /mnt/evidence --format parquet -o evidence.parquet

# DuckDB
blazehash -r /mnt/evidence --format duckdb -o evidence.duckdb

# SQLite
blazehash -r /mnt/evidence --format sqlite -o evidence.db
```

For SIEM-specific ingestion details, see [SIEM & Analytics](siem.md).

---

## Resume a crashed hash run

```bash
blazehash -r /mnt/evidence -o manifest.hash --resume
```

blazehash reads the partial manifest, identifies which files were already hashed, and continues from where it left off.

!!! note
    `--resume` requires `-o` (output file). blazehash reads the existing output to determine which files to skip.

---

## Skip known Windows system files (NSRL)

**Annotate known-good files:**

```bash
blazehash -r /mnt/evidence -c sha256 --nsrl NSRL.db
```

Known-good files get a `[K]` prefix.

**Remove known-good files from output entirely:**

```bash
blazehash -r /mnt/evidence -c sha256 --nsrl NSRL.db --nsrl-exclude
```

---

## Verify a forensic disk image

**E01 / EWF images (EnCase format):**

```bash
blazehash --verify-image case.E01
```

Multi-segment images (`.E01`, `.E02`, `.E03`, ...) detected automatically.

**Raw / DD images with sidecar hash files:**

```bash
blazehash --verify-image disk.raw
```

blazehash looks for `.md5`, `.sha256`, `.sha512`, `.blake3` sidecar files alongside the image.

---

## Hash large files in chunks

```bash
blazehash -r /mnt/evidence -p 1G
```

One hash entry per 1 GiB chunk per file. Useful for detecting targeted modifications within large database files or disk images.

---

## Find hidden ADS data on Windows

```bash
blazehash -r C:\Evidence --ads
```

ADS entries appear as `filename:stream_name` in the output.

!!! note
    The `--ads` flag is Windows-only. On macOS and Linux it is accepted but has no effect.

---

## Compare two directory trees

```bash
blazehash diff baseline/ current/
```

Uses the same `[+]`, `[-]`, `[!]`, `[*]` prefixes as audit mode. For unified diff output:

```bash
blazehash diff baseline/ current/ --patch
```

---

## Live monitoring

Watch a directory for changes against a baseline:

```bash
blazehash watch /path/to/folder -k manifest.hash
```

Alerts immediately when a file is modified, added, or deleted.

---

## Docker / OCI image hashing

```bash
blazehash image nginx:latest
```

Hashes each layer of the container image independently.

---

## Shell completions

```bash
blazehash completions bash > /etc/bash_completion.d/blazehash
blazehash completions zsh  > ~/.zsh/completions/_blazehash
blazehash completions fish > ~/.config/fish/completions/blazehash.fish
```

---

## Interactive TUI

```bash
blazehash tui -r /large-dir
```

Live progress dashboard showing per-file progress, throughput, and a running manifest preview. Press `q` to exit.
