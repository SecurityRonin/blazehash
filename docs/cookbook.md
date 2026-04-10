# Cookbook

Real-world scenarios with exact commands. Each recipe solves a specific problem.

---

## Document evidence before imaging

You have a hard drive mounted at `/mnt/evidence` and need to record its contents before creating a forensic image.

**Step 1: Quick inventory (no hashing)**

```bash
blazehash -r /mnt/evidence -s -o inventory.txt
```

This lists every file with its size. Takes seconds, even on large drives. Review the inventory to confirm you have the right volume.

**Step 2: Full hash with dual algorithms and signature**

```bash
blazehash -r /mnt/evidence -c blake3,sha256 -o pre-image.hash --sign
```

SHA-256 for court acceptance. BLAKE3 for speed and a second independent hash. The `--sign` flag signs the manifest immediately.

```
[+] Public key: a3f8e2c1d4b7...
```

Record the public key in your case notes.

---

## Verify a received hard drive

You received a hard drive with an accompanying manifest and signature. Verify nothing was altered in transit.

```bash
blazehash -r /mnt/received -a -k received.hash --expected-pubkey a3f8e2c1d4b7...
```

blazehash first checks the manifest signature. If valid, it re-hashes every file and compares against the manifest. Any mismatch, missing file, or unexpected file is reported.

---

## Detect file tampering on a live system

You suspect files were modified on a running server. Hash without touching the OS page cache to avoid disturbing memory evidence:

```bash
blazehash -r /var/www -a -k baseline.hash --no-cache
```

`--no-cache` uses direct I/O, reading straight from disk without loading file contents into the OS cache.

---

## Find duplicate files in a case

Identify redundant files to reduce review time:

```bash
blazehash dedup /mnt/evidence
```

Output groups duplicates together:

```
## 3 copies:
  /evidence/file_a.bin
  /evidence/backup/file_a.bin    ← redundant
  /evidence/copy2/file_a.bin     ← redundant

[+] 1,247 files — 1,244 unique, 1 duplicate group, 2 redundant copies (0.3 GiB reclaimable)
```

To get just the duplicates (for scripting):

```bash
blazehash dedup /mnt/evidence --dedup-dupes
```

To get one representative per group (what to keep):

```bash
blazehash dedup /mnt/evidence --dedup-unique
```

---

## Find malware variants with fuzzy hashing

Cryptographic hashes miss near-matches. A single-byte change produces a completely different hash. Fuzzy hashing detects similar files.

**Step 1: Hash the known malware samples**

```bash
blazehash -r /samples/known -c blake3,ssdeep -o known-malware.hash
```

**Step 2: Scan the target with fuzzy audit**

```bash
blazehash -r /mnt/evidence -a -k known-malware.hash -c ssdeep --fuzzy-threshold 70 --fuzzy-top 3
```

Files with 70%+ similarity to known samples appear as fuzzy matches:

```
[~] payload.exe  FUZZY MATCH sim=87%  ← malware/variant_a.exe
[~] dropper.dll  FUZZY MATCH sim=73%  ← malware/loader.dll
```

!!! tip
    Use `ssdeep` for file fragments and near-duplicate documents. Use `tlsh` for larger files (>50 bytes) where locality sensitivity matters.

---

## hashdeep-compatible output for existing workflows

blazehash writes hashdeep-compatible manifests by default. For maximum compatibility with existing scripts:

```bash
blazehash -r /mnt/evidence -c md5,sha256 --format hashdeep -o manifest.hash
```

The output uses the `HASHDEEP-1.0` header and is directly consumable by hashdeep's audit mode.

---

## Export to a case management tool (DFXML)

DFXML (Digital Forensics XML) is the standard import format for Autopsy, The Sleuth Kit, and other forensic platforms:

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
```

---

## Resume a crashed hash run

A 10 TiB drive takes hours to hash. If the process crashes or is interrupted, you don't have to start over:

```bash
blazehash -r /mnt/evidence -o manifest.hash --resume
```

blazehash reads the partial manifest, identifies which files were already hashed, and continues from where it left off.

!!! note
    `--resume` requires `-o` (output file). blazehash reads the existing output to determine which files to skip.

---

## Skip known Windows system files (NSRL)

The NIST NSRL catalogs hashes of known operating system and application files. Filter them out to focus on files that actually need examination.

**One-time setup: build a bloom filter for fast lookups**

```bash
blazehash nsrl build-bloom NSRL.db --output nsrl.bloom
```

**Annotate known-good files:**

```bash
blazehash -r /mnt/evidence -c sha256 --nsrl nsrl.bloom
```

Known-good files get a `[K]` prefix. Everything else is printed normally.

**Remove known-good files from output entirely:**

```bash
blazehash -r /mnt/evidence -c sha256 --nsrl NSRL.db --nsrl-exclude
```

!!! warning
    Use the SQLite database (not bloom filter) with `--nsrl-exclude`. Bloom filters have a ~0.1% false-positive rate, which means a small number of non-NSRL files could be silently suppressed.

---

## Court-admissible chain of custody

A complete chain-of-custody workflow for evidence handling:

**Step 1: Hash and sign at acquisition**

```bash
blazehash -r /mnt/evidence -c blake3,sha256 -o evidence.hash --sign
```

Record the public key: `a3f8e2c1d4b7...`

**Step 2: Transfer evidence and manifest**

Ship the drive, `evidence.hash`, and `evidence.hash.sig` together. Communicate the public key through a separate channel (email, case management system, in person).

**Step 3: Verify at destination**

```bash
blazehash verify-sig evidence.hash --expected-pubkey a3f8e2c1d4b7...
```

**Step 4: Audit the files**

```bash
blazehash -r /mnt/evidence -a -k evidence.hash --expected-pubkey a3f8e2c1d4b7...
```

If both the signature and all file hashes pass, you have cryptographic proof that the evidence is identical to what was originally acquired.

---

## Find hidden ADS data on Windows

NTFS Alternate Data Streams can hide data alongside normal files. Scan for them:

```bash
blazehash -r C:\Evidence --ads
```

ADS entries appear as separate hash entries with the stream name appended (e.g., `C:\Evidence\file.txt:hidden_stream`).

!!! note
    The `--ads` flag is Windows-only. On macOS and Linux it is accepted but has no effect.

---

## Verify a forensic disk image

**E01 / EWF images (EnCase format):**

```bash
blazehash --verify-image case.E01
```

blazehash verifies stored checksums against recomputed values. Multi-segment images (`.E01`, `.E02`, `.E03`, ...) are detected automatically.

**Raw / DD images with sidecar hash files:**

```bash
blazehash --verify-image disk.raw
```

blazehash looks for `.md5`, `.sha256`, `.sha512`, and `.blake3` sidecar files alongside the image and verifies against each one found.

---

## Hash large files in chunks

For very large files where you need to verify specific regions:

```bash
blazehash -r /mnt/evidence -p 1G
```

Each file produces one hash entry per 1 GiB chunk. Useful for detecting targeted modifications within large database files or disk images, and for verifying partial file transfers.
