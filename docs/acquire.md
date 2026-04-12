# Acquire Evidence

Exact commands for hashing drives, folders, and forensic images with signed, timestamped output.

---

## Hash a folder with dual algorithms

```bash
blazehash -r /mnt/evidence -c blake3,sha256 -o evidence.hash
```

SHA-256 for court acceptance. BLAKE3 for speed and an independent second hash.

---

## Hash with chain-of-custody metadata

```bash
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash
```

Case ID and examiner name are embedded in the manifest header and carried through to every downstream format (HTML report, DFXML, JSON, STIX).

---

## Full acquisition pipeline

```bash
# Hash with metadata, direct I/O, progress bar
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --no-cache --progress

# Sign
BLAZEHASH_SIGN_PASSWORD="..." blazehash sign evidence.hash
# -> evidence.hash.sig + evidence.hash.pub

# Timestamp
blazehash ots stamp evidence.hash
# -> evidence.hash.ots

# HTML report
blazehash report evidence.hash -o evidence-report.html
```

You now have five files: the manifest, signature, public key, OTS proof, and HTML report. Ship them all with the evidence.

---

## Multi-examiner acquisition

Two or more examiners independently sign the same manifest:

```bash
# First examiner signs
BLAZEHASH_SIGN_PASSWORD="..." blazehash sign evidence.hash

# Second examiner cosigns
BLAZEHASH_SIGN_PASSWORD="..." blazehash cosign evidence.hash

# Verify both signatures are present
blazehash verify-msig evidence.hash --threshold 2
```

Each examiner uses their own password. The `.msig` file accumulates signatures.

---

## Large acquisition with resume

For multi-terabyte runs that may be interrupted:

```bash
blazehash -r /mnt/evidence -c blake3,sha256 \
  -o evidence.hash --no-cache --progress --resume
```

`--resume` reads the partial manifest and continues from where it left off. `--no-cache` bypasses the OS page cache so you don't blow out RAM on a 4 TiB drive.

---

## Raw block device

Hash an entire disk, including deleted files and slack space:

```bash
blazehash hash /dev/sda --sector-size 512 -o disk.hash
```

Reads bypass the filesystem entirely. Requires root/admin.

---

## EWF / E01 image verification

Verify a forensic image acquired with FTK Imager, EnCase, or similar:

```bash
blazehash --verify-image case.E01
```

Multi-segment images (`.E01`, `.E02`, `.E03`, ...) are detected automatically. blazehash decompresses each segment and recomputes the stored checksums.

For raw/DD images with sidecar hash files:

```bash
blazehash --verify-image disk.raw
```

blazehash looks for `.md5`, `.sha256`, `.sha512`, `.blake3` sidecar files alongside the image.

---

## Quick inventory before hashing

List files and sizes without computing hashes (takes seconds on any drive):

```bash
blazehash -r /mnt/evidence -s -o inventory.txt
```

Review the inventory to confirm you have the right volume before committing to a full hash run.

---

## Hash data from stdin

```bash
cat suspicious.bin | blazehash --stdin -c sha256,md5
```

---

## Hash large files in chunks

For verifying specific regions of large files or partial transfers:

```bash
blazehash -r /mnt/evidence -p 1G
```

One hash entry per 1 GiB chunk per file.

---

## NTFS Alternate Data Streams (Windows)

```bash
blazehash -r C:\Evidence --ads
```

ADS entries appear as `filename:stream_name` in the output. The `--ads` flag is Windows-only; no-op on other platforms.

---

## What to do next

After acquisition, build the full chain-of-custody package: [Building Court-Ready Evidence](custody.md).
