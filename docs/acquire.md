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

## Hash a Google Drive file without downloading

blazehash hashes a Google Drive file entirely in memory — no temporary copy lands on disk. Pass the URL or `gdrive://` URI directly as the path argument:

```bash
blazehash https://drive.google.com/file/d/FILE_ID/view
blazehash gdrive://FILE_ID
```

All of the following URL and ID formats are accepted:

| Input | Example |
|-------|---------|
| Share link (`/file/d/<id>/view`) | `blazehash https://drive.google.com/file/d/1a2B.../view` |
| Open link (`open?id=<id>`) | `blazehash https://drive.google.com/open?id=1a2B...` |
| `gdrive://` URI | `blazehash gdrive://1a2B...` |

Output follows the standard blazehash format:

```
<hash>  gdrive://<file-id>
```

### Authentication

blazehash tries the following auth methods in order:

1. **Cached OAuth token** — if you have previously run `blazehash gdrive auth login`, the stored token at `~/.config/blazehash/gdrive_token.json` is used automatically.
2. **Public download** — if no token is cached, blazehash falls back to an unauthenticated download (works only for files shared publicly).

### `blazehash gdrive auth login`

Opens a browser-based OAuth consent flow and caches the resulting token:

```bash
blazehash gdrive auth login
```

After the browser redirects back and you see a success message, the token is saved to `~/.config/blazehash/gdrive_token.json`. Subsequent Google Drive hashing picks it up automatically, giving access to any file your Google account can reach.

To verify the stored token is valid:

```bash
blazehash gdrive auth status
```

---

## What to do next

After acquisition, build the full chain-of-custody package: [Building Court-Ready Evidence](custody.md).
