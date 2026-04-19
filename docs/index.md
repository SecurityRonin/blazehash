# blazehash

**Hash. Sign. Timestamp. Prove.**

The only open-source forensic hashing tool that answers every question a court asks about digital evidence — *what* changed, *who* handled it, *when* it was sealed, and *in what context* — in a single binary that's drop-in compatible with hashdeep.

Now with **50+ remote storage backends** built in via Apache OpenDAL: hash from S3, GCS, Azure Blob, WebDAV, SFTP, and more — no extra flags required. Hash Google Drive files in memory with `gdrive-collect` — no local copy needed.

```bash
# Acquire evidence with chain-of-custody metadata
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --progress

# Hash evidence on S3, write manifest back to S3
blazehash hash s3://dfir-bucket/case-001/ -o s3://dfir-bucket/case-001.hash

# Sign (prompts for password)
blazehash sign evidence.hash
# → evidence.hash.sig  (Ed25519 signature)
# → evidence.hash.pub  (public key — record this)

# Anchor to Bitcoin blockchain
blazehash ots stamp evidence.hash
# → evidence.hash.ots  (pending proof, confirmed ~1 hr)

# Verify everything, months later
blazehash verify-sig evidence.hash
blazehash ots verify evidence.hash
blazehash -r /mnt/evidence -a -k evidence.hash
```

No other open-source tool delivers all four in one binary.

---

## What Do You Need To Do?

<div class="grid cards" markdown>

-   **I'm acquiring evidence**

    Hash a drive or folder with signed, timestamped, court-ready output.

    [Acquire Evidence](acquire.md){ .md-button }

-   **I need court-ready documentation**

    Build a complete chain-of-custody package: sign, cosign, timestamp, report.

    [Build Chain of Custody](custody.md){ .md-button }

-   **I'm hunting threats**

    Filter known-good, flag known-bad, scan YARA rules, check VirusTotal.

    [Hunt Threats](hunt.md){ .md-button }

-   **I'm feeding a SIEM**

    Export to ECS NDJSON, STIX 2.1, Parquet, SQLite, or DuckDB.

    [SIEM & Analytics](siem.md){ .md-button }

</div>

---

## Install

=== "Debian / Ubuntu / Kali"

    ```bash
    curl -1sLf 'https://dl.cloudsmith.io/public/securityronin/blazehash/setup.deb.sh' | sudo bash
    sudo apt install blazehash
    ```

=== "macOS"

    ```bash
    brew tap SecurityRonin/tap && brew install blazehash
    ```

=== "Windows"

    ```powershell
    winget install SecurityRonin.blazehash
    ```

    Or download the `.msi` from [GitHub Releases](https://github.com/SecurityRonin/blazehash/releases).

=== "Cargo (all platforms)"

    ```bash
    cargo install blazehash
    ```

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
| Live monitoring (watch) | Y | -- | -- | -- |
| BLAKE3 (1,640 MB/s) | Y | -- | Y | -- |
| GPU-accelerated SHA-256/MD5 | Y | -- | -- | -- |
| 14 algorithms simultaneous | Y | -- | -- | -- |
| Direct I/O (no page cache) | Y | -- | -- | -- |
| STIX 2.1 / ECS NDJSON output | Y | -- | -- | -- |
| SQLite / Parquet / DuckDB | Y | -- | -- | -- |
| Piecewise hashing | Y | Y | -- | -- |
| hashdeep / DFXML / CSV / JSON | Y | partial | -- | -- |
| Remote storage (S3/GCS/Azure/WebDAV) | Y | -- | -- | -- |
| Google Drive hashing (no download) | Y | -- | -- | -- |

---

## Performance

Benchmarked on Apple M4 Pro (14-core, 48 GB RAM), warm cache. Full methodology: [benchmarks](benchmarks.md).

| Workload | blazehash | hashdeep v4.4 | Speedup |
|----------|----------:|---------:|--------:|
| 1 GiB, SHA-256 | 2,182 ms | 2,485 ms | **1.14x** |
| 1 GiB, MD5 | 1,447 ms | 2,135 ms | **1.48x** |
| 1 GiB, SHA-1 | 879 ms | 1,803 ms | **2.05x** |
| 1 GiB, BLAKE3 | 655 ms | *n/a* | -- |

BLAKE3 at **1,640-1,780 MB/s** — 2.8x faster than hashdeep's best algorithm and cryptographically stronger.

---

## Why This Exists

[hashdeep](https://github.com/jessek/hashdeep) — written by Jesse Kornbluth and Simson Garfinkel — gave the forensic community its canonical file hashing and audit tool. Court-tested workflows have depended on it for over a decade.

**blazehash** is a continuation, not a replacement. Every hashdeep flag works exactly as you expect. The output format is compatible. Your existing scripts and court-tested procedures keep working. We add what the community needs: speed, modern algorithms, signing with multi-party cosigning, Bitcoin-anchored timestamps, NSRL filtering, YARA scanning, and the subcommands forensic practitioners actually reach for.

---

## Acknowledgements

**Jesse Kornbluth** created [hashdeep](https://github.com/jessek/hashdeep) and gave it to the forensic community as a public domain tool. blazehash would not exist without that foundation.

**Simson Garfinkel** co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML standard.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn — designed the hash function that makes blazehash fast enough to matter.
