# blazehash

**hashdeep, at 2026 speed.**

Forensic file hashing with BLAKE3 by default, GPU acceleration, Ed25519 manifest signing, and full hashdeep compatibility. Point this at a folder. Get a manifest. Sign it. Done.

```bash
blazehash -r /mnt/evidence -c blake3,sha256 -o manifest.hash --sign
```

```
blazehash v0.3.0 — BLAKE3 + SHA-256, 16 threads, mmap I/O
[*] Scanning /mnt/evidence recursively
[+] 847,293 files hashed (2.14 TiB) in 38.7s
[+] Manifest written to manifest.hash
[+] Public key: a3f8e2... (record this for verification)
[+] Signature:  manifest.hash.sig
```

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

## Quick Start

**Hash a folder and save the results:**

```bash
blazehash -r /path/to/folder -o manifest.hash
```

**Check if anything changed:**

```bash
blazehash -r /path/to/folder -a -k manifest.hash
```

**Sign the manifest for chain of custody:**

```bash
blazehash sign manifest.hash
```

[Get started with the full walkthrough.](getting-started.md){ .md-button }

---

## Feature Comparison

| Feature | blazehash | hashdeep | b3sum | sha256sum |
|---------|:---------:|:--------:|:-----:|:---------:|
| Audit mode | Y | Y | — | — |
| Manifest signing (Ed25519) | Y | — | — | — |
| Manifest diff | Y | — | — | — |
| Duplicate detection | Y | — | — | — |
| NSRL known-good filtering | Y | — | — | — |
| Fuzzy / similarity hashing | Y | — | — | — |
| Piecewise hashing | Y | Y | — | — |
| Resume interrupted runs | Y | — | — | — |
| EWF / E01 image verification | Y | — | — | — |
| NTFS ADS hashing | Y | — | — | — |
| MCP server (AI-assisted) | Y | — | — | — |
| Multithreaded hashing | Y | — | Y | — |
| Memory-mapped I/O | Y | — | Y | — |
| GPU acceleration | Y | — | — | — |
| Direct I/O (no page cache) | Y | — | — | — |
| BLAKE3 | Y | — | Y | — |
| 14 algorithms simultaneous | Y | — | — | — |
| hashdeep / DFXML / CSV / JSON | Y | partial | — | — |

---

## Performance

Benchmarked on Apple M4 Pro (14-core, 48 GB RAM), warm cache. Full methodology: [benchmarks](benchmarks.md).

| Workload | blazehash | hashdeep v4.4 | Speedup |
|----------|----------:|----------:|--------:|
| 256 MiB file, SHA-256 | 854 ms | 930 ms | **1.09x** |
| 1,000 small files, SHA-256 | 20 ms | 69 ms | **3.43x** |
| 256 MiB file, BLAKE3 | 187 ms | *n/a* | **~5x vs hashdeep SHA-256** |

---

## Why This Exists

[hashdeep](https://github.com/jessek/hashdeep) — written by Jesse Kornbluth and Simson Garfinkel — gave the forensic community its canonical file hashing and audit tool. Court-tested workflows have depended on it for over a decade.

But hashdeep hasn't had a release since v4.4. It doesn't support BLAKE3. It doesn't use multiple cores. It can't sign manifests. It can't filter by NSRL. It can't detect duplicates or diff two sessions.

**blazehash** is a continuation, not a replacement. Every hashdeep flag works exactly as you expect. The output format is compatible. Your existing scripts and court-tested procedures keep working. We add what the community needs: speed, modern algorithms, signing, NSRL filtering, and the subcommands that forensic practitioners actually reach for.

---

## Acknowledgements

**Jesse Kornbluth** created [hashdeep](https://github.com/jessek/hashdeep) and gave it to the forensic community as a public domain tool. blazehash would not exist without that foundation.

**Simson Garfinkel** co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML standard.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn — designed the hash function that makes blazehash fast enough to matter.
