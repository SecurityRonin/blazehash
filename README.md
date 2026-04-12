# blazehash

[![Crates.io](https://img.shields.io/crates/v/blazehash.svg)](https://crates.io/crates/blazehash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/actions/workflows/ci.yml)
[![Release](https://github.com/SecurityRonin/blazehash/actions/workflows/release.yml/badge.svg)](https://github.com/SecurityRonin/blazehash/releases)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Hash. Sign. Timestamp. Prove.**

The only open-source forensic hashing tool that answers all four questions a court asks about digital evidence: *what* (cryptographic hashes), *who* (Ed25519 signing), *when* (Bitcoin-anchored timestamps), and *context* (case/examiner metadata) — in a single binary that's drop-in compatible with hashdeep.

```bash
# Acquire evidence with chain-of-custody metadata
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --progress

# Sign the manifest
BLAZEHASH_SIGN_PASSWORD="..." blazehash sign evidence.hash

# Second examiner cosigns
BLAZEHASH_SIGN_PASSWORD="..." blazehash cosign evidence.hash

# Anchor to Bitcoin blockchain
blazehash ots stamp evidence.hash

# Verify everything, months later
blazehash verify-sig evidence.hash
blazehash verify-msig evidence.hash --threshold 2
blazehash ots verify evidence.hash
blazehash -r /mnt/evidence -a -k evidence.hash
```

Your evidence, proved.

**[Full documentation](https://securityronin.github.io/blazehash/)**

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

**Cargo (all platforms)**
```bash
cargo install blazehash
```

---

## Three Things You Do With This

### Acquire evidence
Hash a drive or folder, sign it, timestamp it, generate an HTML report. One pipeline, court-ready output.

```bash
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --progress
blazehash sign evidence.hash
blazehash ots stamp evidence.hash
blazehash report evidence.hash -o report.html
```

[Acquisition guide](https://securityronin.github.io/blazehash/acquire/) | [Chain-of-custody guide](https://securityronin.github.io/blazehash/custody/)

### Verify integrity
Come back days, weeks, or months later. Verify nothing was tampered with.

```bash
blazehash -r /mnt/evidence -a -k evidence.hash
blazehash verify-sig evidence.hash
blazehash ots verify evidence.hash
```

### Hunt threats
Filter known-good (NSRL), flag known-bad (HashDB), scan with YARA, check VirusTotal, spot encrypted/packed files by entropy.

```bash
blazehash -r /mnt/suspect -c sha256 \
  --nsrl NSRL.db --nsrl-exclude \
  --hashdb-bad malware.txt \
  --yara rules.yar --entropy
```

[Threat hunting guide](https://securityronin.github.io/blazehash/hunt/) | [SIEM integration guide](https://securityronin.github.io/blazehash/siem/)

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
| NTFS ADS hashing | Y | -- | -- | -- |
| Live monitoring (watch) | Y | -- | -- | -- |
| MCP server (AI-assisted) | Y | -- | -- | -- |
| BLAKE3 (1,640 MB/s) | Y | -- | Y | -- |
| GPU-accelerated SHA-256/MD5 | Y | -- | -- | -- |
| 14 algorithms simultaneous | Y | -- | -- | -- |
| Direct I/O (no page cache) | Y | -- | -- | -- |
| STIX 2.1 / ECS NDJSON output | Y | -- | -- | -- |
| SQLite / Parquet / DuckDB output | Y | -- | -- | -- |
| Piecewise hashing | Y | Y | -- | -- |
| hashdeep / DFXML / CSV / JSON | Y | partial | -- | -- |

---

## Performance

Apple M4 Pro, macOS 15.7.5, warm cache, n=7 runs. Full methodology: **[docs/benchmarks.md](docs/benchmarks.md)**.

| Workload | blazehash | hashdeep | Speedup |
|----------|----------:|---------:|--------:|
| 1 GiB, SHA-256 | 2,182 ms | 2,485 ms | **1.14x** |
| 1 GiB, MD5 | 1,447 ms | 2,135 ms | **1.48x** |
| 1 GiB, SHA-1 | 879 ms | 1,803 ms | **2.05x** |
| 1 GiB, BLAKE3 | 655 ms | *n/a* | -- |

BLAKE3 runs at **1,640-1,780 MB/s** — 2.8x faster than hashdeep's best (SHA-1 at 595 MB/s) and cryptographically stronger.

Small-file caveat: hashdeep's single-threaded C loop has lower per-file overhead for files under ~10 KiB. See [benchmarks](docs/benchmarks.md) for details.

---

## Optional Feature Flags

```bash
cargo install blazehash --features yara,report,docker,parquet-output,ots
```

| Flag | Enables |
|------|---------|
| `nsrl` | SQLite NSRL database + `--format sqlite` |
| `yara` | `--yara <rules.yar>` scanning |
| `report` | `blazehash report` HTML generation |
| `docker` | `blazehash image` OCI/Docker hashing |
| `parquet-output` | `--format parquet` output |
| `ots` | `blazehash ots stamp/verify` Bitcoin timestamps |
| `tui` | `blazehash tui` interactive dashboard |
| `hashdb` | `--hashdb-bad` known-bad flagging |

---

## Why This Exists

[hashdeep](https://github.com/jessek/hashdeep) — written by Jesse Kornbluth and Simson Garfinkel — gave the forensic community its canonical file hashing and audit tool. Court-tested workflows have depended on it for over a decade. It is public domain, auditable, and honest.

**blazehash** is a continuation, not a replacement. Every hashdeep flag works as expected. The output format is compatible. Your existing scripts keep working. We add what the community needs next: BLAKE3, GPU acceleration, Ed25519 signing with multi-party cosigning, Bitcoin-anchored timestamps, NSRL filtering, YARA scanning, and the subcommands forensic practitioners actually reach for.

---

## Acknowledgements

**Jesse Kornbluth** created [hashdeep](https://github.com/jessek/hashdeep) and gave it to the forensic community as a public domain tool.

**Simson Garfinkel** co-authored hashdeep and created [DFXML](https://github.com/simsong/dfxml), the Digital Forensics XML standard.

The [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3) — Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, and Zooko Wilcox-O'Hearn.

## Author

**Albert Hui** ([@h4x0r](https://github.com/h4x0r)) · [@SecurityRonin](https://github.com/SecurityRonin)

## License

[MIT License](LICENSE)
