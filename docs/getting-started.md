# Getting Started

From first install to a signed, timestamped manifest in five minutes.

---

## Hash a single file

```bash
blazehash report.pdf
```

```
%%%% BLAZEHASH-1.0
%%%% size,blake3,filename
## blazehash v0.3.0
1048576,af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,/home/user/report.pdf
```

BLAKE3 by default. If the file changes by even one bit, the hash changes completely.

---

## Hash a folder

```bash
blazehash -r /mnt/evidence
```

`-r` walks the entire directory tree recursively. Output goes to the terminal by default.

---

## Save to a manifest

```bash
blazehash -r /mnt/evidence -o manifest.hash
```

`manifest.hash` is your snapshot: every file's path, size, and hash at the time you ran the command.

---

## Verify nothing changed

```bash
blazehash -r /mnt/evidence -a -k manifest.hash
```

`-a` enables audit mode. `-k` points to your saved manifest. blazehash re-hashes every file and compares.

```
[+] Audit complete: 1,247 files matched, 0 mismatches
```

Exit code `0` = all clear. Exit code `1` = something changed.

---

## Sign the manifest

```bash
blazehash sign manifest.hash
```

You'll be prompted for a password. blazehash derives an Ed25519 signing key from your password using Argon2id. Same password always produces the same key -- no key files to manage.

```
[+] Public key: a3f8e2c1d4b7...
[+] Signature:  manifest.hash.sig
```

!!! warning "Record your public key"
    Write down or save the public key. Anyone verifying your signature needs it. The same password always produces the same public key, but you should record it separately as proof.

---

## Verify a signature

```bash
blazehash verify-sig manifest.hash --expected-pubkey a3f8e2c1d4b7...
```

Exit code `0` = valid. Exit code `1` = tampered or wrong key.

!!! tip "Audit auto-verifies signatures"
    When you audit with `--expected-pubkey`, blazehash checks the signature before comparing any hashes. Invalid signature aborts the audit immediately.

    ```bash
    blazehash -r /mnt/evidence -a -k manifest.hash --expected-pubkey a3f8e2c1d4b7...
    ```

---

## Audit output prefixes

| Prefix | Meaning |
|--------|---------|
| `[ok]` | Hash matches the manifest |
| `[!]` | Hash **changed** -- file was modified |
| `[-]` | File **missing** -- was in manifest, gone from disk |
| `[+]` | File **added** -- on disk but not in manifest |
| `[*]` | File **moved** -- same hash, different path |
| `[~]` | **Fuzzy match** -- similar but not identical (requires ssdeep/tlsh) |

```
[ok] /evidence/document.pdf
[!]  /evidence/tampered.docx
[-]  /evidence/deleted.png
[+]  /evidence/new_file.exe
[*]  /evidence/moved.txt
[~]  /evidence/variant.exe  FUZZY MATCH sim=87%  <- malware/original.exe
```

---

## Configuration file

blazehash reads `./blazehash.toml` in the current directory, then `~/.config/blazehash/blazehash.toml`, and merges them with CLI flags taking priority.

```toml
[defaults]
algorithms    = ["blake3", "sha256"]   # default -c value
output_format = "hashdeep"             # default --format value
sign_key_path = "~/.keys/evidence.key" # pre-loaded signing key
case_id       = "CASE-2026-001"        # embedded in every manifest header
examiner      = "Jane Smith"           # embedded in every manifest header
```

Any field omitted falls back to the built-in default.

---

## Where to go next

You've got the basics: hash, save, audit, sign, verify. Here's where to go depending on what you need:

- **[Acquire Evidence](acquire.md)** -- full acquisition pipeline with direct I/O, resume, block devices, EWF images, and Google Drive (`gdrive-collect`)
- **[Build Court-Ready Evidence](custody.md)** -- signing, cosigning, Bitcoin timestamps, HTML reports
- **[Hunt Threats](hunt.md)** -- NSRL filtering, HashDB flagging, YARA scanning, VirusTotal, entropy
- **[SIEM & Analytics](siem.md)** -- export to Elastic, Splunk, STIX, Parquet, SQLite, DuckDB
- **[CLI Reference](cli-reference.md)** -- every flag and subcommand
- **[Cookbook](cookbook.md)** -- more recipes for specific scenarios
