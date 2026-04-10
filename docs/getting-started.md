# Getting Started

This guide walks you through blazehash from first install to a signed, verified manifest. No forensics background required.

---

## Your first hash

Hash a single file:

```bash
blazehash report.pdf
```

Output:

```
%%%% BLAZEHASH-1.0
%%%% size,blake3,filename
## blazehash v0.3.0
1048576,af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,/home/user/report.pdf
```

blazehash computed a BLAKE3 hash of `report.pdf` and printed the result. The hash is a unique fingerprint: if even one byte changes, the hash changes completely.

---

## Hash a folder

Use `-r` to hash every file in a directory, recursively:

```bash
blazehash -r /mnt/evidence
```

blazehash walks the entire directory tree and hashes every file it finds. Output goes to the terminal by default.

---

## Save to a manifest file

Use `-o` to write the results to a file instead of the terminal:

```bash
blazehash -r /mnt/evidence -o manifest.hash
```

This creates `manifest.hash` — a text file listing every file's path, size, and hash. This file is your **manifest**: a snapshot of what existed and what each file contained at the time you ran the command.

---

## Verify nothing changed (audit)

Come back later and check whether anything has been modified, added, or deleted:

```bash
blazehash -r /mnt/evidence -a -k manifest.hash
```

`-a` enables audit mode. `-k` points to your saved manifest. blazehash re-hashes every file and compares the results.

If everything matches, you see:

```
[+] Audit complete: 1,247 files matched, 0 mismatches
```

Exit code `0` means all clear. Exit code `1` means something changed.

---

## Sign the manifest

Signing proves the manifest came from you and hasn't been altered since:

```bash
blazehash sign manifest.hash
```

You'll be prompted for a password. blazehash derives an Ed25519 signing key from your password (using Argon2id, a memory-hard key derivation function). Same password always produces the same key — no key files to manage.

```
[+] Public key: a3f8e2c1d4b7... ← record this
[+] Signature:  manifest.hash.sig
```

!!! warning "Record your public key"
    Write down or save the public key. Anyone verifying your signature needs it. The same password always produces the same public key, but you should record it separately as proof.

---

## Verify a signature

To confirm a manifest is authentic and unmodified:

```bash
blazehash verify-sig manifest.hash --expected-pubkey a3f8e2c1d4b7...
```

Exit code `0` means the signature is valid. Exit code `1` means the manifest was tampered with or the wrong key was provided.

!!! tip "Audit auto-verifies signatures"
    When you audit with `--expected-pubkey`, blazehash checks the signature before comparing any hashes. If the signature is invalid, audit aborts immediately.

    ```bash
    blazehash -r /mnt/evidence -a -k manifest.hash --expected-pubkey a3f8e2c1d4b7...
    ```

---

## What the output means

blazehash audit uses single-character prefixes to tell you exactly what happened to each file:

| Prefix | Meaning | What to do |
|--------|---------|------------|
| `[ok]` | Hash matches the manifest | Nothing — file is unchanged |
| `[!]` | Hash **changed** | File was modified since the manifest was created |
| `[-]` | File **missing** | File existed in the manifest but is gone from disk |
| `[+]` | File **added** | File exists on disk but was not in the manifest |
| `[*]` | File **moved** | Same hash, different path — file was renamed or relocated |
| `[~]` | **Fuzzy match** | File is similar (not identical) to a known file — requires fuzzy hashing (`ssdeep` or `tlsh`) |

Example audit output:

```
[ok] /evidence/document.pdf
[!]  /evidence/tampered.docx
[-]  /evidence/deleted.png
[+]  /evidence/new_file.exe
[*]  /evidence/moved.txt
[~]  /evidence/variant.exe  FUZZY MATCH sim=87%  ← malware/original.exe
```

---

## Next steps

- [CLI Reference](cli-reference.md) — every flag and subcommand
- [Cookbook](cookbook.md) — real-world scenarios with exact commands
- [Concepts](concepts.md) — forensic hashing fundamentals
