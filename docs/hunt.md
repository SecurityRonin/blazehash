# Hunt Threats

Filter known-good, flag known-bad, scan YARA rules, check VirusTotal, spot encrypted/packed files. Triage a suspect system down to the files that matter.

---

## The triage pipeline

```bash
blazehash -r /mnt/suspect -c sha256 \
  --nsrl NSRL.db --nsrl-exclude \
  --hashdb-bad malware-hashes.txt \
  --yara rules.yar \
  --entropy \
  -o triage.hash
```

This single command:

1. Hashes every file with SHA-256
2. Removes known-good files (NSRL)
3. Flags known-bad files `[BAD]` (HashDB)
4. Runs YARA rules against every file
5. Computes Shannon entropy (encrypted/packed files score >7.2)

Output contains only files worth investigating.

---

## NSRL: Remove known-good files

The NIST NSRL contains hashes of known OS and application files. Remove them from your output to focus on what matters.

**Annotate known-good (mark but keep in output):**

```bash
blazehash -r /mnt/suspect -c sha256 --nsrl NSRL.db
```

Known-good files get a `[K]` prefix.

**Exclude known-good entirely:**

```bash
blazehash -r /mnt/suspect -c sha256 --nsrl NSRL.db --nsrl-exclude
```

**Using NIST flat hashset instead of SQLite:**

```bash
blazehash -r /mnt/suspect -c sha256 --nsrl-hsh NSRLFile.hsh --nsrl-exclude
```

!!! note "Bloom filter for speed"
    Build a bloom filter for faster lookups on large NSRL databases:

    ```bash
    blazehash nsrl build-bloom NSRL.db --output nsrl.bloom
    blazehash -r /mnt/suspect -c sha256 --nsrl nsrl.bloom --nsrl-exclude
    ```

    ~0.1% false positive rate. Use the SQLite database when excluding files in production.

---

## HashDB: Flag known-bad files

Supply a newline-delimited file of known-bad SHA-256 or SHA-1 hashes. Matching files are flagged `[BAD]` in the manifest.

```bash
blazehash -r /mnt/suspect -c sha256 --hashdb-bad known_malware.txt
```

Combine with NSRL to see only unknowns and known-bad:

```bash
blazehash -r /mnt/suspect -c sha256 \
  --nsrl NSRL.db --nsrl-exclude \
  --hashdb-bad known_malware.txt
```

---

## YARA: Scan with rules

Run YARA rules against every file during the hash walk:

```bash
blazehash -r /mnt/suspect --yara rules.yar -o results.hash
```

YARA matches appear in the output alongside hash entries. Combine with other flags freely:

```bash
blazehash -r /mnt/suspect -c sha256 \
  --nsrl NSRL.db --nsrl-exclude \
  --yara apt_rules.yar \
  -o triage.hash
```

!!! note
    Requires `--features yara` at compile time.

### YARA size threshold: `--yara-max-size`

Very large files are expensive to map into memory. Use `--yara-max-size` (in MiB, default `256`) to control the cut-off:

```bash
blazehash -r /mnt/suspect --yara rules.yar --yara-max-size 512
```

blazehash applies a three-branch strategy based on file size and type:

| Condition | Behaviour |
|-----------|-----------|
| File size > threshold | Stream-hashed only. YARA scan is skipped. A warning is printed to stderr. |
| File size <= threshold, regular file | `mmap`-ed, hashed, and YARA-scanned in one pass. |
| File size <= threshold, non-regular file (pipe, device, etc.) | Read into a `Vec<u8>` buffer, hashed, and YARA-scanned. |

The default of 256 MiB covers the vast majority of executables and documents while protecting against accidental OOM on large forensic images.

### YARA ATT&CK tag lookup

blazehash maps YARA rule hits to MITRE ATT&CK techniques via `lookup_attack_for_match()`. It now checks rule **tags** first (e.g. `T1059`, `T1486`) before falling back to name-prefix matching, so community rule sets from **Neo23x0**, **Elastic**, and **YARA-Forge** work without any modification — no renaming of rules required.

---

## VirusTotal: Batch lookup

Check all hashes in a manifest against VirusTotal:

```bash
VT_API_KEY="..." blazehash vt triage.hash
```

Or pass the key directly:

```bash
blazehash vt triage.hash --api-key YOUR_KEY
```

Rate limits apply per your VT API tier. Run this after NSRL exclusion to minimize API calls.

---

## Entropy: Spot encrypted and packed files

Shannon entropy scores range 0.0-8.0. Files scoring above 7.2 are likely encrypted, compressed, or packed.

```bash
blazehash -r /mnt/suspect --entropy
```

The entropy value appears as an additional column in the output. Useful for spotting:

- Encrypted containers and volumes
- Packed/obfuscated malware
- Steganography payloads
- Ransomware-encrypted files

---

## Fuzzy hashing: Find malware variants

Cryptographic hashes miss near-matches. A recompiled binary with minor changes has a completely different SHA-256. Fuzzy hashing catches the similarity.

**Hash known malware samples:**

```bash
blazehash -r /samples/known -c blake3,ssdeep -o known-malware.hash
```

**Scan a target for variants:**

```bash
blazehash -r /mnt/suspect -a -k known-malware.hash \
  -c ssdeep --fuzzy-threshold 70 --fuzzy-top 3
```

Files with 70%+ similarity to known samples appear as fuzzy matches:

```
[~] payload.exe  FUZZY MATCH sim=87%  <- malware/variant_a.exe
[~] dropper.dll  FUZZY MATCH sim=73%  <- malware/loader.dll
```

Use `ssdeep` for file fragments and near-duplicate documents. Use `tlsh` for larger files where locality sensitivity matters.

---

## Combine everything

The full threat hunting workflow:

```bash
# Step 1: Triage with all intelligence sources
blazehash -r /mnt/suspect -c sha256,ssdeep \
  --nsrl NSRL.db --nsrl-exclude \
  --hashdb-bad malware-hashes.txt \
  --yara apt_rules.yar \
  --entropy \
  -o triage.hash --progress

# Step 2: Check unknowns against VirusTotal
VT_API_KEY="..." blazehash vt triage.hash

# Step 3: Find variants of known samples
blazehash -r /mnt/suspect -a -k known-malware.hash \
  -c ssdeep --fuzzy-threshold 60 --fuzzy-top 5

# Step 4: Find duplicates (lateral movement indicator)
blazehash dedup /mnt/suspect
```
