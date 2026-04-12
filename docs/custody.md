# Build Court-Ready Evidence

The complete chain-of-custody workflow. Every step produces a specific artifact that proves a specific thing.

---

## The full pipeline

```bash
# Step 1: Hash with case metadata
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --progress

# Step 2: Sign (prompts for password)
blazehash sign evidence.hash
# -> evidence.hash.sig (detached signature)
# -> evidence.hash.pub (public key)

# Step 3: Second examiner cosigns (prompts for their password)
blazehash cosign evidence.hash
# -> evidence.hash.msig (2 signatures)

# Step 4: Bitcoin timestamp
blazehash ots stamp evidence.hash
# -> evidence.hash.ots (OpenTimestamps proof)

# Step 5: HTML report
blazehash report evidence.hash \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence-report.html

# Step 6: Verify everything
blazehash verify-sig evidence.hash
blazehash verify-msig evidence.hash --threshold 2
blazehash ots verify evidence.hash
blazehash -r /mnt/evidence -a -k evidence.hash
```

---

## What each artifact proves

| Artifact | Proves | Court question |
|----------|--------|----------------|
| `evidence.hash` | Cryptographic fingerprint of every file | *What* is the evidence? |
| `evidence.hash.sig` | Ed25519 signature from the acquiring examiner | *Who* created the manifest? |
| `evidence.hash.pub` | Public key for independent verification | *Can anyone verify the signature?* |
| `evidence.hash.msig` | Multiple examiners independently signed | *Was there a witness?* |
| `evidence.hash.ots` | Bitcoin-anchored timestamp via OpenTimestamps | *When* was the manifest sealed? |
| `evidence-report.html` | Human-readable summary with all metadata | *Can the court review this without tools?* |

---

## Your evidence package checklist

Ship all of these with the physical evidence:

- [ ] `evidence.hash` -- the manifest
- [ ] `evidence.hash.sig` -- single signature
- [ ] `evidence.hash.pub` -- public key
- [ ] `evidence.hash.msig` -- multi-party signatures (if cosigned)
- [ ] `evidence.hash.ots` -- Bitcoin timestamp proof
- [ ] `evidence-report.html` -- human-readable report

Communicate the public key through a separate channel (case management system, email to counsel, written in case notes) so the recipient can verify independently.

---

## Step-by-step details

### Step 1: Hash with metadata

```bash
blazehash -r /mnt/evidence -c blake3,sha256 \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence.hash --progress
```

- `--case` and `--examiner` embed identifiers in the manifest header. They propagate to every output format.
- `--progress` shows a live progress bar with throughput and ETA.
- `-c blake3,sha256` computes both algorithms simultaneously. BLAKE3 for speed, SHA-256 for universal court acceptance.

### Step 2: Sign the manifest

```bash
blazehash sign evidence.hash
# Prompts: Enter signing password:
```

blazehash derives an Ed25519 keypair from your password via Argon2id (memory-hard, brute-force resistant). Same password always produces the same key on any machine. No key files to manage or lose.

Produces:

- `evidence.hash.sig` -- detached Ed25519 signature
- `evidence.hash.pub` -- your public key (hex-encoded)

!!! warning "Record the public key separately"
    The public key is the verification anchor. Record it in your case notes, case management system, or communicate it to counsel directly. Anyone verifying needs it.

If you omit the environment variable, blazehash prompts interactively.

### Step 3: Cosign (multi-party)

```bash
blazehash cosign evidence.hash
# Prompts: Enter signing password:
```

Each additional examiner runs `cosign` with their own password. Signatures accumulate in `evidence.hash.msig`.

To verify that at least N examiners have signed:

```bash
blazehash verify-msig evidence.hash --threshold 2
```

Exit code `0` = quorum met. Exit code `1` = insufficient signatures or verification failure.

### Step 4: Bitcoin timestamp

```bash
blazehash ots stamp evidence.hash
```

Submits the manifest's SHA-256 hash to the OpenTimestamps calendar servers. The proof is anchored in the Bitcoin blockchain, providing a tamper-proof timestamp that doesn't depend on any single authority.

Produces `evidence.hash.ots`.

!!! note "Timestamp confirmation"
    The OTS proof is created immediately, but full Bitcoin confirmation takes ~1-2 hours (one block confirmation). The proof is valid and verifiable regardless -- it just gets stronger over time as more blocks are mined.

### Step 5: HTML report

```bash
blazehash report evidence.hash \
  --case "CASE-2026-001" --examiner "Jane Smith" \
  -o evidence-report.html
```

Generates a self-contained HTML file with:

- Case metadata (ID, examiner, timestamp)
- File inventory with all computed hashes
- Signature verification status
- Suitable for printing or attaching to court filings

### Step 6: Verify

At any later point -- receiving lab, courtroom, opposing counsel -- verify the entire chain:

```bash
# Signature authentic?
blazehash verify-sig evidence.hash

# Quorum met?
blazehash verify-msig evidence.hash --threshold 2

# Timestamp valid?
blazehash ots verify evidence.hash

# Files unchanged?
blazehash -r /mnt/evidence -a -k evidence.hash
```

Each command returns exit code `0` for pass, `1` for fail. All four passing means:

1. The manifest was created by the claimed examiner (signature)
2. Multiple examiners witnessed it (cosign quorum)
3. The manifest existed at the claimed time (Bitcoin timestamp)
4. Every file on disk matches the manifest (audit)

---

## Verify at handoff

Every time evidence changes hands, the receiver should verify:

```bash
# Verify signature with known public key
blazehash verify-sig evidence.hash --expected-pubkey a3f8e2c1d4b7...

# Re-audit files against manifest
blazehash -r /mnt/evidence -a -k evidence.hash --expected-pubkey a3f8e2c1d4b7...
```

`--expected-pubkey` during audit checks the signature before comparing any file hashes. If the signature is invalid, audit aborts immediately.

---

## Audit auto-verifies signatures

When auditing with `-a -k` and a `.sig` file exists alongside the manifest, blazehash automatically verifies the signature first. Pass `--ignore-sig` to skip this.

```bash
# Auto-verifies signature, then audits files
blazehash -r /mnt/evidence -a -k evidence.hash

# Skip signature check
blazehash -r /mnt/evidence -a -k evidence.hash --ignore-sig
```
