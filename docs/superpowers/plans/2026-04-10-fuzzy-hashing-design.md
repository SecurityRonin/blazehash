# Fuzzy Hashing Design

**Date:** 2026-04-10
**Status:** Approved

## Overview

Add ssdeep and tlsh as first-class algorithm columns alongside cryptographic hashes. Fuzzy hashes enable similarity detection — finding modified copies of files, malware variants, and degraded matches in audit mode.

---

## 1. Algorithm Implementation

### ssdeep

Pure Rust implementation (no C bindings). Uses Context-Triggered Piecewise Hashing (CTPH):
- Rolling hash with 7-byte window (Adler-32 variant)
- FNV hash accumulates chunk digests into base64-encoded block hashes
- Output format: `block_size:hash1:hash2` (e.g. `1024:abc123:def456`)
- Similarity: edit distance on block hashes, scaled to 0-100

### tlsh

`tlsh2` crate (pure Rust). Locality Sensitive Hash:
- Output: 70-char hex digest (e.g. `T1A2B3C4...`)
- Distance metric inverted to 0-100 similarity score (`distance=0 → 100`, `distance=300 → 0`, capped)

### Excluded from `--all` / `-c all`

ssdeep and tlsh must be opted into explicitly. They are not cryptographic integrity hashes and are expensive for large datasets.

---

## 2. CLI Integration

ssdeep and tlsh join the `Algorithm` enum as first-class members:

```bash
blazehash -r /evidence -c blake3,ssdeep,tlsh
blazehash -r /evidence -c ssdeep           # fuzzy only
```

Two new flags (audit mode only; silently ignored outside `-a`):

```
--fuzzy-threshold <0-100>    Minimum similarity % for fuzzy audit matches (default: 50)
--fuzzy-top <N>              Show top N fuzzy matches per file (default: 5)
```

---

## 3. Output Format

Fuzzy hashes appear as columns in all existing output formats. No new format introduced.

**hashdeep format** — additional comma-separated fields:
```
1024:abc123...:T1A2B...:blake3hash:sha256hash:/path/to/file
```

**JSON/JSONL** — additional fields on same object:
```json
{"path": "/evidence/file.bin", "blake3": "...", "ssdeep": "1024:abc:def", "tlsh": "T1A2B..."}
```

In audit mode, fuzzy-matched files get a similarity annotation:
- hashdeep text: `(sim=87%)` suffix
- JSON: additional `similarity` field

---

## 4. Fuzzy Audit Mode

Standard audit (`-a -k manifest.hash`) matches by exact hash. With fuzzy algorithms selected, files that fail exact match are re-evaluated by similarity:

1. Exact hash match wins immediately (as today)
2. If no exact match: compare fuzzy hash against manifest candidates, keep matches above `--fuzzy-threshold`
3. Report sorted by similarity descending, capped at `--fuzzy-top`

**ssdeep comparison uses block-size index**: only manifest entries with matching or adjacent block sizes (÷2, ×1, ×2) are compared. Guaranteed by CTPH math — no match is possible across non-adjacent block sizes. Dramatically reduces comparisons in practice.

**tlsh uses linear scan**: O(m) per file (m = manifest entries). tlsh distance is constant-time arithmetic. Acceptable for case-scale manifests (≤100k entries). Not recommended for NSRL-scale manifests.

**Audit report categories unchanged** (matched/not-matched/moved/new):
- Fuzzy matches land in **matched** with similarity annotation
- Exit code 0 on fuzzy match (analyst decides), non-zero only on no-match

**Console output:**
```
[~] file.bin  FUZZY MATCH  sim=87%  ← evidence/original.bin
[~] payload.exe  FUZZY MATCH  sim=62%  ← malware/variant_a.exe
[!] unknown.dat  NO MATCH
```

`[~]` is a new status indicator alongside existing `[+]`/`[-]`/`[*]`.

---

## 5. Testing Strategy

Fuzzy similarity scores are probabilistic — tests use ranges, not exact values.

### ssdeep
- Known-vector tests: pre-computed hashes for fixed inputs (empty, 1 byte, exact block boundary, multi-block) verified against reference C ssdeep tool
- Similarity ranges: identical files → 100, near-identical (1 byte changed) → ≥90, unrelated → 0
- Block-size index unit test: only same/adjacent block-size entries are compared

### tlsh
- Known-vector tests: pre-computed digests verified against reference tlsh tool
- Similarity ranges: same approach as ssdeep
- Distance inversion: `distance=0 → similarity=100`, `distance=300 → similarity=0`

### CLI integration
- `-c ssdeep` produces ssdeep column; no cryptographic hashes unless also specified
- `--fuzzy-threshold` / `--fuzzy-top` silently ignored outside audit mode

### Fuzzy audit
- Same file → 100, matches
- Modified copy → score in range, matches if above threshold
- Unrelated file → 0, no match
- `[~]` in output for fuzzy matches, `[!]` for no match

### Platform
- Fuzzy hashing is CPU-only — no GPU/platform interaction

---

## Module Layout

```
src/
  algorithm.rs        — add Ssdeep, Tlsh variants to Algorithm enum
  fuzzy/
    mod.rs            — FuzzyHash trait, similarity scoring
    ssdeep.rs         — CTPH rolling hash, block-size index
    tlsh.rs           — tlsh2 wrapper, distance inversion
  commands/
    audit.rs          — fuzzy match integration, [~] output
  cli.rs              — --fuzzy-threshold, --fuzzy-top flags
```

---

## Cargo Dependencies

```toml
[dependencies]
tlsh2 = "0.4"
```

ssdeep is implemented from scratch (pure Rust, no crate needed — the algorithm is simple enough and existing crates have C FFI or unmaintained status).
