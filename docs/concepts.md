# Concepts

Fundamentals of forensic hashing for people new to DFIR (Digital Forensics and Incident Response).

---

## What is forensic hashing and why it matters

A hash function takes any input — a file, a disk image, a stream of bytes — and produces a fixed-length fingerprint. If the input changes by even one bit, the fingerprint changes completely.

In forensic work, hashing proves that evidence has not been altered. You hash a file when you collect it. Later, you hash it again. If the hashes match, the file is identical. If they don't, something changed.

Courts, regulators, and opposing counsel accept hash-based integrity verification because the math is unambiguous: two files with the same SHA-256 hash are, for all practical purposes, identical.

---

## Chain of custody

Chain of custody is the documented trail showing who handled evidence, when, and what they did with it. A break in the chain — evidence left unattended, transferred without verification — can get evidence excluded.

Hash manifests strengthen chain of custody by recording the exact state of every file at a specific point in time. Signing the manifest with Ed25519 adds a cryptographic seal: the signature proves who created the manifest and that nobody altered it afterward.

A strong workflow:

1. Hash all files at collection time
2. Sign the manifest
3. Record the public key separately (case notes, case management system)
4. At every handoff, verify the signature and re-audit the files
5. Any tampering between handoffs is immediately detected

Without signing, a manifest is just a text file — anyone could edit it. With signing, altering the manifest invalidates the signature.

---

## BLAKE3 vs SHA-256 vs MD5

| Property | BLAKE3 | SHA-256 | MD5 |
|----------|--------|---------|-----|
| Output size | 256 bits | 256 bits | 128 bits |
| Speed (single-threaded) | ~3 GiB/s | ~500 MiB/s | ~700 MiB/s |
| Parallelizable | Yes (Merkle tree) | No | No |
| Collision resistance | Full | Full | **Broken** since 2004 |
| Court acceptance | Growing | Universal | Legacy — still accepted but weakening |

**When to use BLAKE3:** Default choice. Fastest secure hash available. Use it for speed-critical workflows and as a second algorithm alongside SHA-256.

**When to use SHA-256:** Court submissions, regulatory compliance, interoperability with existing tools and procedures. SHA-256 is the universally accepted standard.

**When to use MD5:** Only for backward compatibility with existing manifests, NSRL lookups, or hashdeep interop. MD5 collisions are [trivial to produce](https://www.mscs.dal.ca/~selMDnger/md5collision/). Never rely on MD5 alone for evidence integrity.

!!! warning
    SHA-1 is also broken. Google published a [practical collision](https://shattered.io/) in 2017. Use SHA-1 only for hashdeep compatibility, never as your sole integrity hash.

---

## Cryptographic vs fuzzy hashing

**Cryptographic hashing** (BLAKE3, SHA-256, MD5) produces an exact fingerprint. Change one bit, and the hash is completely different. This is what you want for integrity verification: "is this file identical to the original?"

**Fuzzy hashing** (ssdeep, tlsh) produces a similarity score. Two files that share large sections of content will have similar fuzzy hashes, even if they aren't identical. This answers a different question: "is this file similar to something I've seen before?"

Use cases for fuzzy hashing:

- **Malware variants.** An attacker recompiles malware with minor changes. Cryptographic hashes miss the connection. Fuzzy hashing catches it.
- **Modified documents.** A suspect edits a Word document. The SHA-256 is completely different, but the ssdeep hash shows 90%+ similarity.
- **File fragments.** Partial file recovery from damaged media. The fragment won't match any cryptographic hash, but fuzzy hashing can identify what it came from.

| Algorithm | Strength | Minimum file size |
|-----------|----------|-------------------|
| ssdeep | Near-duplicates, fragments, document variants | Any |
| tlsh | Larger files, better locality sensitivity | ~50 bytes |

Fuzzy hashes are not cryptographically secure. They don't prove integrity. Use them alongside (not instead of) a cryptographic hash.

---

## What is NSRL

The [National Software Reference Library](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl) (NSRL) is maintained by NIST. It contains hashes of known software — operating systems, applications, drivers, updates — cataloged from legitimate distribution media.

In forensic analysis, NSRL helps you separate known-good files from everything else. A typical Windows installation contains tens of thousands of system files. NSRL filtering removes them from your analysis queue so you can focus on files that actually matter.

blazehash supports two NSRL formats:

- **SQLite database** — exact lookups, zero false positives, larger file size
- **Bloom filter** — probabilistic lookups, ~0.1% false positive rate, much smaller file size

Use the SQLite database when excluding files from output (`--nsrl-exclude`). Use the bloom filter for annotation (`--nsrl` without `--nsrl-exclude`) where a rare false positive is acceptable.

---

## NTFS Alternate Data Streams

On NTFS (the Windows file system), every file can have multiple data streams. The default stream is what you see in Explorer — the file's normal content. But additional named streams can be attached to any file, invisible to most tools.

Alternate Data Streams (ADS) have been used to:

- Hide malware alongside legitimate files
- Store metadata without modifying the visible file
- Exfiltrate data in streams attached to ordinary documents

blazehash's `--ads` flag hashes these hidden streams alongside the main file content. An ADS entry appears as `filename:stream_name` in the output.

ADS is a Windows/NTFS feature. The `--ads` flag is silently ignored on macOS and Linux.

---

## Forensic disk images

A forensic disk image is a bit-for-bit copy of a storage device. Two common formats:

### E01 / EWF (EnCase format)

The Expert Witness Format (EWF) is the most widely used forensic image format. E01 files store:

- Compressed disk data in 32 KiB chunks
- Embedded MD5 and/or SHA-1 checksums
- Case metadata (examiner, case number, notes)
- Segment splitting for large images (`.E01`, `.E02`, `.E03`, ...)

blazehash verifies E01 images by decompressing each segment and recomputing the stored checksums. Supported variants: E01, Ex01, L01, Lx01.

### Raw / DD images

A raw image is an uncompressed, byte-for-byte copy of the disk. Tools like `dd`, `dc3dd`, and FTK Imager write raw images. Because the format has no built-in integrity checking, examiners typically create sidecar hash files (`.md5`, `.sha256`, `.sha512`) alongside the image.

blazehash automatically detects and verifies sidecar hash files when you run `--verify-image` on a raw image.

---

## How tamper evidence works (`seal` / `file-proof` / `verify-proof`)

### The problem: a manifest is just a text file

A SHA-256 manifest proves each file's integrity, but it doesn't prove the manifest itself is intact. Anyone who can edit the manifest can remove entries, change hashes, or swap paths — and unless you kept the original, you can't tell.

Signing the manifest (Ed25519) is the standard fix. But signatures are binary — you can't verify a single entry without the full manifest and the public key.

### What `seal` does

`blazehash seal` builds a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) over every entry in the manifest:

1. **Leaf hashing** — each entry `(path, hash_value)` is serialised and SHA-256 hashed to produce a leaf node.
2. **Tree construction** — leaf nodes are pairwise-hashed bottom-up: `parent = SHA-256(left_child || right_child)`. If a level has an odd number of nodes, the last node is duplicated.
3. **Root commitment** — the single root hash at the top of the tree commits to every entry simultaneously. Change any leaf (path, hash, or order) and the root changes completely.

The root hash is a short, publishable value — 64 hex characters. You can put it in an email, a court filing, a blockchain transaction, or a notebook. Anyone who later sees the same manifest can recompute the root and verify it matches.

### What `file-proof` does

`blazehash file-proof` generates an **inclusion proof** for one file:

1. Find the file's leaf node in the Merkle tree.
2. Walk up the tree, recording the **sibling hash** at each level.
3. Output the root hash and the ordered list of sibling hashes (the "proof path").

The proof is a compact JSON array — O(log n) hashes for a manifest of n files. For 10,000 files, that's ~13 hashes, ~416 bytes. The proof reveals nothing about any other file in the manifest.

### What `verify-proof` does

`blazehash verify-proof` recomputes the path from leaf to root using only:

- The file being verified (to recompute its leaf hash)
- The proof path (sibling hashes)
- The expected root hash

It hashes the file's entry to get the leaf, then applies each sibling hash in sequence to climb the tree. If the recomputed root matches the provided root, the file was present in the manifest when it was sealed — provably, without access to the original manifest or the other files.

### What `disclose` does

`blazehash disclose` produces a redacted copy of the manifest that contains only the files you choose, but includes their Merkle proof paths. A recipient can verify each disclosed file against the same root hash. Undisclosed files remain completely private — their hashes are never transmitted.

### Security properties

| Property | Guarantee |
|----------|-----------|
| Tamper detection | Any change to any entry changes the root hash |
| Selective disclosure | Proof reveals nothing about undisclosed entries |
| Offline verification | `verify-proof` needs no access to the original manifest |
| Compact proofs | O(log n) hashes; ~400 bytes for 10,000-file manifests |

The underlying algorithm is the same one used by [Certificate Transparency](https://certificate.transparency.dev/) logs and [Git's object graph](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects) — a well-understood construction with no known attacks when SHA-256 is used as the node hash function.

---

## Further reading

- [NIST SP 800-86: Guide to Integrating Forensic Techniques](https://csrc.nist.gov/pubs/sp/800/86/final) — NIST guide to digital forensics
- [BLAKE3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) — the hash function specification
- [ssdeep documentation](https://ssdeep-project.github.io/ssdeep/) — context-triggered piecewise hashing
- [TLSH paper](https://github.com/trendmicro/tlsh/blob/master/TLSH_CTC_final.pdf) — trend locality-sensitive hashing
- [SHAttered](https://shattered.io/) — SHA-1 collision (Stevens et al., 2017)
