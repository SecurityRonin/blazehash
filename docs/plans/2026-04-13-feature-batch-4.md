# Feature Batch 4 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add post-quantum signing (ML-DSA-65), Merkle tree inclusion proofs, QR code evidence labels, and chunked GPU SHA-256 streaming for large files.

**Architecture:** ML-DSA signing mirrors the existing Ed25519 pattern in `signing.rs` (password → Argon2id → deterministic key) but uses a 64-byte seed and produces `.pqsig` sidecars. Merkle tree is a pure-Rust implementation in `src/merkle.rs` consuming the parsed manifest. QR code generation is a thin CLI command wrapping the `qrcode` crate. Chunked GPU modifies the existing WGSL shader to accept an external initial state buffer instead of hardcoding the SHA-256 IV, enabling streaming multi-dispatch processing of arbitrarily large files.

**Tech Stack:** `ml-dsa` (RustCrypto pure-Rust ML-DSA-65), `qrcode` + `image` (QR PNG), `sha2` (already present, Merkle nodes), `wgpu` (already present, GPU shader modification).

---

## Context for the implementer

You are working on **blazehash**, a forensic file hashing CLI at `/Users/4n6h4x0r/src/blazehash`. It is a Rust workspace with a binary (`src/main.rs`) and a library (`src/lib.rs`). All tests live in `tests/`. The project uses strict TDD: **RED commit (failing tests) then GREEN commit (passing implementation)** — two separate commits per task. Never skip this.

Key files to understand before starting:
- `src/signing.rs` — Ed25519 signing reference implementation; PQ signing mirrors this
- `src/cosign.rs` — multi-party signing; shows the `.msig` sidecar pattern
- `src/gpu/sha256.rs` — current single-shot GPU SHA-256; chunked GPU extends this
- `src/gpu/sha256.wgsl` — the WGSL compute shader; needs a new `init_state` binding
- `src/cli.rs` — Mode enum and Cli struct; add new modes here
- `src/main.rs` — dispatch table; add new mode arms here
- `src/lib.rs` — re-export new modules here

Run all tests with: `cargo test --all-features`
Build check: `cargo build --all-features`
Clippy: `cargo clippy --all-features -- -D warnings`

---

## Task 1: Cargo deps

**Files:**
- Modify: `Cargo.toml`
- Test: `tests/batch4_dep_tests.rs` (create)

### Step 1: Write the failing test

```rust
// tests/batch4_dep_tests.rs
#[test]
fn ml_dsa_crate_available() {
    // If this compiles, the dep is present
    let _ = std::mem::size_of::<ml_dsa::KeyPair<ml_dsa::MlDsa65>>();
}

#[cfg(feature = "qr")]
#[test]
fn qrcode_crate_available() {
    let qr = qrcode::QrCode::new(b"test").unwrap();
    assert!(qr.width() > 0);
}

#[cfg(feature = "qr")]
#[test]
fn image_crate_available() {
    let img = image::RgbImage::new(1, 1);
    assert_eq!(img.width(), 1);
}
```

### Step 2: Run to confirm it fails

```bash
cargo test --test batch4_dep_tests 2>&1 | head -20
```
Expected: compile error — `ml_dsa` not found.

### Step 3: Add the deps

In `Cargo.toml`, under `[dependencies]`:

```toml
ml-dsa = "0.1"
signature = "2"
```

Under `[dependencies]` as optional:

```toml
qrcode = { version = "0.14", optional = true }
image = { version = "0.25", optional = true, default-features = false, features = ["png"] }
```

Under `[features]`:

```toml
pq  = []
qr  = ["dep:qrcode", "dep:image"]
```

Add `pq` and `qr` to the `default` feature list:

```toml
default = ["forensic-image", "gpu", "sqlite", "parquet-output", "duckdb-output", "pq", "qr"]
```

### Step 4: Run to confirm it passes

```bash
cargo test --test batch4_dep_tests --all-features 2>&1 | tail -5
```
Expected: `test result: ok. 3 passed`.

### Step 5: Commit (RED)

```bash
git add tests/batch4_dep_tests.rs Cargo.toml Cargo.lock
git commit -m "test(RED): add failing dep tests for ml-dsa, qrcode, image"
```

After implementing (Step 3 above is the implementation — deps make tests compile):

```bash
git add Cargo.toml Cargo.lock
git commit -m "feat: add ml-dsa, qrcode, image crate deps (pq and qr features)"
```

---

## Task 2: Post-quantum signing — `src/pq_signing.rs`

ML-DSA-65 is NIST ML-DSA at security level 3 (equivalent to AES-192). Key sizes: signing key 4032 bytes, verifying key 1952 bytes, signature 3309 bytes. Password derivation: Argon2id with a 64-byte output (same APP_SALT as signing.rs) → used as the seed for deterministic ML-DSA key generation.

**Files:**
- Create: `src/pq_signing.rs`
- Modify: `src/lib.rs` (add `pub mod pq_signing;`)
- Test: `tests/pq_signing_tests.rs` (create)

### Step 1: Write the failing tests

```rust
// tests/pq_signing_tests.rs
use std::io::Write;
use tempfile::NamedTempFile;

fn write_temp_manifest(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

#[test]
fn test_pq_derive_key_deterministic() {
    use blazehash::pq_signing::derive_pq_key;
    let key1 = derive_pq_key("password123").unwrap();
    let key2 = derive_pq_key("password123").unwrap();
    // Same password → same verifying key bytes
    assert_eq!(
        key1.verifying_key_bytes(),
        key2.verifying_key_bytes()
    );
}

#[test]
fn test_pq_derive_key_different_passwords() {
    use blazehash::pq_signing::derive_pq_key;
    let key1 = derive_pq_key("password123").unwrap();
    let key2 = derive_pq_key("different").unwrap();
    assert_ne!(
        key1.verifying_key_bytes(),
        key2.verifying_key_bytes()
    );
}

#[test]
fn test_pq_sign_creates_pqsig_file() {
    use blazehash::pq_signing::pq_sign_with_password;
    let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc123,/foo/bar\n");
    let manifest_path = manifest.path();
    pq_sign_with_password(manifest_path, "testpass").unwrap();
    let sig_path = manifest_path.with_extension(
        format!("{}.pqsig", manifest_path.extension().unwrap_or_default().to_str().unwrap_or(""))
    );
    // .pqsig path: manifest.hash → manifest.hash.pqsig
    let sig_path = {
        let name = format!("{}.pqsig",
            manifest_path.file_name().unwrap().to_str().unwrap());
        manifest_path.with_file_name(name)
    };
    assert!(sig_path.exists(), ".pqsig file must be created");
    let content = std::fs::read_to_string(&sig_path).unwrap();
    assert!(content.starts_with("blazehash-pqsig-v1\n"), "must have version header");
    assert!(content.contains("algorithm: ml-dsa-65"), "must declare algorithm");
    assert!(content.contains("pubkey: "), "must embed pubkey");
    assert!(content.contains("sig: "), "must embed signature");
}

#[test]
fn test_pq_verify_valid_signature() {
    use blazehash::pq_signing::{pq_sign_with_password, pq_verify_sig};
    let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc123,/foo/bar\n");
    let manifest_path = manifest.path();
    pq_sign_with_password(manifest_path, "mypassword").unwrap();
    let result = pq_verify_sig(manifest_path, "").unwrap();
    assert!(result, "valid PQ signature must verify");
}

#[test]
fn test_pq_verify_tampered_manifest_fails() {
    use blazehash::pq_signing::{pq_sign_with_password, pq_verify_sig};
    let mut manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc123,/foo/bar\n");
    let manifest_path = manifest.path().to_path_buf();
    pq_sign_with_password(&manifest_path, "mypassword").unwrap();
    // Tamper
    manifest.write_all(b"\ntampered").unwrap();
    let result = pq_verify_sig(&manifest_path, "").unwrap();
    assert!(!result, "tampered manifest must fail PQ verification");
}

#[test]
fn test_pq_verify_wrong_pubkey_fails() {
    use blazehash::pq_signing::{pq_sign_with_password, pq_verify_sig};
    let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc123,/foo/bar\n");
    let manifest_path = manifest.path();
    pq_sign_with_password(manifest_path, "mypassword").unwrap();
    // Wrong expected pubkey
    let wrong_pubkey = "a".repeat(3904); // 1952 bytes hex
    let result = pq_verify_sig(manifest_path, &wrong_pubkey).unwrap();
    assert!(!result, "wrong expected pubkey must fail");
}
```

### Step 2: Run to confirm RED

```bash
cargo test --test pq_signing_tests 2>&1 | head -10
```
Expected: compile error — `blazehash::pq_signing` not found.

### Step 3: Implement `src/pq_signing.rs`

```rust
//! Post-quantum manifest signing using ML-DSA-65 (NIST ML-DSA, security level 3).
//!
//! Key derivation: Argon2id(password, APP_SALT) → 64-byte seed → ML-DSA-65 keypair.
//! Same password always produces the same keypair on any machine.
//!
//! Sidecar format (.pqsig):
//!   blazehash-pqsig-v1
//!   algorithm: ml-dsa-65
//!   pubkey: <hex>
//!   signed: <unix_timestamp>
//!   sig: <hex>

use anyhow::{Context, Result};
use argon2::{Algorithm as Argon2Algo, Argon2, Params, Version};
use ml_dsa::{KeyPair, MlDsa65};
use signature::{Signer, Verifier};
use std::path::{Path, PathBuf};

const APP_SALT: &[u8] = b"blazehash-pq-signing-v1";

pub struct PqKeyPair {
    inner: KeyPair<MlDsa65>,
}

impl PqKeyPair {
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        use signature::Keypair;
        let vk = self.inner.verifying_key();
        // ML-DSA verifying key: encode as bytes
        vk.to_bytes().to_vec()
    }
}

/// Derive a ML-DSA-65 keypair from a password using Argon2id.
/// 64-byte seed → deterministic keypair.
pub fn derive_pq_key(password: &str) -> Result<PqKeyPair> {
    let params = Params::new(65536, 3, 1, Some(64))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Argon2Algo::Argon2id, Version::V0x13, params);
    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(password.as_bytes(), APP_SALT, &mut seed)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    // ML-DSA-65 key generation from seed
    let key_pair = KeyPair::<MlDsa65>::from_seed(&seed);
    Ok(PqKeyPair { inner: key_pair })
}

fn pqsig_path_for(manifest_path: &Path) -> PathBuf {
    let name = format!(
        "{}.pqsig",
        manifest_path.file_name().and_then(|n| n.to_str()).unwrap_or("manifest")
    );
    manifest_path.with_file_name(name)
}

/// Sign `manifest_path` with ML-DSA-65. Writes `.pqsig` sidecar.
pub fn pq_sign_with_password(manifest_path: &Path, password: &str) -> Result<()> {
    let key_pair = derive_pq_key(password)?;
    let signing_key = &key_pair.inner;
    use signature::Keypair;
    let verifying_key = signing_key.verifying_key();

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read {}", manifest_path.display()))?;

    let sig = signing_key.sign(&manifest_bytes);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pubkey_hex = hex::encode(verifying_key.to_bytes());
    let sig_hex = hex::encode(sig.to_bytes());

    let content = format!(
        "blazehash-pqsig-v1\nalgorithm: ml-dsa-65\npubkey: {pubkey_hex}\nsigned: {timestamp}\nsig: {sig_hex}\n"
    );

    let pqsig_path = pqsig_path_for(manifest_path);
    std::fs::write(&pqsig_path, &content)
        .with_context(|| format!("cannot write {}", pqsig_path.display()))?;

    eprintln!("[+] PQ-Signed: {}", manifest_path.display());
    eprintln!("[+] PQ Public key: {}...", &pubkey_hex[..32]);
    eprintln!("[+] PQ Signature: {}", pqsig_path.display());
    Ok(())
}

/// Sign using interactive password prompt.
pub fn pq_sign(manifest_path: &Path) -> Result<()> {
    let password = crate::signing::read_password()?;
    pq_sign_with_password(manifest_path, &password)
}

/// Verify `.pqsig` sidecar. `expected_pubkey_hex` may be empty (use embedded).
pub fn pq_verify_sig(manifest_path: &Path, expected_pubkey_hex: &str) -> Result<bool> {
    let pqsig_path = pqsig_path_for(manifest_path);
    let content = std::fs::read_to_string(&pqsig_path)
        .with_context(|| format!("cannot read {}", pqsig_path.display()))?;

    let mut embedded_pubkey = None;
    let mut sig_hex = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("pubkey: ") { embedded_pubkey = Some(v.to_string()); }
        if let Some(v) = line.strip_prefix("sig: ")    { sig_hex = Some(v.to_string()); }
    }

    let pub_hex = if expected_pubkey_hex.is_empty() {
        embedded_pubkey.ok_or_else(|| anyhow::anyhow!("no pubkey: in .pqsig"))?
    } else {
        if let Some(ref emb) = embedded_pubkey {
            if emb.trim() != expected_pubkey_hex.trim() {
                eprintln!("[!] PQ sig pubkey does not match --expected-pubkey");
                return Ok(false);
            }
        }
        expected_pubkey_hex.to_string()
    };

    let sig_hex = sig_hex.ok_or_else(|| anyhow::anyhow!("no sig: in .pqsig"))?;
    let pub_bytes = hex::decode(pub_hex.trim()).context("invalid pubkey hex")?;
    let sig_bytes = hex::decode(sig_hex.trim()).context("invalid sig hex")?;

    use ml_dsa::VerifyingKey;
    let verifying_key = VerifyingKey::<MlDsa65>::from_bytes(&pub_bytes)
        .map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 verifying key"))?;

    use ml_dsa::Signature;
    let sig = Signature::<MlDsa65>::from_bytes(&sig_bytes)
        .map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 signature"))?;

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read {}", manifest_path.display()))?;

    match verifying_key.verify(&manifest_bytes, &sig) {
        Ok(()) => {
            eprintln!("[+] PQ Signature valid — {}", manifest_path.display());
            Ok(true)
        }
        Err(_) => {
            eprintln!("[!] PQ Signature INVALID — {}", manifest_path.display());
            Ok(false)
        }
    }
}
```

**IMPORTANT:** The exact `ml-dsa` API may differ from the above. After adding the dep, run `cargo doc --open -p ml-dsa` to see the actual types. Key things to verify:
- `KeyPair::<MlDsa65>::from_seed(&seed)` — check if this method exists; may be `generate_from_seed` or similar
- `signing_key.sign(&bytes)` — requires `use signature::Signer`
- `VerifyingKey::<MlDsa65>::from_bytes(bytes)` — check exact byte slice type expected
- `Signature::<MlDsa65>::from_bytes(bytes)` — same check

If `from_seed` doesn't exist, use random generation and store the keypair bytes (encrypted with Argon2id-derived symmetric key).

### Step 4: Register module in `src/lib.rs`

Add:
```rust
pub mod pq_signing;
```

### Step 5: Run tests

```bash
cargo test --test pq_signing_tests --all-features 2>&1 | tail -10
```
Expected: all 5 tests pass.

### Step 6: Commits

RED was done before implementation. Now:
```bash
git add src/pq_signing.rs src/lib.rs
git commit -m "feat: ML-DSA-65 post-quantum signing (pq-sign/pq-verify-sig)"
```

---

## Task 3: PQ signing — CLI integration

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Test: add to `tests/pq_signing_tests.rs`

### Step 1: Add CLI tests

Append to `tests/pq_signing_tests.rs`:

```rust
use assert_cmd::Command;

#[test]
fn test_cli_pq_sign_creates_pqsig() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("evidence.hash");
    std::fs::write(&manifest, "%%blazehash-1.0\nblake3,path\nabc,/foo\n").unwrap();

    let mut cmd = Command::cargo_bin("blazehash").unwrap();
    cmd.env("BLAZEHASH_SIGN_PASSWORD", "testpass")
       .arg("pq-sign")
       .arg(&manifest);
    cmd.assert().success();

    let pqsig = dir.path().join("evidence.hash.pqsig");
    assert!(pqsig.exists());
}

#[test]
fn test_cli_pq_verify_sig_valid() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("evidence.hash");
    std::fs::write(&manifest, "%%blazehash-1.0\nblake3,path\nabc,/foo\n").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "testpass")
        .arg("pq-sign").arg(&manifest)
        .assert().success();

    Command::cargo_bin("blazehash").unwrap()
        .arg("pq-verify-sig").arg(&manifest)
        .assert().success();
}
```

### Step 2: Run to confirm RED

```bash
cargo test --test pq_signing_tests 2>&1 | grep "FAILED\|error"
```
Expected: CLI tests fail — subcommands don't exist yet.

### Step 3: Add to `src/cli.rs`

In the `Mode` enum, add:
```rust
PqSign,
PqVerifySig,
```

In the `mode()` method, add detection for `paths[0] == "pq-sign"` and `"pq-verify-sig"` (same pattern as `Sign` and `VerifySig`).

### Step 4: Add to `src/main.rs`

In the dispatch section (before the final `match`):

```rust
if let Mode::PqSign = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash pq-sign <manifest>"))?;
    blazehash::pq_signing::pq_sign(&manifest)?;
    return Ok(());
}

if let Mode::PqVerifySig = cli.mode() {
    let manifest = PathBuf::from(cli.paths.get(1).ok_or_else(|| {
        anyhow::anyhow!("usage: blazehash pq-verify-sig <manifest>")
    })?);
    let pubkey = cli.expected_pubkey.as_deref().unwrap_or("");
    let valid = blazehash::pq_signing::pq_verify_sig(&manifest, pubkey)?;
    if !valid { std::process::exit(1); }
    return Ok(());
}
```

Add `unreachable!()` arms in the final `match`.

### Step 5: Run tests

```bash
cargo test --test pq_signing_tests --all-features 2>&1 | tail -5
```

### Step 6: Commits

```bash
git add tests/pq_signing_tests.rs
git commit -m "test(RED): add CLI tests for pq-sign / pq-verify-sig"

git add src/cli.rs src/main.rs
git commit -m "feat: wire pq-sign and pq-verify-sig into CLI"
```

---

## Task 4: Merkle tree manifests — `src/merkle.rs`

A binary Merkle tree where each leaf is `SHA256(0x00 || path_bytes || 0x00 || sha256_hash_hex_bytes)` and each internal node is `SHA256(0x01 || left_hash || right_hash)` with left/right always sorted (canonical form). This means the root is deterministic regardless of insert order.

**Files:**
- Create: `src/merkle.rs`
- Modify: `src/lib.rs`
- Test: `tests/merkle_tests.rs` (create)

### Step 1: Write the failing tests

```rust
// tests/merkle_tests.rs
use blazehash::merkle::{build_merkle_tree, generate_proof, verify_proof, MerkleProof};

fn sample_entries() -> Vec<(String, String)> {
    vec![
        ("/evidence/file_a.bin".to_string(), "a".repeat(64)),
        ("/evidence/file_b.bin".to_string(), "b".repeat(64)),
        ("/evidence/file_c.bin".to_string(), "c".repeat(64)),
        ("/evidence/file_d.bin".to_string(), "d".repeat(64)),
    ]
}

#[test]
fn test_merkle_root_is_deterministic() {
    let entries = sample_entries();
    let root1 = build_merkle_tree(&entries).unwrap();
    let root2 = build_merkle_tree(&entries).unwrap();
    assert_eq!(root1, root2);
}

#[test]
fn test_merkle_root_changes_with_different_data() {
    let entries1 = sample_entries();
    let mut entries2 = sample_entries();
    entries2[0].1 = "z".repeat(64); // different hash
    let root1 = build_merkle_tree(&entries1).unwrap();
    let root2 = build_merkle_tree(&entries2).unwrap();
    assert_ne!(root1, root2);
}

#[test]
fn test_merkle_root_order_independent() {
    let mut entries = sample_entries();
    let root1 = build_merkle_tree(&entries).unwrap();
    entries.reverse();
    let root2 = build_merkle_tree(&entries).unwrap();
    // Sorted canonical form → same root regardless of input order
    assert_eq!(root1, root2);
}

#[test]
fn test_merkle_single_entry() {
    let entries = vec![("/foo".to_string(), "a".repeat(64))];
    let root = build_merkle_tree(&entries).unwrap();
    assert_eq!(root.len(), 64, "root is a 64-char hex string");
}

#[test]
fn test_generate_proof_for_known_entry() {
    let entries = sample_entries();
    let root = build_merkle_tree(&entries).unwrap();
    let proof = generate_proof(&entries, "/evidence/file_b.bin").unwrap();
    assert!(verify_proof(&proof, "/evidence/file_b.bin", &entries[1].1, &root));
}

#[test]
fn test_verify_proof_wrong_path_fails() {
    let entries = sample_entries();
    let root = build_merkle_tree(&entries).unwrap();
    let proof = generate_proof(&entries, "/evidence/file_a.bin").unwrap();
    // Use proof for file_a but claim it's file_b → must fail
    assert!(!verify_proof(&proof, "/evidence/file_b.bin", &entries[1].1, &root));
}

#[test]
fn test_generate_proof_unknown_path_errors() {
    let entries = sample_entries();
    assert!(generate_proof(&entries, "/does/not/exist").is_err());
}

#[test]
fn test_proof_json_roundtrip() {
    let entries = sample_entries();
    let root = build_merkle_tree(&entries).unwrap();
    let proof = generate_proof(&entries, "/evidence/file_c.bin").unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let proof2: MerkleProof = serde_json::from_str(&json).unwrap();
    assert!(verify_proof(&proof2, "/evidence/file_c.bin", &entries[2].1, &root));
}
```

### Step 2: Confirm RED

```bash
cargo test --test merkle_tests 2>&1 | head -5
```
Expected: compile error.

### Step 3: Implement `src/merkle.rs`

```rust
//! Merkle tree for privacy-preserving file inclusion proofs.
//!
//! Leaf: SHA256(0x00 || path_utf8 || 0x00 || sha256_hex_utf8)
//! Node: SHA256(0x01 || sorted(left, right))  ← canonical ordering
//!
//! "sorted" means we always hash min(left,right) || max(left,right),
//! so the root is the same regardless of the order entries are given.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn leaf_hash(path: &str, hash_hex: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(path.as_bytes());
    h.update([0x00]);
    h.update(hash_hex.as_bytes());
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if left <= right { (left, right) } else { (right, left) };
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(lo);
    h.update(hi);
    h.finalize().into()
}

fn bytes_to_hex(b: &[u8; 32]) -> String {
    hex::encode(b)
}

/// A single step in a Merkle proof: the sibling hash needed at that level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    pub sibling: String, // hex-encoded 32-byte hash
}

/// Inclusion proof for a single entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub steps: Vec<ProofStep>,
    pub root: String,
}

/// Build the Merkle root from a list of (path, sha256_hex) entries.
/// Input order does not matter — leaves are sorted before tree construction.
pub fn build_merkle_tree(entries: &[(String, String)]) -> Result<String> {
    if entries.is_empty() {
        bail!("cannot build Merkle tree from empty entries");
    }
    let mut leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|(p, h)| leaf_hash(p, h))
        .collect();
    // Sort for canonical form
    leaves.sort();
    Ok(bytes_to_hex(&compute_root(leaves)))
}

fn compute_root(mut nodes: Vec<[u8; 32]>) -> [u8; 32] {
    while nodes.len() > 1 {
        if nodes.len() % 2 == 1 {
            // Duplicate last node for odd count
            let last = *nodes.last().unwrap();
            nodes.push(last);
        }
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| node_hash(&pair[0], &pair[1]))
            .collect();
    }
    nodes[0]
}

/// Generate an inclusion proof for the entry at `path`.
pub fn generate_proof(entries: &[(String, String)], path: &str) -> Result<MerkleProof> {
    let target_leaf = entries
        .iter()
        .find(|(p, _)| p == path)
        .map(|(p, h)| leaf_hash(p, h))
        .ok_or_else(|| anyhow::anyhow!("path not found in entries: {path}"))?;

    let mut leaves: Vec<[u8; 32]> = entries.iter().map(|(p, h)| leaf_hash(p, h)).collect();
    leaves.sort();

    let mut idx = leaves.iter().position(|l| l == &target_leaf)
        .ok_or_else(|| anyhow::anyhow!("leaf not in sorted tree"))?;

    let root = bytes_to_hex(&compute_root(leaves.clone()));
    let mut steps = Vec::new();
    let mut current = leaves;

    while current.len() > 1 {
        if current.len() % 2 == 1 {
            let last = *current.last().unwrap();
            current.push(last);
        }
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        steps.push(ProofStep { sibling: bytes_to_hex(&current[sibling_idx]) });
        current = current
            .chunks_exact(2)
            .map(|pair| node_hash(&pair[0], &pair[1]))
            .collect();
        idx /= 2;
    }

    Ok(MerkleProof { steps, root })
}

/// Verify an inclusion proof.
pub fn verify_proof(proof: &MerkleProof, path: &str, hash_hex: &str, expected_root: &str) -> bool {
    let mut current = leaf_hash(path, hash_hex);
    for step in &proof.steps {
        let Ok(sibling_bytes) = hex::decode(&step.sibling) else { return false };
        let Ok(sib_arr): Result<[u8; 32], _> = sibling_bytes.try_into() else { return false };
        current = node_hash(&current, &sib_arr);
    }
    bytes_to_hex(&current) == expected_root
}
```

### Step 4: Add to `src/lib.rs`

```rust
pub mod merkle;
```

### Step 5: Run tests

```bash
cargo test --test merkle_tests 2>&1 | tail -5
```

### Step 6: Commits

```bash
git add tests/merkle_tests.rs
git commit -m "test(RED): add failing Merkle tree inclusion proof tests"

git add src/merkle.rs src/lib.rs
git commit -m "feat: Merkle tree manifests (build/prove/verify inclusion proofs)"
```

---

## Task 5: Merkle — CLI integration

**Files:**
- Modify: `src/cli.rs`, `src/main.rs`, `src/commands/merkle.rs` (create)
- Test: `tests/merkle_tests.rs` (append CLI tests)

### Step 1: Add CLI tests

Append to `tests/merkle_tests.rs`:

```rust
use assert_cmd::Command;
use std::io::Write;

fn write_manifest(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("evidence.hash");
    std::fs::write(&p,
        "%%blazehash-1.0\n## case: TEST\nsha256,path\n\
         a3f1e2d4b5c6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2,/foo/a.bin\n\
         b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3,/foo/b.bin\n"
    ).unwrap();
    p
}

#[test]
fn test_cli_merkle_root_prints_hex() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write_manifest(dir.path());
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["merkle", manifest.to_str().unwrap()])
        .output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.trim().len() == 64, "root must be 64-char hex, got: {stdout}");
}

#[test]
fn test_cli_merkle_proof_json() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write_manifest(dir.path());
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["merkle-proof", manifest.to_str().unwrap(), "/foo/a.bin"])
        .output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let proof: serde_json::Value = serde_json::from_str(stdout.trim()).expect("must be valid JSON");
    assert!(proof.get("steps").is_some());
    assert!(proof.get("root").is_some());
}

#[test]
fn test_cli_merkle_verify_exits_0_for_valid() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = write_manifest(dir.path());
    // Get root first
    let root_out = Command::cargo_bin("blazehash").unwrap()
        .args(["merkle", manifest.to_str().unwrap()])
        .output().unwrap();
    let root = String::from_utf8(root_out.stdout).unwrap().trim().to_string();
    // Get proof
    let proof_out = Command::cargo_bin("blazehash").unwrap()
        .args(["merkle-proof", manifest.to_str().unwrap(), "/foo/a.bin"])
        .output().unwrap();
    let proof_path = dir.path().join("proof.json");
    std::fs::write(&proof_path, proof_out.stdout).unwrap();
    // Verify
    Command::cargo_bin("blazehash").unwrap()
        .args(["merkle-verify", manifest.to_str().unwrap(), "/foo/a.bin",
               proof_path.to_str().unwrap()])
        .assert().success();
}
```

### Step 2: Implement `src/commands/merkle.rs`

```rust
use anyhow::Result;
use std::path::Path;

/// Parse (path, sha256_hex) pairs from a blazehash manifest.
/// Handles hashdeep format: skip lines starting with '#', '%', or blank.
/// Hash columns: the first column is always the first algorithm's hash.
fn parse_manifest_entries(manifest_path: &Path) -> Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("cannot read {}", manifest_path.display()))?;

    let mut entries = Vec::new();
    let mut header_done = false;
    let mut hash_col = 0usize; // index of sha256 column
    let mut path_col = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        if !header_done {
            // Column header line: e.g. "blake3,sha256,path" or "sha256,path"
            let cols: Vec<&str> = trimmed.split(',').collect();
            path_col = cols.iter().position(|&c| c == "path").unwrap_or(cols.len() - 1);
            hash_col = 0; // use first hash column
            header_done = true;
            continue;
        }
        let cols: Vec<&str> = trimmed.splitn(path_col + 2, ',').collect();
        if cols.len() <= path_col { continue; }
        let hash = cols[hash_col].trim().to_string();
        let path = cols[path_col].trim().to_string();
        if !hash.is_empty() && !path.is_empty() {
            entries.push((path, hash));
        }
    }
    Ok(entries)
}

pub fn run_merkle_root(manifest_path: &Path) -> Result<()> {
    use anyhow::Context;
    let entries = parse_manifest_entries(manifest_path)?;
    let root = blazehash::merkle::build_merkle_tree(&entries)?;
    println!("{root}");
    Ok(())
}

pub fn run_merkle_proof(manifest_path: &Path, file_path: &str) -> Result<()> {
    let entries = parse_manifest_entries(manifest_path)?;
    let proof = blazehash::merkle::generate_proof(&entries, file_path)?;
    println!("{}", serde_json::to_string_pretty(&proof)?);
    Ok(())
}

pub fn run_merkle_verify(manifest_path: &Path, file_path: &str, proof_path: &Path) -> Result<()> {
    use anyhow::Context;
    let entries = parse_manifest_entries(manifest_path)?;
    let hash_hex = entries
        .iter()
        .find(|(p, _)| p == file_path)
        .map(|(_, h)| h.clone())
        .ok_or_else(|| anyhow::anyhow!("{file_path} not found in manifest"))?;

    let proof_json = std::fs::read_to_string(proof_path)
        .with_context(|| format!("cannot read proof {}", proof_path.display()))?;
    let proof: blazehash::merkle::MerkleProof = serde_json::from_str(&proof_json)?;

    let root = blazehash::merkle::build_merkle_tree(&entries)?;
    if blazehash::merkle::verify_proof(&proof, file_path, &hash_hex, &root) {
        eprintln!("[+] Merkle proof valid — {file_path} is in manifest (root: {})", &root[..16]);
        Ok(())
    } else {
        anyhow::bail!("Merkle proof INVALID — {file_path}");
    }
}
```

Add `use anyhow::Context;` at the top of the file.

### Step 3: Wire into CLI

Add modes to `src/cli.rs`: `Merkle`, `MerkleProof`, `MerkleVerify`.

Add dispatch in `src/main.rs`:
```rust
if let Mode::Merkle = cli.mode() {
    let manifest = cli.paths.get(1).cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash merkle <manifest>"))?;
    commands::merkle::run_merkle_root(&manifest)?;
    return Ok(());
}

if let Mode::MerkleProof = cli.mode() {
    let manifest = cli.paths.get(1).cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash merkle-proof <manifest> <path>"))?;
    let file_path = cli.paths.get(2)
        .and_then(|p| p.to_str())
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash merkle-proof <manifest> <path>"))?;
    commands::merkle::run_merkle_proof(&manifest, file_path)?;
    return Ok(());
}

if let Mode::MerkleVerify = cli.mode() {
    let manifest = cli.paths.get(1).cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash merkle-verify <manifest> <path> <proof.json>"))?;
    let file_path = cli.paths.get(2)
        .and_then(|p| p.to_str())
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash merkle-verify <manifest> <path> <proof.json>"))?;
    let proof_path = cli.paths.get(3).cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash merkle-verify <manifest> <path> <proof.json>"))?;
    commands::merkle::run_merkle_verify(&manifest, file_path, &proof_path)?;
    return Ok(());
}
```

### Step 4: Commits

```bash
git add tests/merkle_tests.rs
git commit -m "test(RED): CLI tests for merkle/merkle-proof/merkle-verify subcommands"

git add src/commands/merkle.rs src/cli.rs src/main.rs
git commit -m "feat: wire merkle/merkle-proof/merkle-verify into CLI"
```

---

## Task 6: QR code evidence labels — `src/commands/qr.rs`

QR content: `BLAZEHASH:sha256=<manifest_sha256>&pubkey=<ed25519_pubkey>&case=<case_id>`

All fields are optional except sha256. The QR encodes enough for anyone with a phone to verify the manifest hash. Ed25519 pubkey (64 hex chars) and case ID fit comfortably in a QR code at error correction level M (≤1273 alphanumeric chars).

**Files:**
- Create: `src/commands/qr.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Test: `tests/qr_tests.rs` (create)

### Step 1: Write failing tests

```rust
// tests/qr_tests.rs
#[cfg(feature = "qr")]
mod qr_tests {
    use blazehash::qr_label::{build_qr_content, QrArgs};
    use std::path::PathBuf;

    #[test]
    fn test_qr_content_includes_sha256() {
        let content = build_qr_content("abc123def456", None, None);
        assert!(content.starts_with("BLAZEHASH:"));
        assert!(content.contains("sha256=abc123def456"));
    }

    #[test]
    fn test_qr_content_with_pubkey_and_case() {
        let content = build_qr_content("abc123", Some("pubkey123"), Some("CASE-2026-001"));
        assert!(content.contains("pubkey=pubkey123"));
        assert!(content.contains("case=CASE-2026-001"));
    }

    #[test]
    fn test_qr_content_without_optional_fields() {
        let content = build_qr_content("deadbeef", None, None);
        assert!(!content.contains("pubkey="));
        assert!(!content.contains("case="));
    }

    #[test]
    fn test_qr_generates_png_file() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("label.png");
        blazehash::qr_label::generate_qr_png("BLAZEHASH:sha256=test", &out_path).unwrap();
        assert!(out_path.exists());
        let bytes = std::fs::read(&out_path).unwrap();
        // PNG magic bytes
        assert_eq!(&bytes[..4], b"\x89PNG");
    }

    #[test]
    fn test_qr_generates_svg_file() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("label.svg");
        blazehash::qr_label::generate_qr_svg("BLAZEHASH:sha256=test", &out_path).unwrap();
        assert!(out_path.exists());
        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("<svg"), "must be SVG");
    }
}

#[cfg(feature = "qr")]
mod cli_qr_tests {
    use assert_cmd::Command;

    fn write_signed_manifest(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("evidence.hash");
        std::fs::write(&p, "%%blazehash-1.0\nblake3,path\nabc,/foo\n").unwrap();
        // Write fake .pub file
        std::fs::write(dir.join("evidence.hash.pub"),
            "a3f8e2c1d4b7f9e0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4").unwrap();
        p
    }

    #[test]
    fn test_cli_qr_creates_png() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_signed_manifest(dir.path());
        let out = dir.path().join("label.png");
        Command::cargo_bin("blazehash").unwrap()
            .args(["qr", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
            .assert().success();
        assert!(out.exists());
    }

    #[test]
    fn test_cli_qr_svg_format() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_signed_manifest(dir.path());
        let out = dir.path().join("label.svg");
        Command::cargo_bin("blazehash").unwrap()
            .args(["qr", manifest.to_str().unwrap(), "-o", out.to_str().unwrap(), "--svg"])
            .assert().success();
        assert!(out.exists());
    }
}
```

### Step 2: Confirm RED

```bash
cargo test --test qr_tests --features qr 2>&1 | head -5
```

### Step 3: Implement `src/qr_label.rs`

```rust
//! QR code generation for evidence labels.
//!
//! Content: `BLAZEHASH:sha256=<hex>[&pubkey=<hex>][&case=<id>]`

#[cfg(feature = "qr")]
use anyhow::{Context, Result};
#[cfg(feature = "qr")]
use std::path::Path;

/// Build the QR code payload string.
pub fn build_qr_content(
    manifest_sha256: &str,
    pubkey_hex: Option<&str>,
    case_id: Option<&str>,
) -> String {
    let mut s = format!("BLAZEHASH:sha256={manifest_sha256}");
    if let Some(pk) = pubkey_hex {
        s.push_str(&format!("&pubkey={pk}"));
    }
    if let Some(c) = case_id {
        s.push_str(&format!("&case={c}"));
    }
    s
}

/// Generate a PNG QR code file.
#[cfg(feature = "qr")]
pub fn generate_qr_png(content: &str, out_path: &Path) -> Result<()> {
    use qrcode::QrCode;
    use qrcode::render::unicode;
    use image::{ImageBuffer, Luma};

    let code = QrCode::new(content.as_bytes())
        .context("failed to generate QR code — content may be too long")?;
    let image = code.render::<Luma<u8>>()
        .module_dimensions(8, 8)
        .quiet_zone(true)
        .build();
    image.save(out_path)
        .with_context(|| format!("cannot write PNG {}", out_path.display()))?;
    Ok(())
}

/// Generate an SVG QR code file.
#[cfg(feature = "qr")]
pub fn generate_qr_svg(content: &str, out_path: &Path) -> Result<()> {
    use qrcode::QrCode;
    use qrcode::render::svg;

    let code = QrCode::new(content.as_bytes())
        .context("failed to generate QR code")?;
    let svg_string = code.render::<svg::Color>()
        .module_dimensions(8, 8)
        .quiet_zone(true)
        .build();
    std::fs::write(out_path, svg_string)
        .with_context(|| format!("cannot write SVG {}", out_path.display()))?;
    Ok(())
}

/// Compute SHA-256 of a manifest file.
#[cfg(feature = "qr")]
pub fn manifest_sha256(manifest_path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read {}", manifest_path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}
```

**Note on `qrcode` render API:** The exact render API (`render::<Luma<u8>>()`) should be confirmed against `qrcode` 0.14 docs. The `image` crate's `Luma<u8>` is the standard grayscale pixel type.

### Step 4: Implement `src/commands/qr.rs`

```rust
#[cfg(feature = "qr")]
pub struct QrArgs {
    pub manifest: std::path::PathBuf,
    pub output: std::path::PathBuf,
    pub case_id: Option<String>,
    pub svg: bool,
}

#[cfg(feature = "qr")]
pub fn run_qr(args: QrArgs) -> anyhow::Result<()> {
    use blazehash::qr_label::*;

    let sha256 = manifest_sha256(&args.manifest)?;

    // Read pubkey from .pub sidecar if present
    let pub_path = {
        let name = format!("{}.pub",
            args.manifest.file_name().unwrap().to_str().unwrap());
        args.manifest.with_file_name(name)
    };
    let pubkey = if pub_path.exists() {
        Some(std::fs::read_to_string(&pub_path)?.trim().to_string())
    } else {
        None
    };

    let content = build_qr_content(
        &sha256,
        pubkey.as_deref(),
        args.case_id.as_deref(),
    );

    if args.svg {
        generate_qr_svg(&content, &args.output)?;
    } else {
        generate_qr_png(&content, &args.output)?;
    }

    eprintln!("[+] QR label: {}", args.output.display());
    eprintln!("[+] QR content: {content}");
    Ok(())
}
```

### Step 5: Register in lib.rs, wire CLI

In `src/lib.rs`: add `pub mod qr_label;`

Add `--svg` flag to `Cli` struct. Add `QrLabel` mode. Add `pub mod qr;` in `src/commands/mod.rs`. Dispatch in `src/main.rs`:

```rust
#[cfg(feature = "qr")]
if let Mode::QrLabel = cli.mode() {
    let manifest = cli.paths.get(1).cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash qr <manifest> -o <label.png>"))?;
    let out = output.ok_or_else(|| anyhow::anyhow!("qr requires -o <output>"))?;
    commands::qr::run_qr(commands::qr::QrArgs {
        manifest,
        output: out,
        case_id: cli.case_id.clone(),
        svg: cli.svg,
    })?;
    return Ok(());
}
```

### Step 6: Commits

```bash
git add tests/qr_tests.rs
git commit -m "test(RED): add failing QR code generation tests"

git add src/qr_label.rs src/commands/qr.rs src/lib.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash qr — QR code evidence label (PNG/SVG)"
```

---

## Task 7: Chunked GPU SHA-256 — WGSL shader

The current `sha256.wgsl` hardcodes the SHA-256 IV (`h0..h7`). For chunked streaming, we need to accept an external initial state so intermediate state from one GPU dispatch can seed the next.

**Files:**
- Modify: `src/gpu/sha256.wgsl`
- Modify: `src/gpu/sha256.rs`
- Test: `tests/gpu_tests.rs` (append)

### Step 1: Add failing tests

Append to `tests/gpu_tests.rs`:

```rust
#[cfg(feature = "gpu")]
mod chunked_tests {
    use blazehash::gpu::backend::GpuBackend;
    use blazehash::gpu::sha256::GpuSha256;
    use sha2::{Digest, Sha256};

    fn cpu_sha256(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    #[test]
    fn test_chunked_matches_cpu_small() {
        let Some(backend) = GpuBackend::detect() else { return; };
        let gpu = GpuSha256::new(&backend);
        let data = b"hello world";
        let gpu_result = gpu.hash_chunked(data).unwrap();
        assert_eq!(gpu_result, cpu_sha256(data));
    }

    #[test]
    fn test_chunked_matches_cpu_exactly_one_block() {
        let Some(backend) = GpuBackend::detect() else { return; };
        let gpu = GpuSha256::new(&backend);
        // 55 bytes: pads to exactly one 64-byte block
        let data = vec![0xABu8; 55];
        assert_eq!(gpu.hash_chunked(&data).unwrap(), cpu_sha256(&data));
    }

    #[test]
    fn test_chunked_matches_cpu_multiple_blocks() {
        let Some(backend) = GpuBackend::detect() else { return; };
        let gpu = GpuSha256::new(&backend);
        // 1 MiB: forces multiple 64-byte blocks
        let data = vec![0x42u8; 1024 * 1024];
        assert_eq!(gpu.hash_chunked(&data).unwrap(), cpu_sha256(&data));
    }

    #[test]
    fn test_chunked_matches_cpu_large_multi_batch() {
        let Some(backend) = GpuBackend::detect() else { return; };
        let gpu = GpuSha256::new(&backend);
        // 10 MiB: forces chunked batching if BATCH_BLOCKS < ~163840
        let data = vec![0x77u8; 10 * 1024 * 1024];
        assert_eq!(gpu.hash_chunked(&data).unwrap(), cpu_sha256(&data));
    }
}
```

### Step 2: Confirm RED

```bash
cargo test --test gpu_tests --features gpu -- chunked 2>&1 | grep "FAILED\|error"
```
Expected: `hash_chunked` method not found.

### Step 3: Modify `src/gpu/sha256.wgsl`

Add a fourth binding for initial state. Replace the hardcoded IV initialization:

```wgsl
// SHA-256 compute shader — chunked streaming variant
// Binding 0: padded message blocks (big-endian u32 words)
// Binding 1: output digest / intermediate state (8 u32)
// Binding 2: params (num_blocks)
// Binding 3: initial state h0..h7 (8 u32); use SHA-256 IV for first chunk

struct Params {
    num_blocks: u32,
}

@group(0) @binding(0) var<storage, read>       msg:       array<u32>;
@group(0) @binding(1) var<storage, read_write> digest:    array<u32>;
@group(0) @binding(2) var<uniform>             params:    Params;
@group(0) @binding(3) var<storage, read>       init_state: array<u32>;

// ... (keep all k_val, rotr, ch, maj, ep0, ep1, sig0, sig1 functions unchanged)

@compute @workgroup_size(1)
fn main() {
    // Read initial state from binding 3 instead of hardcoding IV
    var h0: u32 = init_state[0];
    var h1: u32 = init_state[1];
    var h2: u32 = init_state[2];
    var h3: u32 = init_state[3];
    var h4: u32 = init_state[4];
    var h5: u32 = init_state[5];
    var h6: u32 = init_state[6];
    var h7: u32 = init_state[7];

    // ... (rest of the compression loop unchanged)
}
```

**Full replacement of `sha256.wgsl`:** copy the existing file and replace only the `main()` function's first 8 lines (the hardcoded `h0..h7 = <IV>` values) with the `init_state[0..7]` reads. Add binding 3 declaration at the top. Everything else (k_val, rotr, compression loop) stays identical.

### Step 4: Modify `src/gpu/sha256.rs` — add `hash_chunked`

The SHA-256 IV as a constant:
```rust
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Maximum blocks per GPU dispatch (64 KiB of data = 1024 blocks).
const BATCH_BLOCKS: usize = 1024;
```

Update the existing `new()` to add binding 3 to the `BindGroupLayout` (read-only storage buffer for `init_state`).

Add the new `compress_blocks()` private method — runs one GPU dispatch with given `blocks_data` (raw u32 words, pre-padded) and `init_state`, returns the updated state:

```rust
fn compress_blocks(&self, words: &[u32], init: &[u32; 8]) -> [u32; 8] {
    // ... create msg_buf from words, init_state_buf from init
    // ... create bind group with 4 bindings
    // ... dispatch, read back 8 u32s as new state
    // Returns [h0, h1, h2, h3, h4, h5, h6, h7]
}
```

Add public `hash_chunked()` method:

```rust
pub fn hash_chunked(&self, data: &[u8]) -> anyhow::Result<String> {
    let total_bits = data.len() as u64 * 8;
    let mut state = SHA256_IV;

    // Process all full 64-byte blocks except the last batch
    // (no SHA-256 padding until the very end)
    let full_blocks = data.len() / 64;
    let remainder = data.len() % 64;

    let mut offset = 0usize;
    let mut blocks_left = full_blocks;

    while blocks_left > 0 {
        let batch = blocks_left.min(BATCH_BLOCKS);
        // Take batch * 64 bytes, convert to big-endian u32 words
        let chunk = &data[offset..offset + batch * 64];
        let words: Vec<u32> = chunk.chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        state = self.compress_blocks(&words, &state);
        offset += batch * 64;
        blocks_left -= batch;
    }

    // Build the final padded chunk (remainder bytes + SHA-256 padding)
    let remaining = &data[offset..];
    let padded_words = pad_final_chunk(remaining, total_bits);
    let batch_size = padded_words.len() / 16;
    // Process in BATCH_BLOCKS batches if very large padding
    let mut pad_offset = 0;
    let mut pad_left = padded_words.len() / 16;
    while pad_left > 0 {
        let batch = pad_left.min(BATCH_BLOCKS);
        let words = &padded_words[pad_offset * 16..(pad_offset + batch) * 16];
        state = self.compress_blocks(words, &state);
        pad_offset += batch;
        pad_left -= batch;
    }

    Ok(state.iter().map(|w| format!("{w:08x}")).collect())
}
```

`pad_final_chunk(data, total_bits)` applies SHA-256 padding to the final partial block and returns the big-endian u32 word sequence. This is the same logic as the existing `pad_message()` but takes the total bit count from the full original message.

### Step 5: Run tests

```bash
cargo test --test gpu_tests --features gpu -- chunked 2>&1 | tail -10
```

### Step 6: Wire `hash_chunked` into `hash_file`

In `src/hash.rs`, where GPU SHA-256 is called for large files (above a threshold), use `hash_chunked` instead of `hash`:

```rust
const GPU_CHUNK_THRESHOLD: u64 = 64 * 1024 * 1024; // 64 MiB

// In the GPU dispatch block:
let hash_str = if file_size > GPU_CHUNK_THRESHOLD {
    gpu_sha256.hash_chunked(&file_bytes)?
} else {
    gpu_sha256.hash(&file_bytes)
};
```

### Step 7: Commits

```bash
git add tests/gpu_tests.rs
git commit -m "test(RED): failing tests for chunked GPU SHA-256 streaming"

git add src/gpu/sha256.wgsl src/gpu/sha256.rs src/hash.rs
git commit -m "feat: chunked GPU SHA-256 — streaming multi-dispatch for large files"
```

---

## Task 8: CI — add new feature flag test variants

**Files:**
- Modify: `.github/workflows/ci.yml`

Add steps for `pq` and `qr` features (they're in default, so standard `cargo test` covers them, but add explicit feature variant tests):

```yaml
- name: Test pq feature
  run: cargo test --features pq

- name: Test qr feature
  run: cargo test --features qr

- name: Test pq-only (no other features)
  run: cargo test --no-default-features --features pq
```

### Commit

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add pq and qr feature variant test steps"
```

---

## Task 9: Docs

**Files:**
- Modify: `docs/custody.md` (add PQ signing section)
- Modify: `docs/index.md` (update feature table)
- Modify: `README.md` (update feature table)

Add to the feature comparison table:
```
| Post-quantum signing (ML-DSA-65) | Y | -- | -- | -- |
| Merkle inclusion proofs          | Y | -- | -- | -- |
| QR code evidence labels          | Y | -- | -- | -- |
```

Add a "Post-quantum signing" section to `docs/custody.md`:

```markdown
### Post-quantum signing (future-proof)

Standard Ed25519 signing is secure today but broken by a sufficiently powerful
quantum computer. If evidence collected now may be challenged in 10+ years, add
a ML-DSA-65 signature alongside the Ed25519 one:

```bash
blazehash sign evidence.hash          # Ed25519 (today's standard)
blazehash pq-sign evidence.hash       # ML-DSA-65 (quantum-resistant)
# → evidence.hash.sig
# → evidence.hash.pub
# → evidence.hash.pqsig

# Verify both
blazehash verify-sig evidence.hash
blazehash pq-verify-sig evidence.hash
```

ML-DSA-65 is NIST-standardized (FIPS 204, 2024). Same password → same key on
any machine. No key files.
```

### Commit

```bash
git add docs/custody.md docs/index.md README.md
git commit -m "docs: document pq-sign, merkle proofs, qr label subcommands"
```

---

## Final verification

```bash
cargo test --all-features 2>&1 | tail -20
cargo clippy --all-features -- -D warnings
cargo build --release --all-features
```

All tests green, no clippy warnings, release build succeeds.
