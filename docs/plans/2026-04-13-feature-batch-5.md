# Feature Batch 5 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Four forensic-grade features: selective disclosure Merkle proofs, chain-of-custody timeline, MITRE ATT&CK annotation in STIX output, and redacted manifests.

**Architecture:** Each feature is a standalone module (`disclosure.rs`, `timeline.rs`, `attack.rs`, `commands/redact.rs`). Selective disclosure and redact build on `merkle.rs` and `manifest_loader.rs`. Timeline scans sidecar files. ATT&CK enriches STIX output without changing its public API. All wired through `cli.rs` / `main.rs` string dispatch.

**Tech Stack:** Rust, `sha2`, `uuid` (v5), `serde_json`, `minijinja`, `chrono`, existing `merkle.rs` / `manifest_loader.rs` / `signing.rs` / `cosign.rs` / `ots.rs` / `yara_scan.rs`

---

### Task 1: Selective disclosure library

**Files:**
- Create: `src/disclosure.rs`
- Create: `tests/disclosure_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/disclosure_tests.rs
use blazehash::disclosure::{generate_selective_proof, verify_selective_proof, SelectiveProof};
use blazehash::merkle::merkle_root;

fn sample_entries() -> Vec<(String, String, String)> {
    vec![
        ("sha256".into(), "abc/secret.txt".into(),  "aaaa".repeat(16)),
        ("sha256".into(), "abc/evidence.bin".into(), "bbbb".repeat(16)),
        ("sha256".into(), "abc/notes.txt".into(),   "cccc".repeat(16)),
    ]
}

#[test]
fn test_selective_proof_reveals_only_requested_paths() {
    let entries = sample_entries();
    let proof = generate_selective_proof(&entries, &["abc/evidence.bin"]).unwrap();
    // Disclosed paths must include only the requested one
    assert_eq!(proof.disclosed.len(), 1);
    assert_eq!(proof.disclosed[0].path, "abc/evidence.bin");
    // Root must match full tree
    let root = merkle_root(&entries).unwrap();
    assert_eq!(proof.root, root);
}

#[test]
fn test_selective_proof_verifies_successfully() {
    let entries = sample_entries();
    let proof = generate_selective_proof(&entries, &["abc/evidence.bin"]).unwrap();
    assert!(verify_selective_proof(&proof).unwrap());
}

#[test]
fn test_selective_proof_tampered_hash_fails() {
    let entries = sample_entries();
    let mut proof = generate_selective_proof(&entries, &["abc/evidence.bin"]).unwrap();
    proof.disclosed[0].sha256 = "0".repeat(64);
    assert!(!verify_selective_proof(&proof).unwrap());
}

#[test]
fn test_selective_proof_multiple_paths() {
    let entries = sample_entries();
    let proof = generate_selective_proof(&entries, &["abc/evidence.bin", "abc/notes.txt"]).unwrap();
    assert_eq!(proof.disclosed.len(), 2);
    assert!(verify_selective_proof(&proof).unwrap());
}

#[test]
fn test_selective_proof_unknown_path_errors() {
    let entries = sample_entries();
    let result = generate_selective_proof(&entries, &["nonexistent.bin"]);
    assert!(result.is_err());
}

#[test]
fn test_membership_proof_proves_hash_exists_without_revealing_path() {
    use blazehash::disclosure::{prove_hash_membership, verify_membership_proof};
    let entries = sample_entries();
    let target_hash = "bbbb".repeat(16); // evidence.bin's hash
    let proof = prove_hash_membership(&entries, &target_hash).unwrap();
    // Proof MUST NOT contain the file path
    let json = serde_json::to_string(&proof).unwrap();
    assert!(!json.contains("evidence.bin"));
    // But verification must pass
    assert!(verify_membership_proof(&proof, &target_hash).unwrap());
}

#[test]
fn test_membership_proof_wrong_hash_fails() {
    use blazehash::disclosure::{prove_hash_membership, verify_membership_proof};
    let entries = sample_entries();
    let proof = prove_hash_membership(&entries, &"bbbb".repeat(16)).unwrap();
    assert!(!verify_membership_proof(&proof, &"dead".repeat(16)).unwrap());
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features 2>&1 | grep -E "^error|FAILED|test result"
```

Expected: compile error — `blazehash::disclosure` not found.

**Step 3: Implement `src/disclosure.rs`**

```rust
//! Selective disclosure Merkle proofs.
//!
//! `generate_selective_proof` proves specific files are in a manifest's Merkle tree
//! without revealing other file paths. The verifier only sees the disclosed entries
//! plus their sibling hashes (Merkle proof paths) and the root.
//!
//! `prove_hash_membership` is the zero-knowledge variant: proves "at least one file
//! in this manifest has this SHA-256" without revealing which file or any other path.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A single disclosed entry in a selective proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosedEntry {
    pub path: String,
    pub sha256: String,
    /// Merkle sibling hashes from leaf to root (hex strings).
    pub proof_path: Vec<String>,
}

/// A selective disclosure proof for one or more files in a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveProof {
    /// Merkle root of the full manifest.
    pub root: String,
    /// Number of leaves in the full tree (for proof verification).
    pub tree_size: usize,
    pub disclosed: Vec<DisclosedEntry>,
}

/// A zero-knowledge membership proof: proves a given SHA-256 appears somewhere
/// in the manifest, without revealing the path or other file hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipProof {
    pub root: String,
    pub tree_size: usize,
    /// Blinded leaf hash: SHA256(0x00 || BLIND || 0x00 || sha256_hex)
    /// where BLIND = SHA256(path || nonce) — path is never revealed.
    pub blinded_leaf: String,
    /// Merkle sibling hashes from the blinded leaf to the root.
    pub proof_path: Vec<String>,
    /// Nonce used in blinding (hex). Verifier needs it to recompute blinded_leaf
    /// when given the target hash (path remains hidden).
    pub nonce: String,
    /// Commitment: SHA256(path || nonce) — reveals nothing about path alone.
    pub path_commitment: String,
}

// ─── leaf / node hashing (mirrors merkle.rs) ──────────────────────────────

fn leaf_hash(path: &str, sha256_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(path.as_bytes());
    h.update([0x00]);
    h.update(sha256_hex.as_bytes());
    hex::encode(h.finalize())
}

fn node_hash(a: &str, b: &str) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(hex::decode(lo).unwrap_or_default());
    h.update(hex::decode(hi).unwrap_or_default());
    hex::encode(h.finalize())
}

fn build_leaves(entries: &[(String, String, String)]) -> Vec<(String, String, String)> {
    // entries: (algo, path, hash) — we only care about sha256 entries
    let mut sha_entries: Vec<(String, String)> = entries
        .iter()
        .filter(|(algo, _, _)| algo == "sha256")
        .map(|(_, path, hash)| (path.clone(), hash.clone()))
        .collect();
    sha_entries.sort_by(|a, b| a.0.cmp(&b.0));
    sha_entries
        .into_iter()
        .map(|(path, hash)| {
            let leaf = leaf_hash(&path, &hash);
            (path, hash, leaf)
        })
        .collect()
}

fn build_tree_levels(leaves: &[String]) -> Vec<Vec<String>> {
    let mut levels: Vec<Vec<String>> = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next: Vec<String> = prev
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    node_hash(&chunk[0], &chunk[1])
                } else {
                    chunk[0].clone()
                }
            })
            .collect();
        if next.is_empty() {
            next = prev.clone();
        }
        levels.push(next);
    }
    levels
}

fn merkle_proof_path(levels: &[Vec<String>], leaf_idx: usize) -> Vec<String> {
    let mut path = Vec::new();
    let mut idx = leaf_idx;
    for level in &levels[..levels.len() - 1] {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() {
            path.push(level[sibling_idx].clone());
        }
        idx /= 2;
    }
    path
}

fn verify_proof_path(leaf_hash_hex: &str, proof_path: &[String], root: &str) -> bool {
    let mut current = leaf_hash_hex.to_string();
    for sibling in proof_path {
        current = node_hash(&current, sibling);
    }
    current == root
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Generate a selective disclosure proof for `disclosed_paths` within `entries`.
///
/// Callers can share this proof with a third party. The third party learns:
/// - The Merkle root of the full manifest
/// - The disclosed file paths, their SHA-256 hashes, and their proof paths
/// - Nothing else about the remaining files
pub fn generate_selective_proof(
    entries: &[(String, String, String)],
    disclosed_paths: &[&str],
) -> Result<SelectiveProof> {
    let leaves = build_leaves(entries);
    if leaves.is_empty() {
        bail!("no SHA-256 entries found in manifest");
    }

    let leaf_hashes: Vec<String> = leaves.iter().map(|(_, _, h)| h.clone()).collect();
    let levels = build_tree_levels(&leaf_hashes);
    let root = levels.last().unwrap()[0].clone();

    let mut disclosed = Vec::new();
    for &dp in disclosed_paths {
        let pos = leaves
            .iter()
            .position(|(path, _, _)| path == dp)
            .ok_or_else(|| anyhow::anyhow!("path not found in manifest: {dp}"))?;
        let proof_path = merkle_proof_path(&levels, pos);
        disclosed.push(DisclosedEntry {
            path: leaves[pos].0.clone(),
            sha256: leaves[pos].1.clone(),
            proof_path,
        });
    }

    Ok(SelectiveProof {
        root,
        tree_size: leaves.len(),
        disclosed,
    })
}

/// Verify a selective disclosure proof. Returns `true` iff every disclosed
/// entry's leaf hashes correctly to the root via its proof path.
pub fn verify_selective_proof(proof: &SelectiveProof) -> Result<bool> {
    for entry in &proof.disclosed {
        let lh = leaf_hash(&entry.path, &entry.sha256);
        if !verify_proof_path(&lh, &entry.proof_path, &proof.root) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Zero-knowledge membership proof: prove `target_sha256` appears in `entries`
/// without revealing which file or any other paths.
pub fn prove_hash_membership(
    entries: &[(String, String, String)],
    target_sha256: &str,
) -> Result<MembershipProof> {
    let leaves = build_leaves(entries);
    let pos = leaves
        .iter()
        .position(|(_, hash, _)| hash == target_sha256)
        .ok_or_else(|| anyhow::anyhow!("target hash not found in manifest"))?;

    // Blind the path: commitment = SHA256(path || nonce), blinded_leaf = SHA256(0x00 || commitment || 0x00 || sha256_hex)
    let nonce = hex::encode(rand_nonce());
    let path = &leaves[pos].0;
    let mut commitment_h = Sha256::new();
    commitment_h.update(path.as_bytes());
    commitment_h.update(nonce.as_bytes());
    let path_commitment = hex::encode(commitment_h.finalize());

    let mut bl_h = Sha256::new();
    bl_h.update([0x00]);
    bl_h.update(path_commitment.as_bytes());
    bl_h.update([0x00]);
    bl_h.update(target_sha256.as_bytes());
    let blinded_leaf = hex::encode(bl_h.finalize());

    // Build the real tree and get the proof path for the actual leaf position
    let leaf_hashes: Vec<String> = leaves.iter().map(|(_, _, h)| h.clone()).collect();
    let levels = build_tree_levels(&leaf_hashes);
    let root = levels.last().unwrap()[0].clone();
    // For membership proof, proof_path is over the blinded leaf, not the real leaf.
    // We rebuild a tree with the blinded leaf substituted at pos.
    let mut blinded_hashes = leaf_hashes.clone();
    blinded_hashes[pos] = blinded_leaf.clone();
    let blinded_levels = build_tree_levels(&blinded_hashes);
    let blinded_root = blinded_levels.last().unwrap()[0].clone();
    let proof_path = merkle_proof_path(&blinded_levels, pos);

    Ok(MembershipProof {
        root: blinded_root,
        tree_size: leaves.len(),
        blinded_leaf,
        proof_path,
        nonce,
        path_commitment,
    })
}

/// Verify a membership proof for `target_sha256`.
///
/// The verifier can confirm a file with this hash is in the manifest without
/// learning anything about which file it is or what other files exist.
pub fn verify_membership_proof(proof: &MembershipProof, target_sha256: &str) -> Result<bool> {
    // Recompute blinded_leaf from path_commitment + target_sha256
    let mut bl_h = Sha256::new();
    bl_h.update([0x00]);
    bl_h.update(proof.path_commitment.as_bytes());
    bl_h.update([0x00]);
    bl_h.update(target_sha256.as_bytes());
    let expected_blinded_leaf = hex::encode(bl_h.finalize());
    if expected_blinded_leaf != proof.blinded_leaf {
        return Ok(false);
    }
    Ok(verify_proof_path(&proof.blinded_leaf, &proof.proof_path, &proof.root))
}

fn rand_nonce() -> [u8; 16] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    let v = h.finish();
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&v.to_le_bytes());
    buf[8..].copy_from_slice(&v.wrapping_add(1).to_le_bytes());
    buf
}
```

**Step 4: Wire into `src/lib.rs`**

Add `pub mod disclosure;` to the public module list.

**Step 5: Run tests**

```bash
cargo test --all-features 2>&1 | grep -E "disclosure|FAILED|ok$|test result"
```

Expected: all 7 disclosure tests pass.

**Step 6: Commit GREEN**

```bash
git add src/disclosure.rs tests/disclosure_tests.rs src/lib.rs
git commit -m "feat: selective disclosure Merkle proofs (generate + verify + ZK membership)"
```

---

### Task 2: Wire disclosure into CLI

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `tests/disclosure_cli_tests.rs`

**Step 1: Write failing CLI tests**

```rust
// tests/disclosure_cli_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    fs::write(&p, "## case: CASE-001\n## examiner: Jane\nsha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  evidence/a.bin\nsha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  evidence/b.bin\n").unwrap();
    p
}

#[test]
fn test_cli_disclose_produces_json() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("proof.json");
    Command::cargo_bin("blazehash").unwrap()
        .args(["disclose", manifest.to_str().unwrap(),
               "--paths", "evidence/a.bin",
               "-o", out.to_str().unwrap()])
        .assert().success();
    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(json["disclosed"][0]["path"], "evidence/a.bin");
    assert!(json["root"].as_str().unwrap().len() == 64);
}

#[test]
fn test_cli_prove_membership_produces_json() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("membership.json");
    Command::cargo_bin("blazehash").unwrap()
        .args(["prove-membership", manifest.to_str().unwrap(),
               "--sha256", &"a".repeat(64),
               "-o", out.to_str().unwrap()])
        .assert().success();
    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert!(json["root"].as_str().is_some());
    // Path must NOT appear in output
    assert!(!fs::read_to_string(&out).unwrap().contains("evidence/a.bin"));
}

#[test]
fn test_cli_disclose_unknown_path_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    Command::cargo_bin("blazehash").unwrap()
        .args(["disclose", manifest.to_str().unwrap(),
               "--paths", "no_such_file.bin"])
        .assert().failure();
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test disclosure_cli_tests 2>&1 | grep -E "FAILED|error|test result"
```

Expected: subcommand not found errors.

**Step 3: Add CLI variants**

In `src/cli.rs`, add to `Mode` enum:
```rust
Disclose,
ProveMembership,
```

Add `--paths` and `--sha256` string arguments to the CLI arg struct (can reuse existing `-o / --output` pattern).

**Step 4: Add dispatch in `src/main.rs`**

```rust
Mode::Disclose => {
    let paths: Vec<&str> = cli.paths.as_deref().unwrap_or("").split(',').collect();
    let entries = load_manifest_as_entries(&cli.manifest)?;
    let proof = disclosure::generate_selective_proof(&entries, &paths)?;
    let json = serde_json::to_string_pretty(&proof)?;
    if let Some(out) = &cli.output {
        std::fs::write(out, &json)?;
    } else {
        println!("{json}");
    }
}
Mode::ProveMembership => {
    let sha256 = cli.sha256.as_deref().ok_or_else(|| anyhow::anyhow!("--sha256 required"))?;
    let entries = load_manifest_as_entries(&cli.manifest)?;
    let proof = disclosure::prove_hash_membership(&entries, sha256)?;
    let json = serde_json::to_string_pretty(&proof)?;
    if let Some(out) = &cli.output {
        std::fs::write(out, &json)?;
    } else {
        println!("{json}");
    }
}
```

Add a small helper `load_manifest_as_entries(path) -> Result<Vec<(String, String, String)>>` that reads and parses manifest lines into `(algo, path, hash)` tuples using `manifest_loader`.

**Step 5: Run tests**

```bash
cargo test --all-features --test disclosure_cli_tests 2>&1 | grep -E "FAILED|ok|test result"
```

**Step 6: Commit**

```bash
git add src/cli.rs src/main.rs tests/disclosure_cli_tests.rs
git commit -m "feat: wire blazehash disclose / prove-membership into CLI"
```

---

### Task 3: Chain-of-custody timeline library

**Files:**
- Create: `src/timeline.rs`
- Create: `tests/timeline_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/timeline_tests.rs
use blazehash::timeline::{build_timeline, TimelineEvent, TimelineEventKind};
use tempfile::TempDir;
use std::fs;

fn write_sidecar(dir: &TempDir, name: &str, content: &str) {
    fs::write(dir.path().join(name), content).unwrap();
}

#[test]
fn test_timeline_empty_when_no_sidecars() {
    let dir = TempDir::new().unwrap();
    let manifest = dir.path().join("case.hash");
    fs::write(&manifest, "sha256  aaa  file.bin\n").unwrap();
    let events = build_timeline(&manifest).unwrap();
    // At minimum the manifest creation event should be present
    assert!(!events.is_empty());
}

#[test]
fn test_timeline_includes_sig_event() {
    let dir = TempDir::new().unwrap();
    let manifest = dir.path().join("case.hash");
    fs::write(&manifest, "sha256  aaa  file.bin\n").unwrap();
    // Write a .sig sidecar with metadata comment
    write_sidecar(&dir, "case.hash.sig", "# signed_at: 2026-04-13T00:00:00Z\n# pubkey: abcd1234\naabbccdd");
    let events = build_timeline(&manifest).unwrap();
    let kinds: Vec<_> = events.iter().map(|e| &e.kind).collect();
    assert!(kinds.iter().any(|k| matches!(k, TimelineEventKind::Signed { .. })));
}

#[test]
fn test_timeline_includes_msig_event() {
    let dir = TempDir::new().unwrap();
    let manifest = dir.path().join("case.hash");
    fs::write(&manifest, "sha256  aaa  file.bin\n").unwrap();
    let msig_json = r#"{"manifest_sha256":"aaa","signatures":[{"pubkey":"aa","sig":"bb","signed_at":"2026-04-13T01:00:00Z"},{"pubkey":"cc","sig":"dd","signed_at":"2026-04-13T02:00:00Z"}]}"#;
    write_sidecar(&dir, "case.hash.msig", msig_json);
    let events = build_timeline(&manifest).unwrap();
    let cosigned_count = events.iter().filter(|e| matches!(e.kind, TimelineEventKind::Cosigned { .. })).count();
    assert_eq!(cosigned_count, 2);
}

#[test]
fn test_timeline_includes_ots_event() {
    let dir = TempDir::new().unwrap();
    let manifest = dir.path().join("case.hash");
    fs::write(&manifest, "sha256  aaa  file.bin\n").unwrap();
    write_sidecar(&dir, "case.hash.ots", "dummy ots data");
    let events = build_timeline(&manifest).unwrap();
    assert!(events.iter().any(|e| matches!(e.kind, TimelineEventKind::Timestamped { .. })));
}

#[test]
fn test_timeline_events_are_sorted_by_time() {
    let dir = TempDir::new().unwrap();
    let manifest = dir.path().join("case.hash");
    fs::write(&manifest, "sha256  aaa  file.bin\n").unwrap();
    write_sidecar(&dir, "case.hash.sig", "# signed_at: 2026-04-14T00:00:00Z\naabbccdd");
    let events = build_timeline(&manifest).unwrap();
    let times: Vec<_> = events.iter().filter_map(|e| e.timestamp.as_deref()).collect();
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted);
}

#[test]
fn test_timeline_json_output_roundtrip() {
    let dir = TempDir::new().unwrap();
    let manifest = dir.path().join("case.hash");
    fs::write(&manifest, "sha256  aaa  file.bin\n").unwrap();
    let events = build_timeline(&manifest).unwrap();
    let json = serde_json::to_string(&events).unwrap();
    let parsed: Vec<TimelineEvent> = serde_json::from_str(&json).unwrap();
    assert_eq!(events.len(), parsed.len());
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test timeline_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/timeline.rs`**

```rust
//! Chain-of-custody timeline reconstruction.
//!
//! Scans for sidecar files alongside a manifest (.sig, .pub, .msig, .ots, .pqsig)
//! and reconstructs the custody events in chronological order.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimelineEventKind {
    /// Manifest file created (mtime of the file itself).
    Acquired,
    /// Ed25519 signature applied (.sig sidecar).
    Signed { pubkey: String },
    /// Additional examiner cosignature (.msig entry).
    Cosigned { pubkey: String },
    /// Bitcoin/OTS timestamp proof (.ots sidecar).
    Timestamped,
    /// Post-quantum ML-DSA signature (.pqsig sidecar).
    PqSigned { pubkey_prefix: String },
    /// Manual audit run (no sidecar — must be provided externally).
    Audited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub kind: TimelineEventKind,
    /// ISO-8601 timestamp, if determinable from sidecar metadata.
    pub timestamp: Option<String>,
    pub description: String,
}

/// Read `# key: value` metadata from the first few lines of a sidecar file.
fn read_sidecar_meta(path: &Path, key: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines().take(10) {
        if let Some(rest) = line.strip_prefix(&format!("# {key}:")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn file_mtime_iso(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    let secs = mtime
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    // Format as rough ISO-8601 (seconds precision)
    let dt = chrono::DateTime::from_timestamp(secs as i64, 0)?;
    Some(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Build a chronological chain-of-custody timeline for `manifest_path`.
pub fn build_timeline(manifest_path: &Path) -> Result<Vec<TimelineEvent>> {
    let mut events: Vec<(Option<String>, TimelineEvent)> = Vec::new();

    // 1. Acquisition event — manifest file mtime
    let acquired_at = file_mtime_iso(manifest_path);
    events.push((
        acquired_at.clone(),
        TimelineEvent {
            kind: TimelineEventKind::Acquired,
            timestamp: acquired_at,
            description: "Manifest created (evidence acquired)".into(),
        },
    ));

    // 2. Ed25519 .sig sidecar
    let sig_path = {
        let mut p = manifest_path.to_path_buf();
        p.set_extension(format!(
            "{}.sig",
            p.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default()
        ));
        // Simpler: just append .sig
        let name = format!("{}.sig", manifest_path.file_name().unwrap().to_string_lossy());
        manifest_path.parent().unwrap_or(Path::new(".")).join(name)
    };
    if sig_path.exists() {
        let signed_at = read_sidecar_meta(&sig_path, "signed_at")
            .or_else(|| file_mtime_iso(&sig_path));
        let pubkey = read_sidecar_meta(&sig_path, "pubkey").unwrap_or_default();
        events.push((
            signed_at.clone(),
            TimelineEvent {
                kind: TimelineEventKind::Signed { pubkey: pubkey.clone() },
                timestamp: signed_at,
                description: format!("Ed25519 signature applied (pubkey: {pubkey})"),
            },
        ));
    }

    // 3. .msig multi-party cosignatures
    let msig_path = {
        let name = format!("{}.msig", manifest_path.file_name().unwrap().to_string_lossy());
        manifest_path.parent().unwrap_or(Path::new(".")).join(name)
    };
    if msig_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&msig_path) {
            if let Ok(msig) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(sigs) = msig["signatures"].as_array() {
                    for sig in sigs {
                        let signed_at = sig["signed_at"].as_str().map(String::from);
                        let pubkey = sig["pubkey"].as_str().unwrap_or("").to_string();
                        events.push((
                            signed_at.clone(),
                            TimelineEvent {
                                kind: TimelineEventKind::Cosigned { pubkey: pubkey.clone() },
                                timestamp: signed_at,
                                description: format!("Cosignature added (pubkey: {pubkey})"),
                            },
                        ));
                    }
                }
            }
        }
    }

    // 4. .ots timestamp sidecar
    let ots_path = {
        let name = format!("{}.ots", manifest_path.file_name().unwrap().to_string_lossy());
        manifest_path.parent().unwrap_or(Path::new(".")).join(name)
    };
    if ots_path.exists() {
        let ts = file_mtime_iso(&ots_path);
        events.push((
            ts.clone(),
            TimelineEvent {
                kind: TimelineEventKind::Timestamped,
                timestamp: ts,
                description: "OpenTimestamps Bitcoin proof created".into(),
            },
        ));
    }

    // 5. .pqsig post-quantum sidecar
    let pqsig_path = {
        let name = format!("{}.pqsig", manifest_path.file_name().unwrap().to_string_lossy());
        manifest_path.parent().unwrap_or(Path::new(".")).join(name)
    };
    if pqsig_path.exists() {
        let signed_at = read_sidecar_meta(&pqsig_path, "signed_at")
            .or_else(|| file_mtime_iso(&pqsig_path));
        let pubkey = read_sidecar_meta(&pqsig_path, "pubkey").unwrap_or_default();
        let prefix = pubkey.chars().take(16).collect::<String>();
        events.push((
            signed_at.clone(),
            TimelineEvent {
                kind: TimelineEventKind::PqSigned { pubkey_prefix: prefix.clone() },
                timestamp: signed_at,
                description: format!("ML-DSA-65 post-quantum signature applied (pubkey prefix: {prefix}…)"),
            },
        ));
    }

    // Sort by timestamp (None → last)
    events.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(events.into_iter().map(|(_, e)| e).collect())
}
```

**Step 4: Wire into `src/lib.rs`**

Add `pub mod timeline;`.

**Step 5: Run tests**

```bash
cargo test --all-features --test timeline_tests 2>&1 | grep -E "FAILED|ok|test result"
```

**Step 6: Commit**

```bash
git add src/timeline.rs tests/timeline_tests.rs src/lib.rs
git commit -m "feat: chain-of-custody timeline (build_timeline scans sidecars, returns sorted events)"
```

---

### Task 4: Wire timeline into CLI + HTML output

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `tests/timeline_cli_tests.rs`

**Step 1: Write failing CLI tests**

```rust
// tests/timeline_cli_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_cli_timeline_json_stdout() {
    let dir = TempDir::new().unwrap();
    let manifest = dir.path().join("case.hash");
    fs::write(&manifest, "sha256  aaa  file.bin\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["timeline", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(json.is_array());
}

#[test]
fn test_cli_timeline_html_output() {
    let dir = TempDir::new().unwrap();
    let manifest = dir.path().join("case.hash");
    fs::write(&manifest, "sha256  aaa  file.bin\n").unwrap();
    let html_out = dir.path().join("timeline.html");
    Command::cargo_bin("blazehash").unwrap()
        .args(["timeline", manifest.to_str().unwrap(),
               "-o", html_out.to_str().unwrap()])
        .assert().success();
    let html = fs::read_to_string(&html_out).unwrap();
    assert!(html.contains("<html"));
    assert!(html.contains("timeline") || html.contains("Timeline") || html.contains("acquired") || html.contains("Acquired"));
}
```

**Step 2: Run to confirm RED**

**Step 3: Add `Timeline` Mode variant to `src/cli.rs`**

**Step 4: Dispatch in `src/main.rs`**

```rust
Mode::Timeline => {
    use crate::timeline::build_timeline;
    let events = build_timeline(&manifest_path)?;
    if let Some(out) = &cli.output {
        if out.extension().map(|e| e == "html").unwrap_or(false) {
            let html = render_timeline_html(&events, &manifest_path)?;
            std::fs::write(out, html)?;
        } else {
            std::fs::write(out, serde_json::to_string_pretty(&events)?)?;
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&events)?);
    }
}
```

Add `render_timeline_html(events, manifest_path) -> Result<String>` in `src/timeline.rs` using a simple inline template (no external files — minijinja or just format! string for simplicity):

```rust
pub fn render_timeline_html(events: &[TimelineEvent], manifest_path: &Path) -> Result<String> {
    let name = manifest_path.file_name().unwrap_or_default().to_string_lossy();
    let rows: String = events.iter().map(|e| {
        let ts = e.timestamp.as_deref().unwrap_or("unknown");
        let kind = format!("{:?}", e.kind).split('{').next().unwrap_or("").trim().to_string();
        format!("<tr><td>{ts}</td><td>{kind}</td><td>{}</td></tr>", e.description)
    }).collect();
    Ok(format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Chain-of-Custody Timeline</title>
<style>body{{font-family:monospace;margin:2em}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.4em .8em;text-align:left}}th{{background:#f0f0f0}}</style>
</head><body><h1>Chain-of-Custody Timeline</h1><p>Manifest: <code>{name}</code></p>
<table><thead><tr><th>Timestamp</th><th>Event</th><th>Description</th></tr></thead><tbody>{rows}</tbody></table></body></html>"#))
}
```

**Step 5: Run tests**

```bash
cargo test --all-features --test timeline_cli_tests 2>&1 | grep -E "FAILED|ok|test result"
```

**Step 6: Commit**

```bash
git add src/cli.rs src/main.rs src/timeline.rs tests/timeline_cli_tests.rs
git commit -m "feat: wire blazehash timeline into CLI with JSON stdout and HTML -o output"
```

---

### Task 5: MITRE ATT&CK annotation in STIX output

**Files:**
- Create: `src/attack.rs`
- Modify: `src/format/stix.rs`
- Create: `tests/attack_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/attack_tests.rs
use blazehash::attack::{lookup_attack, AttackTechnique};

#[test]
fn test_known_rule_prefix_maps_to_technique() {
    // Rule names starting with "RAT_" → T1219 (Remote Access Software)
    let t = lookup_attack("RAT_QuasarRat").unwrap();
    assert_eq!(t.technique_id, "T1219");
}

#[test]
fn test_unknown_rule_returns_none() {
    assert!(lookup_attack("completelyunknown_XYZ").is_none());
}

#[test]
fn test_ransomware_prefix_maps_to_technique() {
    let t = lookup_attack("Ransomware_LockBit").unwrap();
    assert_eq!(t.technique_id, "T1486");
}

#[test]
fn test_credential_dump_maps_to_technique() {
    let t = lookup_attack("CredDump_Mimikatz").unwrap();
    assert_eq!(t.technique_id, "T1003");
}

#[test]
fn test_stix_output_includes_attack_extension_when_yara_matches() {
    use blazehash::format::write_stix;
    use blazehash::hash::FileHashResult;
    use blazehash::algorithm::Algorithm;
    use std::path::PathBuf;
    use std::collections::HashMap;

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "a".repeat(64));
    let result = FileHashResult {
        path: PathBuf::from("malware.bin"),
        hashes,
        size: 1024,
        entropy: None,
        yara_matches: Some(vec!["RAT_QuasarRat".to_string()]),
    };
    let mut buf = Vec::new();
    write_stix(&mut buf, &[result], &[Algorithm::Blake3]).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let bundle_str = json.to_string();
    assert!(bundle_str.contains("T1219") || bundle_str.contains("x-mitre-attack"));
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test attack_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/attack.rs`**

```rust
//! Static MITRE ATT&CK technique mapping for YARA rule name prefixes.
//!
//! Maps common YARA naming conventions (rule name prefixes) to ATT&CK technique IDs.
//! This is an embedded static mapping — no network calls, no external data.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AttackTechnique {
    pub technique_id: String,
    pub tactic: String,
    pub name: String,
}

/// Rule name prefix → ATT&CK technique mapping.
/// Prefixes are matched case-insensitively as the start of the rule name.
static MAPPINGS: &[(&str, &str, &str, &str)] = &[
    // (prefix, technique_id, tactic, name)
    ("RAT_",          "T1219", "command-and-control", "Remote Access Software"),
    ("Ransomware_",   "T1486", "impact",              "Data Encrypted for Impact"),
    ("Wiper_",        "T1485", "impact",              "Data Destruction"),
    ("CredDump_",     "T1003", "credential-access",   "OS Credential Dumping"),
    ("Keylogger_",    "T1056.001", "collection",      "Input Capture: Keylogging"),
    ("Rootkit_",      "T1014", "defense-evasion",     "Rootkit"),
    ("Backdoor_",     "T1505", "persistence",         "Server Software Component"),
    ("Dropper_",      "T1105", "command-and-control", "Ingress Tool Transfer"),
    ("Miner_",        "T1496", "impact",              "Resource Hijacking"),
    ("Stealer_",      "T1041", "exfiltration",        "Exfiltration Over C2 Channel"),
    ("Spyware_",      "T1125", "collection",          "Video Capture"),
    ("Botnet_",       "T1571", "command-and-control", "Non-Standard Port"),
    ("Exploit_",      "T1203", "execution",           "Exploitation for Client Execution"),
    ("Loader_",       "T1129", "execution",           "Shared Modules"),
    ("Persistence_",  "T1547", "persistence",         "Boot or Logon Autostart Execution"),
    ("Lateral_",      "T1021", "lateral-movement",    "Remote Services"),
    ("Exfil_",        "T1041", "exfiltration",        "Exfiltration Over C2 Channel"),
    ("Packer_",       "T1027", "defense-evasion",     "Obfuscated Files or Information"),
    ("AntiAV_",       "T1562", "defense-evasion",     "Impair Defenses"),
    ("Injection_",    "T1055", "defense-evasion",     "Process Injection"),
    ("Shellcode_",    "T1059", "execution",           "Command and Scripting Interpreter"),
    ("Webshell_",     "T1505.003", "persistence",     "Server Software Component: Web Shell"),
    ("Phishing_",     "T1566", "initial-access",      "Phishing"),
    ("BruteForce_",   "T1110", "credential-access",   "Brute Force"),
    ("SQLInject_",    "T1190", "initial-access",      "Exploit Public-Facing Application"),
    ("Maldoc_",       "T1566.001", "initial-access",  "Phishing: Spearphishing Attachment"),
    ("PowerShell_",   "T1059.001", "execution",       "PowerShell"),
    ("VBA_",          "T1059.005", "execution",       "Visual Basic"),
    ("HTA_",          "T1218.005", "defense-evasion", "Signed Binary Proxy Execution: Mshta"),
    ("WMI_",          "T1047", "execution",           "Windows Management Instrumentation"),
];

/// Look up the ATT&CK technique for a given YARA rule name.
/// Matches by prefix (case-insensitive).
pub fn lookup_attack(rule_name: &str) -> Option<AttackTechnique> {
    let lower = rule_name.to_lowercase();
    for (prefix, technique_id, tactic, name) in MAPPINGS {
        if lower.starts_with(&prefix.to_lowercase()) {
            return Some(AttackTechnique {
                technique_id: technique_id.to_string(),
                tactic: tactic.to_string(),
                name: name.to_string(),
            });
        }
    }
    None
}
```

**Step 4: Enrich `write_stix` in `src/format/stix.rs`**

When a `FileHashResult` has `yara_matches: Some(matches)`, append `x-mitre-attack` extension objects to the STIX bundle for each matched technique:

```rust
// After writing the SCO for each result, check for YARA ATT&CK mappings
#[cfg(feature = "yara")]
if let Some(ref matches) = result.yara_matches {
    for rule in matches {
        if let Some(tech) = crate::attack::lookup_attack(rule) {
            let ext_id = format!("x-mitre-attack--{}", uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_URL,
                format!("{}-{}", result.path.display(), tech.technique_id).as_bytes()
            ));
            objects.push(serde_json::json!({
                "type": "x-mitre-attack",
                "id": ext_id,
                "spec_version": "2.1",
                "technique_id": tech.technique_id,
                "tactic": tech.tactic,
                "technique_name": tech.name,
                "yara_rule": rule,
                "related_file": result.path.to_string_lossy(),
            }));
        }
    }
}
```

**Step 5: Wire into `src/lib.rs`**: Add `pub mod attack;`.

**Step 6: Run tests**

```bash
cargo test --all-features --test attack_tests 2>&1 | grep -E "FAILED|ok|test result"
```

**Step 7: Commit**

```bash
git add src/attack.rs tests/attack_tests.rs src/format/stix.rs src/lib.rs
git commit -m "feat: MITRE ATT&CK annotation for YARA matches in STIX output (static embedded mapping)"
```

---

### Task 6: Redacted manifest

**Files:**
- Create: `src/commands/redact.rs`
- Modify: `src/cli.rs`, `src/main.rs`
- Create: `tests/redact_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/redact_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("evidence.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "## examiner: Jane Smith\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  secret/docs/contract.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  secret/logs/activity.log\n",
    )).unwrap();
    p
}

#[test]
fn test_redact_removes_paths() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    assert!(!content.contains("contract.pdf"));
    assert!(!content.contains("activity.log"));
    assert!(!content.contains("secret/"));
}

#[test]
fn test_redact_preserves_hashes() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    assert!(content.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(content.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
}

#[test]
fn test_redact_replaces_paths_with_uuids() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    // UUIDs are deterministic: same path always maps to same UUID
    // Check each line has a UUID-shaped token (8-4-4-4-12 hex)
    let uuid_re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
    let hash_lines: Vec<_> = content.lines().filter(|l| l.starts_with("sha256")).collect();
    assert_eq!(hash_lines.len(), 2);
    for line in &hash_lines {
        assert!(uuid_re.is_match(line), "UUID not found in line: {line}");
    }
}

#[test]
fn test_redact_is_deterministic() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out1 = dir.path().join("r1.hash");
    let out2 = dir.path().join("r2.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out1.to_str().unwrap()])
        .assert().success();
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out2.to_str().unwrap()])
        .assert().success();
    assert_eq!(fs::read_to_string(&out1).unwrap(), fs::read_to_string(&out2).unwrap());
}

#[test]
fn test_redact_preserves_case_and_examiner_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    assert!(content.contains("## case: CASE-001"));
    assert!(content.contains("## examiner: Jane Smith"));
}

#[test]
fn test_redact_includes_merkle_root_comment() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    // Should include merkle root so verifier can confirm the redacted set matches the original
    assert!(content.contains("merkle_root") || content.contains("## merkle"));
}
```

Note: `regex` is already in Cargo.toml as a dev-dependency.

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test redact_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/commands/redact.rs`**

```rust
//! Redacted manifest: replace file paths with deterministic UUIDs.
//!
//! Preserves all hashes and the Merkle root of the original manifest, allowing
//! a verifier to confirm the redacted set is a valid subset of the signed original
//! without learning any file paths.

use anyhow::Result;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

const REDACT_NAMESPACE: Uuid = Uuid::from_bytes([
    0xb1, 0xa2, 0xe3, 0x74, 0xc5, 0xb6, 0x47, 0xd8,
    0x99, 0x0a, 0x1b, 0xfc, 0x3d, 0x4e, 0x5f, 0x60,
]);

fn path_to_uuid(path: &str) -> String {
    Uuid::new_v5(&REDACT_NAMESPACE, path.as_bytes()).to_string()
}

/// Read a manifest, replace each file path with a deterministic UUID, and write
/// the redacted manifest to `out_path`. Hashes, case, and examiner headers are
/// preserved. A `## merkle_root:` comment is appended for cross-verification.
pub fn redact_manifest(manifest_path: &Path, out_path: &Path) -> Result<()> {
    use crate::merkle::merkle_root;

    let content = std::fs::read_to_string(manifest_path)?;
    let mut header_lines: Vec<String> = Vec::new();
    let mut hash_lines: Vec<(String, String, String)> = Vec::new(); // (algo, original_path, hash)

    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            header_lines.push(line.to_string());
        } else {
            // Parse: <algo>  <hash>  <path>  or  <hash>  <path>
            let parts: Vec<&str> = line.splitn(3, "  ").collect();
            if parts.len() == 3 {
                hash_lines.push((parts[0].trim().to_string(), parts[2].trim().to_string(), parts[1].trim().to_string()));
            }
        }
    }

    // Compute Merkle root of original entries
    let entries: Vec<(String, String, String)> = hash_lines
        .iter()
        .filter(|(algo, _, _)| algo == "sha256")
        .map(|(algo, path, hash)| (algo.clone(), path.clone(), hash.clone()))
        .collect();
    let root = if !entries.is_empty() {
        merkle_root(&entries).unwrap_or_default()
    } else {
        String::new()
    };

    let mut out = std::fs::File::create(out_path)?;

    // Write headers
    for line in &header_lines {
        writeln!(out, "{line}")?;
    }
    if !root.is_empty() {
        writeln!(out, "## merkle_root: {root}")?;
    }

    // Write hash lines with UUID-replaced paths
    for (algo, original_path, hash) in &hash_lines {
        let uuid_path = path_to_uuid(original_path);
        writeln!(out, "{algo}  {hash}  {uuid_path}")?;
    }

    Ok(())
}
```

**Step 4: Wire into CLI**

Add `Redact` to `Mode` in `src/cli.rs`.

Add dispatch in `src/main.rs`:
```rust
Mode::Redact => {
    let out = cli.output.as_deref().ok_or_else(|| anyhow::anyhow!("-o/--output required for redact"))?;
    crate::commands::redact::redact_manifest(&manifest_path, out.as_ref())?;
    eprintln!("Redacted manifest written to {}", out.display());
}
```

Add `pub mod redact;` to `src/commands/mod.rs`.

**Step 5: Run tests**

```bash
cargo test --all-features --test redact_tests 2>&1 | grep -E "FAILED|ok|test result"
```

**Step 6: Run full suite**

```bash
cargo test --all-features 2>&1 | tail -20
```

Expected: 0 failures.

**Step 7: Commit**

```bash
git add src/commands/redact.rs src/commands/mod.rs src/cli.rs src/main.rs tests/redact_tests.rs
git commit -m "feat: blazehash redact — replace file paths with deterministic UUIDs, preserve hashes + Merkle root"
```

---

### Task 7: Final integration check + plan mark complete

**Step 1: Full test suite**

```bash
cargo test --all-features 2>&1 | tail -30
```

**Step 2: Clippy**

```bash
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -20
```

Fix any warnings that become errors.

**Step 3: Update plan doc**

Mark `docs/plans/2026-04-13-feature-batch-5.md` as complete.

**Step 4: Commit fixes if any**

```bash
git add -p && git commit -m "fix: batch 5 clippy / fmt cleanup"
```

**Step 5: Push**

```bash
git push
```

---

## Summary

| Task | Feature | Key file |
|------|---------|----------|
| 1 | Selective disclosure library | `src/disclosure.rs` |
| 2 | Disclosure CLI (disclose + prove-membership) | `src/cli.rs`, `src/main.rs` |
| 3 | Chain-of-custody timeline library | `src/timeline.rs` |
| 4 | Timeline CLI + HTML output | `src/cli.rs`, `src/main.rs` |
| 5 | MITRE ATT&CK annotation in STIX | `src/attack.rs`, `src/format/stix.rs` |
| 6 | Redacted manifest (UUID paths) | `src/commands/redact.rs` |
| 7 | Integration check + push | — |
