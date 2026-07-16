//! Selective disclosure proofs and zero-knowledge membership proofs over Merkle manifests.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosedEntry {
    pub path: String,
    pub sha256: String,
    pub proof_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveProof {
    pub root: String,
    pub tree_size: usize,
    pub disclosed: Vec<DisclosedEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipProof {
    pub root: String,
    pub tree_size: usize,
    pub blinded_leaf: String,
    pub proof_path: Vec<String>,
    pub nonce: String,
    pub path_commitment: String,
}

// ── Internal hashing helpers ─────────────────────────────────────────────────

fn leaf_hash_hex(path: &str, sha256_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(path.as_bytes());
    h.update([0x00]);
    h.update(sha256_hex.as_bytes());
    hex::encode(h.finalize())
}

fn node_hash_hex(a: &str, b: &str) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update([0x01]);
    // Safety: lo and hi are always hex strings produced by leaf_hash() or node_hash() — never externally sourced
    h.update(hex::decode(lo).unwrap_or_default());
    h.update(hex::decode(hi).unwrap_or_default());
    hex::encode(h.finalize())
}

// ── Tree building ─────────────────────────────────────────────────────────────

/// Build tree levels from a pre-sorted list of leaf hashes (hex strings).
/// Level 0 = leaves, last level = [root].
fn build_tree_levels(leaves: &[String]) -> Vec<Vec<String>> {
    let mut levels: Vec<Vec<String>> = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let next: Vec<String> = prev
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    node_hash_hex(&chunk[0], &chunk[1])
                } else {
                    // Odd leaf: pair with itself (matches merkle.rs behaviour)
                    node_hash_hex(&chunk[0], &chunk[0])
                }
            })
            .collect();
        levels.push(next);
    }
    levels
}

/// Extract the sibling proof path for a leaf at `leaf_idx`.
fn merkle_proof_path(levels: &[Vec<String>], leaf_idx: usize) -> Vec<String> {
    let mut path = Vec::new();
    let mut idx = leaf_idx;
    for level in &levels[..levels.len() - 1] {
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        let sibling = if sibling_idx < level.len() {
            level[sibling_idx].clone()
        } else {
            // Odd leaf: pair with itself (matches merkle.rs behaviour)
            level[idx].clone()
        };
        path.push(sibling);
        idx /= 2;
    }
    path
}

/// Walk the proof path from a leaf hash back to the root.
fn verify_proof_path(leaf_hash_hex: &str, proof_path: &[String], root: &str) -> bool {
    let mut current = leaf_hash_hex.to_string();
    for sibling in proof_path {
        // Validate sibling is valid hex before hashing
        if hex::decode(sibling).is_err() {
            return false;
        }
        current = node_hash_hex(&current, sibling);
    }
    current == root
}

// ── Nonce generation ─────────────────────────────────────────────────────────

fn rand_nonce() -> [u8; 16] {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

// ── Helper: build sorted leaf set matching merkle.rs exactly ─────────────────

/// Returns (path, hash) pairs sorted by their leaf hash — exactly as merkle.rs does.
/// Uses ALL entries regardless of algorithm, matching `merkle.rs::build_levels`.
fn sorted_sha256_entries(entries: &[(String, String, String)]) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String, String)> = entries
        .iter()
        .map(|(_, path, hash)| {
            let lh = leaf_hash_hex(path, hash);
            (lh, path.clone(), hash.clone())
        })
        .collect();
    // Sort by leaf hash (matches merkle.rs build_levels sort_by_key)
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
        .into_iter()
        .map(|(_, path, hash)| (path, hash))
        .collect()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate a selective disclosure proof for `disclosed_paths`.
/// The proof root equals `merkle_root(entries)` exactly.
pub fn generate_selective_proof(
    entries: &[(String, String, String)],
    disclosed_paths: &[&str],
) -> Result<SelectiveProof> {
    if entries.is_empty() {
        bail!("empty manifest");
    }

    let sorted = sorted_sha256_entries(entries);

    let leaves: Vec<String> = sorted
        .iter()
        .map(|(path, hash)| leaf_hash_hex(path, hash))
        .collect();

    let levels = build_tree_levels(&leaves);
    let root = levels.last().unwrap()[0].clone();
    let tree_size = sorted.len();

    let mut disclosed = Vec::new();
    for &target_path in disclosed_paths {
        let pos = sorted
            .iter()
            .position(|(p, _)| p == target_path)
            .ok_or_else(|| anyhow::anyhow!("path not found in manifest: {target_path}"))?;

        let (_, hash) = &sorted[pos];
        let proof_path = merkle_proof_path(&levels, pos);

        disclosed.push(DisclosedEntry {
            path: target_path.to_string(),
            sha256: hash.clone(),
            proof_path,
        });
    }

    Ok(SelectiveProof {
        root,
        tree_size,
        disclosed,
    })
}

/// Verify a selective disclosure proof.
/// Each disclosed entry must independently verify against the proof root.
pub fn verify_selective_proof(proof: &SelectiveProof) -> Result<bool> {
    for entry in &proof.disclosed {
        let lh = leaf_hash_hex(&entry.path, &entry.sha256);
        if !verify_proof_path(&lh, &entry.proof_path, &proof.root) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Prove that `target_sha256` exists somewhere in the manifest without revealing which file.
pub fn prove_hash_membership(
    entries: &[(String, String, String)],
    target_sha256: &str,
) -> Result<MembershipProof> {
    if entries.is_empty() {
        bail!("empty manifest");
    }

    let sorted = sorted_sha256_entries(entries);

    // Find the position of the target hash
    let pos = sorted
        .iter()
        .position(|(_, hash)| hash == target_sha256)
        .ok_or_else(|| anyhow::anyhow!("target hash not found in manifest"))?;

    let path = &sorted[pos].0;

    // Generate nonce and path commitment
    let nonce_bytes = rand_nonce();
    let nonce_hex = hex::encode(nonce_bytes);

    let mut h = Sha256::new();
    h.update(path.as_bytes());
    h.update(nonce_hex.as_bytes());
    let path_commitment = hex::encode(h.finalize());

    // Compute blinded leaf
    let mut h2 = Sha256::new();
    h2.update([0x00]);
    h2.update(path_commitment.as_bytes());
    h2.update([0x00]);
    h2.update(target_sha256.as_bytes());
    let blinded_leaf = hex::encode(h2.finalize());

    // Build tree with the blinded leaf substituted at pos
    let mut leaves: Vec<String> = sorted
        .iter()
        .map(|(p, hash)| leaf_hash_hex(p, hash))
        .collect();
    leaves[pos] = blinded_leaf.clone();

    let levels = build_tree_levels(&leaves);
    let blinded_root = levels.last().unwrap()[0].clone();
    let tree_size = sorted.len();

    let proof_path = merkle_proof_path(&levels, pos);

    Ok(MembershipProof {
        root: blinded_root,
        tree_size,
        blinded_leaf,
        proof_path,
        nonce: nonce_hex,
        path_commitment,
    })
}

/// Verify a membership proof for `target_sha256`.
pub fn verify_membership_proof(proof: &MembershipProof, target_sha256: &str) -> Result<bool> {
    // Recompute blinded leaf from path_commitment + target_sha256
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(proof.path_commitment.as_bytes());
    h.update([0x00]);
    h.update(target_sha256.as_bytes());
    let expected_blinded_leaf = hex::encode(h.finalize());

    if expected_blinded_leaf != proof.blinded_leaf {
        return Ok(false);
    }

    Ok(verify_proof_path(
        &proof.blinded_leaf,
        &proof.proof_path,
        &proof.root,
    ))
}
