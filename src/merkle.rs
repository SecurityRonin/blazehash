//! Merkle tree over a file manifest.
//!
//! Leaf hash:  SHA256(0x00 || path_bytes || 0x00 || sha256_hex_bytes)
//! Node hash:  SHA256(0x01 || min(left, right) || max(left, right))
//!
//! The min/max canonical ordering makes the root order-independent.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

/// A single sibling hash in a Merkle proof (32 bytes).
pub type ProofStep = [u8; 32];

/// Internal tree representation: levels of 32-byte hashes, plus a sorted leaf index.
type TreeLevels = (Vec<Vec<[u8; 32]>>, Vec<([u8; 32], usize)>);

/// Compute the leaf hash for (path, sha256_hex).
fn leaf_hash(path: &str, sha256_hex: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(path.as_bytes());
    h.update([0x00]);
    h.update(sha256_hex.as_bytes());
    h.finalize().into()
}

/// Compute the node hash from two child hashes (canonical ordering).
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(lo.as_slice());
    h.update(hi.as_slice());
    h.finalize().into()
}

/// Build the tree as a Vec of levels, bottom-up.
/// Level 0 = leaves (sorted by leaf_hash for canonical ordering).
/// Returns: (levels, sorted leaf hashes with original index)
fn build_levels(entries: &[(String, String, String)]) -> TreeLevels {
    // Compute leaf hashes and keep original index
    let mut leaves: Vec<([u8; 32], usize)> = entries
        .iter()
        .enumerate()
        .map(|(i, (_, path, hash))| (leaf_hash(path, hash), i))
        .collect();
    // Sort by leaf hash for canonical ordering
    leaves.sort_by_key(|(h, _)| *h);

    let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|(h, _)| *h).collect();

    let mut levels: Vec<Vec<[u8; 32]>> = vec![leaf_hashes];

    loop {
        let current = levels.last().unwrap();
        if current.len() == 1 {
            break;
        }

        let mut next = Vec::new();
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                next.push(node_hash(&current[i], &current[i + 1]));
                i += 2;
            } else {
                // Odd node: duplicate it
                next.push(node_hash(&current[i], &current[i]));
                i += 1;
            }
        }
        levels.push(next);
    }

    (levels, leaves)
}

/// Compute the Merkle root for a list of (algorithm, path, sha256_hex) entries.
/// Returns the root as a lowercase hex string.
pub fn merkle_root(entries: &[(String, String, String)]) -> Result<String> {
    if entries.is_empty() {
        bail!("cannot compute Merkle root of empty manifest");
    }
    let (levels, _) = build_levels(entries);
    let root = levels.last().unwrap()[0];
    Ok(hex::encode(root))
}

/// Generate an inclusion proof for a file at `path`.
/// Returns a Vec of sibling hashes (hex-encoded) from leaf to root.
pub fn generate_proof(entries: &[(String, String, String)], path: &str) -> Result<Vec<String>> {
    if entries.is_empty() {
        bail!("empty manifest");
    }

    let (levels, sorted_leaves) = build_levels(entries);

    // Find the canonical position of this path
    let entry = entries
        .iter()
        .find(|(_, p, _)| p == path)
        .ok_or_else(|| anyhow::anyhow!("path not found in manifest: {path}"))?;
    let target_leaf = leaf_hash(path, &entry.2);

    let pos = sorted_leaves
        .iter()
        .position(|(h, _)| *h == target_leaf)
        .ok_or_else(|| anyhow::anyhow!("leaf not found after sort (impossible)"))?;

    if levels[0].len() == 1 {
        // Single entry: empty proof
        return Ok(vec![]);
    }

    let mut proof = Vec::new();
    let mut current_pos = pos;

    for level in &levels[..levels.len() - 1] {
        let sibling_pos = if current_pos % 2 == 0 {
            // even: sibling is current_pos + 1 (or self if last)
            if current_pos + 1 < level.len() {
                current_pos + 1
            } else {
                current_pos
            }
        } else {
            current_pos - 1
        };
        proof.push(hex::encode(level[sibling_pos]));
        current_pos /= 2;
    }

    Ok(proof)
}

/// Verify a Merkle inclusion proof.
/// `proof` is a slice of hex-encoded sibling hashes from leaf to root.
pub fn verify_proof(
    root_hex: &str,
    path: &str,
    sha256_hex: &str,
    proof: &[String],
) -> Result<bool> {
    let mut current = leaf_hash(path, sha256_hex);

    for sibling_hex in proof {
        let sibling_bytes = hex::decode(sibling_hex)
            .map_err(|_| anyhow::anyhow!("invalid hex in proof"))?;
        if sibling_bytes.len() != 32 {
            bail!("proof step must be 32 bytes");
        }
        let sibling: [u8; 32] = sibling_bytes.try_into().unwrap();
        current = node_hash(&current, &sibling);
    }

    let computed = hex::encode(current);
    Ok(computed == root_hex)
}

/// Convenience: build tree returning root + leaf count.
pub fn build_tree(entries: &[(String, String, String)]) -> Result<(String, usize)> {
    let root = merkle_root(entries)?;
    Ok((root, entries.len()))
}
