use anyhow::Result;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

const REDACT_NAMESPACE: Uuid = Uuid::from_bytes([
    0xb1, 0xa2, 0xe3, 0x74, 0xc5, 0xb6, 0x47, 0xd8,
    0x99, 0x0a, 0x1b, 0xfc, 0x3d, 0x4e, 0x5f, 0x60,
]);

pub fn redact_manifest(manifest_path: &Path, out_path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers = Vec::new();
    let mut hash_entries: Vec<(String, String, String)> = Vec::new(); // (algo, path, hash)

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            headers.push(line.to_string());
        } else {
            let parts: Vec<&str> = line.splitn(3, "  ").collect();
            if parts.len() == 3 {
                hash_entries.push((
                    parts[0].trim().to_string(),
                    parts[2].trim().to_string(), // path
                    parts[1].trim().to_string(), // hash
                ));
            }
        }
    }

    // Compute Merkle root of original entries: (algo, path, hash)
    let merkle_entries: Vec<(String, String, String)> = hash_entries
        .iter()
        .map(|(algo, path, hash)| (algo.clone(), path.clone(), hash.clone()))
        .collect();
    let root = blazehash::merkle::merkle_root(&merkle_entries).unwrap_or_default();

    let mut out = std::fs::File::create(out_path)?;

    for h in &headers {
        writeln!(out, "{h}")?;
    }
    if !root.is_empty() {
        writeln!(out, "## merkle_root: {root}")?;
    }

    for (algo, original_path, hash) in &hash_entries {
        let uuid = Uuid::new_v5(&REDACT_NAMESPACE, original_path.as_bytes());
        writeln!(out, "{algo}  {hash}  {uuid}")?;
    }

    Ok(())
}
