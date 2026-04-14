use anyhow::{bail, Result};
use std::path::Path;

/// Returns true if `term` appears as substring in any path or hash field.
/// Prints `FOUND  <path>` for each matching entry.
pub fn contains_manifest(manifest_path: &Path, term: &str) -> Result<bool> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut found = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }
        let hash = parts[1].trim();
        let path = parts[2].trim();
        if hash.contains(term) || path.contains(term) {
            println!("FOUND  {path}");
            found = true;
        }
    }
    Ok(found)
}
