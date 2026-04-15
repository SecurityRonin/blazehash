use anyhow::{bail, Result};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

pub fn unique_hash_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut seen: HashSet<String> = HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{trimmed}")?;
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            writeln!(out, "{line}")?;
            continue;
        }
        let hash = parts[1].trim().to_string();
        if seen.insert(hash) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}
