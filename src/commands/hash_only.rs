use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn hash_only_manifest(
    manifest_path: &Path,
    algo_filter: Option<&str>,
    out: &mut impl Write,
) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let filter_upper = algo_filter.map(|a| a.to_uppercase());
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }
        let entry_algo = parts[0].trim();
        let hash = parts[1].trim();
        if let Some(ref required) = filter_upper {
            if entry_algo.to_uppercase() != *required {
                continue;
            }
        }
        writeln!(out, "{hash}")?;
    }
    Ok(())
}
