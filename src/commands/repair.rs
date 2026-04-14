use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn repair_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{trimmed}")?;
            continue;
        }
        if let Some(normalized) = normalize_data_line(trimmed) {
            writeln!(out, "{normalized}")?;
        }
    }
    Ok(())
}

fn normalize_data_line(line: &str) -> Option<String> {
    // Find first run of 2+ spaces
    let first = line.find("  ")?;
    let algo = line[..first].trim();
    let rest = line[first..].trim_start();
    // Find next run of 2+ spaces in remainder
    let second = rest.find("  ")?;
    let hash = rest[..second].trim();
    let path = rest[second..].trim_start();
    if algo.is_empty() || hash.is_empty() || path.is_empty() {
        return None;
    }
    Some(format!("{algo}  {hash}  {path}"))
}
