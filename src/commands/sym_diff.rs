use anyhow::{bail, Result};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

fn parse_entries(manifest_path: &Path) -> Result<Vec<(String, String, String)>> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            entries.push((
                parts[0].trim().to_string(),
                parts[1].trim().to_string(),
                parts[2].trim().to_string(),
            ));
        }
    }
    Ok(entries)
}

pub fn sym_diff_manifests(path_a: &Path, path_b: &Path, out: &mut impl Write) -> Result<()> {
    let a = parse_entries(path_a)?;
    let b = parse_entries(path_b)?;
    let paths_b: HashSet<&str> = b.iter().map(|(_, _, p)| p.as_str()).collect();
    let paths_a: HashSet<&str> = a.iter().map(|(_, _, p)| p.as_str()).collect();
    for (algo, hash, path) in &a {
        if !paths_b.contains(path.as_str()) {
            writeln!(out, "{algo}  {hash}  {path}")?;
        }
    }
    for (algo, hash, path) in &b {
        if !paths_a.contains(path.as_str()) {
            writeln!(out, "{algo}  {hash}  {path}")?;
        }
    }
    Ok(())
}
