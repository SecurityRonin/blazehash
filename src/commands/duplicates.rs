use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

pub fn duplicates_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }
        let hash = parts[1].trim().to_string();
        groups.entry(hash).or_default().push(trimmed.to_string());
    }
    let mut dup_lines: Vec<String> = groups
        .into_values()
        .filter(|v| v.len() > 1)
        .flatten()
        .collect();
    dup_lines.sort();
    for line in dup_lines {
        writeln!(out, "{line}")?;
    }
    Ok(())
}
