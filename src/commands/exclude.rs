use anyhow::{bail, Result};
use globset::GlobBuilder;
use std::io::Write;
use std::path::Path;

pub fn exclude_manifest(manifest_path: &Path, pattern: &str, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let glob = GlobBuilder::new(pattern)
        .literal_separator(false)
        .build()
        .map_err(|e| anyhow::anyhow!("invalid glob {pattern:?}: {e}"))?
        .compile_matcher();
    let content = std::fs::read_to_string(manifest_path)?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            writeln!(out, "{line}")?;
            continue;
        }
        let path = parts[2].trim();
        if !glob.is_match(path) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}
