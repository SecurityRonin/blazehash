use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn rename_manifest(
    manifest_path: &Path,
    from: &str,
    to: &str,
    out: &mut impl Write,
) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("##") || trimmed.starts_with("%%") {
            writeln!(out, "{line}")?;
            continue;
        }
        if line.trim().is_empty() {
            writeln!(out, "{line}")?;
            continue;
        }
        // Parse: "algo  hash  path" — path is the third whitespace-delimited token
        // Split on exactly two spaces to preserve the format
        let parts: Vec<&str> = line.splitn(3, "  ").collect();
        if parts.len() == 3 {
            let new_path = parts[2].replacen(from, to, 1);
            writeln!(out, "{}  {}  {}", parts[0], parts[1], new_path)?;
        } else {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}
