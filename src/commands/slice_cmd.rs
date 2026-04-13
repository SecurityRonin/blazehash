//! Output a window of entries from a manifest using offset + count.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn slice_manifest(
    manifest_path: &Path,
    offset: usize,
    count: usize,
    out: &mut impl Write,
) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers = Vec::new();
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("##") || trimmed.starts_with("%%") || line.trim().is_empty() {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }
    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for entry in entries.iter().skip(offset).take(count) {
        writeln!(out, "{entry}")?;
    }
    Ok(())
}
