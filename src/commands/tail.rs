//! Output last N entries from a manifest, preserving all header lines.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn tail_manifest(manifest_path: &Path, count: usize, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers = Vec::new();
    let mut entries = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }

    for h in &headers {
        writeln!(out, "{h}")?;
    }

    let start = entries.len().saturating_sub(count);
    for entry in &entries[start..] {
        writeln!(out, "{entry}")?;
    }

    Ok(())
}
