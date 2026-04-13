//! Output first N entries from a manifest, preserving all header lines.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn head_manifest(manifest_path: &Path, count: usize, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut emitted = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        if emitted < count {
            writeln!(out, "{line}")?;
            emitted += 1;
        }
        if emitted >= count {
            break;
        }
    }
    Ok(())
}
