use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn annotate_manifest(manifest_path: &Path, note: &str, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<String> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    let mut has_note = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            if trimmed.starts_with("## note:") || trimmed.starts_with("##note:") {
                headers.push(format!("## note: {note}"));
                has_note = true;
            } else {
                headers.push(trimmed.to_string());
            }
        } else {
            entries.push(line.to_string());
        }
    }
    if !has_note {
        headers.push(format!("## note: {note}"));
    }
    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for e in &entries {
        writeln!(out, "{e}")?;
    }
    Ok(())
}
