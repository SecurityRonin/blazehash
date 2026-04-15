use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

fn read_manifest(path: &Path) -> Result<(Vec<String>, Vec<String>)> {
    if !path.exists() {
        bail!("manifest not found: {}", path.display());
    }
    let content = std::fs::read_to_string(path)?;
    let mut headers = Vec::new();
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(trimmed.to_string());
        } else {
            entries.push(line.to_string());
        }
    }
    Ok((headers, entries))
}

pub fn interleave_manifests(path_a: &Path, path_b: &Path, out: &mut impl Write) -> Result<()> {
    let (headers_a, entries_a) = read_manifest(path_a)?;
    let (_, entries_b) = read_manifest(path_b)?;
    for h in &headers_a {
        writeln!(out, "{h}")?;
    }
    let len = entries_a.len().max(entries_b.len());
    for i in 0..len {
        if let Some(e) = entries_a.get(i) {
            writeln!(out, "{e}")?;
        }
        if let Some(e) = entries_b.get(i) {
            writeln!(out, "{e}")?;
        }
    }
    Ok(())
}
