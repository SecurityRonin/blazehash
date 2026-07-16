//! Apply a blazehash diff patch to a manifest.
//! Lines starting with `-` (after prefix strip) are removed from the manifest.
//! Lines starting with `+` are added. `---`/`+++` diff headers are skipped.

use anyhow::Result;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

pub fn apply_patch(manifest_path: &Path, patch_path: &Path, out: &mut impl Write) -> Result<()> {
    let manifest = std::fs::read_to_string(manifest_path)?;
    let patch = std::fs::read_to_string(patch_path)?;

    let mut removals: HashSet<String> = HashSet::new();
    let mut additions: Vec<String> = Vec::new();

    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix('-') {
            if rest.starts_with("--") {
                continue;
            } // skip `--- filename` header
            removals.insert(rest.to_string());
        } else if let Some(rest) = line.strip_prefix('+') {
            if rest.starts_with("++") {
                continue;
            } // skip `+++ filename` header
            additions.push(rest.to_string());
        }
    }

    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        if !removals.contains(trimmed) {
            writeln!(out, "{line}")?;
        }
    }

    for addition in &additions {
        writeln!(out, "{addition}")?;
    }
    Ok(())
}
