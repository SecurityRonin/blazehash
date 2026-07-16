//! Output entries whose path appears in both manifests.
//! Hash and algo are taken from the first (left) manifest.

use anyhow::Result;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

pub fn intersect_manifests(
    left_path: &Path,
    right_path: &Path,
    out: &mut impl Write,
) -> Result<usize> {
    let left = std::fs::read_to_string(left_path)?;
    let right = std::fs::read_to_string(right_path)?;

    let right_paths: HashSet<String> = right
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with('%') {
                return None;
            }
            let parts: Vec<&str> = t.splitn(3, "  ").collect();
            if parts.len() == 3 {
                Some(parts[2].trim().to_string())
            } else {
                None
            }
        })
        .collect();

    let mut matched = 0;
    for line in left.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 && right_paths.contains(parts[2].trim()) {
            writeln!(out, "{line}")?;
            matched += 1;
        }
    }
    Ok(matched)
}
