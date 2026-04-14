use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

pub fn tally_manifest(manifest_path: &Path, key: &str, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut counts: HashMap<String, u64> = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }
        let algo = parts[0].trim();
        let path = parts[2].trim();
        let bucket = match key {
            "algo" => algo.to_string(),
            "dir" => {
                std::path::Path::new(path)
                    .parent()
                    .map(|d| d.to_string_lossy().into_owned())
                    .unwrap_or_else(|| ".".to_string())
            }
            _ => {
                match std::path::Path::new(path).extension().and_then(|e| e.to_str()) {
                    Some(ext) => format!(".{ext}"),
                    None => "(none)".to_string(),
                }
            }
        };
        *counts.entry(bucket).or_insert(0) += 1;
    }
    let mut pairs: Vec<(u64, String)> = counts.into_iter().map(|(k, v)| (v, k)).collect();
    pairs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (count, bucket) in pairs {
        writeln!(out, "{count}\t{bucket}")?;
    }
    Ok(())
}
