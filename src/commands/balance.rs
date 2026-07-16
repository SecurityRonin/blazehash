use anyhow::{bail, Result};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn balance_manifest(
    manifest_path: &Path,
    parts: usize,
    out_dir: Option<&Path>,
) -> Result<Vec<std::path::PathBuf>> {
    if parts == 0 {
        bail!("--parts must be >= 1");
    }
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<String> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
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
    let stem = manifest_path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let dir = out_dir.unwrap_or_else(|| manifest_path.parent().unwrap_or(Path::new(".")));
    let total = entries.len();
    let base_size = total.checked_div(parts).unwrap_or(0);
    let extras = total % parts;
    let mut offset = 0;
    let mut out_paths = Vec::new();
    for i in 0..parts {
        let chunk_size = base_size + if i < extras { 1 } else { 0 };
        let part_path = dir.join(format!("{stem}_part{:03}.hash", i + 1));
        let mut f = File::create(&part_path)?;
        for h in &headers {
            writeln!(f, "{h}")?;
        }
        for e in &entries[offset..offset + chunk_size] {
            writeln!(f, "{e}")?;
        }
        offset += chunk_size;
        out_paths.push(part_path);
    }
    Ok(out_paths)
}
