use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn find_missing(
    manifest_path: &Path,
    root: Option<&Path>,
    out: &mut impl Write,
) -> Result<usize> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut missing_count = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }
        let path_str = parts[2].trim();
        let file_path = if let Some(r) = root {
            r.join(path_str)
        } else {
            Path::new(path_str).to_path_buf()
        };

        if !file_path.exists() {
            writeln!(out, "{path_str}")?;
            missing_count += 1;
        }
    }

    Ok(missing_count)
}
