use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub struct NormalizeOpts<'a> {
    pub strip_prefix: Option<&'a str>,
    pub add_prefix: Option<&'a str>,
}

pub fn normalize_manifest<W: Write>(
    manifest_path: &Path,
    opts: &NormalizeOpts<'_>,
    out: &mut W,
) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            writeln!(out, "{line}")?;
            continue;
        }
        let algo = parts[0];
        let hash = parts[1];
        let mut path = parts[2].trim().to_string();

        if let Some(prefix) = opts.strip_prefix {
            if path.starts_with(prefix) {
                path = path[prefix.len()..].to_string();
            }
        }
        if let Some(prefix) = opts.add_prefix {
            path = format!("{prefix}{path}");
        }

        writeln!(out, "{algo}  {hash}  {path}")?;
    }
    Ok(())
}
