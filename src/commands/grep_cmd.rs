use anyhow::{bail, Result};
use regex::RegexBuilder;
use std::io::Write;
use std::path::Path;

pub fn grep_manifest(
    manifest_path: &Path,
    pattern: &str,
    ignore_case: bool,
    out: &mut impl Write,
) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let re = RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .map_err(|e| anyhow::anyhow!("invalid pattern {pattern:?}: {e}"))?;

    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers = Vec::new();
    let mut entries = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("##") || trimmed.starts_with("%%") || line.trim().is_empty() {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }

    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for entry in &entries {
        // entry format: "algo  hash  path"
        if re.is_match(entry) {
            writeln!(out, "{entry}")?;
        }
    }
    Ok(())
}
