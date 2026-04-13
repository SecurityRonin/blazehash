//! Export a blazehash manifest to structured formats: CSV, JSONL, TSV.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn export_manifest(manifest_path: &Path, format: &str, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    match format.to_ascii_lowercase().as_str() {
        "csv"   => export_delimited(&content, ',', out),
        "tsv"   => export_delimited(&content, '\t', out),
        "jsonl" => export_jsonl(&content, out),
        other   => bail!("unknown export format '{other}'; supported: csv, tsv, jsonl"),
    }
}

fn export_delimited(content: &str, sep: char, out: &mut impl Write) -> Result<()> {
    writeln!(out, "algo{sep}hash{sep}path")?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            let algo = parts[0].trim();
            let hash = parts[1].trim();
            let path = parts[2].trim();
            let path_cell = if path.contains(sep) || path.contains('"') {
                format!("\"{}\"", path.replace('"', "\"\""))
            } else {
                path.to_string()
            };
            writeln!(out, "{algo}{sep}{hash}{sep}{path_cell}")?;
        }
    }
    Ok(())
}

fn export_jsonl(content: &str, out: &mut impl Write) -> Result<()> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            let obj = serde_json::json!({
                "algo": parts[0].trim(),
                "hash": parts[1].trim(),
                "path": parts[2].trim(),
            });
            writeln!(out, "{}", serde_json::to_string(&obj)?)?;
        }
    }
    Ok(())
}
