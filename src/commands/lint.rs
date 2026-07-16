//! Manifest linter: detect duplicate paths, duplicate hashes, malformed lines.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LintReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl LintReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn lint_manifest(manifest_path: &Path) -> Result<LintReport> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut report = LintReport::default();
    let mut seen_paths: HashMap<String, usize> = HashMap::new();
    let mut seen_hashes: HashMap<String, (usize, String)> = HashMap::new();

    for (i, line) in content.lines().enumerate() {
        let lineno = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            report.errors.push(format!(
                "line {lineno}: malformed entry (expected 'algo  hash  path'): {trimmed}"
            ));
            continue;
        }
        let path = parts[2].trim().to_string();
        let hash = parts[1].trim().to_string();

        if let Some(first) = seen_paths.insert(path.clone(), lineno) {
            report.errors.push(format!(
                "line {lineno}: duplicate path '{path}' (first seen at line {first})"
            ));
        }
        if let Some((first_line, first_path)) =
            seen_hashes.insert(hash.clone(), (lineno, path.clone()))
        {
            report.warnings.push(format!(
                "line {lineno}: duplicate hash '{hash}' for '{path}' (also on line {first_line} for '{first_path}') — possible hardlink"
            ));
        }
    }
    Ok(report)
}

pub fn print_report(report: &LintReport) {
    for e in &report.errors {
        eprintln!("ERROR: {e}");
    }
    for w in &report.warnings {
        eprintln!("WARN:  {w}");
    }
    if report.ok() && report.warnings.is_empty() {
        println!("OK");
    }
}
