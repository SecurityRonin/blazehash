use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestInfo {
    pub path: String,
    pub headers: HashMap<String, String>,
    pub entries: usize,
    pub algorithms: HashMap<String, usize>,
    pub unique_paths: usize,
}

pub fn parse_info(manifest_path: &Path) -> Result<ManifestInfo> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut entries = 0usize;
    let mut algorithms: HashMap<String, usize> = HashMap::new();
    let mut paths: std::collections::HashSet<String> = Default::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("##") {
            let rest = rest.trim();
            if let Some((k, v)) = rest.split_once(':') {
                headers.insert(k.trim().to_string(), v.trim().to_string());
            }
            continue;
        }
        if trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            entries += 1;
            *algorithms
                .entry(parts[0].trim().to_lowercase())
                .or_insert(0) += 1;
            paths.insert(parts[2].trim().to_string());
        }
    }

    Ok(ManifestInfo {
        path: manifest_path.display().to_string(),
        headers,
        entries,
        algorithms,
        unique_paths: paths.len(),
    })
}

pub fn run_info(manifest_path: &Path, json: bool, out: &mut impl Write) -> Result<()> {
    let info = parse_info(manifest_path)?;
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&info)?)?;
        return Ok(());
    }
    writeln!(out, "Path:     {}", info.path)?;
    writeln!(out, "Entries:  {}", info.entries)?;
    writeln!(out, "Unique:   {}", info.unique_paths)?;
    if !info.headers.is_empty() {
        writeln!(out, "\nHeaders:")?;
        let mut kvs: Vec<_> = info.headers.iter().collect();
        kvs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in kvs {
            writeln!(out, "  {k:<16} {v}")?;
        }
    }
    if !info.algorithms.is_empty() {
        writeln!(out, "\nAlgorithms:")?;
        let mut algos: Vec<_> = info.algorithms.iter().collect();
        algos.sort_by_key(|(k, _)| k.as_str());
        for (algo, count) in algos {
            writeln!(out, "  {algo:<12} {count}")?;
        }
    }
    Ok(())
}
