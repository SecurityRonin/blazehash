//! Universal manifest loader with format auto-detection.
//!
//! Supports:
//! - hashdeep format (`%%%% HASHDEEP-1.0` or `%%%% BLAZEHASH-1.0`)
//! - JSON array (`[...]`)
//! - JSONL (`{...}` per line)
//! - CSV with hash-column headers

use crate::algorithm::Algorithm;
use crate::manifest::{parse_records, ManifestRecord};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// File extensions considered candidate manifests when scanning directories.
const MANIFEST_EXTENSIONS: &[&str] = &["hash", "hashdeep", "csv", "json", "jsonl"];

/// Returns `true` if the first 256 bytes of a file look like a blazehash/hashdeep manifest.
/// Accepts both `%%%% HASHDEEP-1.0` and `%%%% BLAZEHASH-1.0` magic prefixes, as well as
/// JSON arrays/objects and CSV files with hash-column headers.
pub fn looks_like_manifest(path: &Path) -> bool {
    let mut buf = [0u8; 256];
    let n = fs::File::open(path)
        .and_then(|mut f| f.read(&mut buf))
        .unwrap_or(0);
    let snippet = std::str::from_utf8(&buf[..n]).unwrap_or("");
    sniff_format(snippet) != ManifestFormat::Unknown
}

#[derive(Debug, PartialEq)]
enum ManifestFormat {
    /// `%%%% HASHDEEP-1.0` or `%%%% BLAZEHASH-1.0`
    Hashdeep,
    /// JSON array `[...]`
    JsonArray,
    /// JSONL `{...}` per line
    Jsonl,
    /// CSV with hash-column headers
    Csv,
    Unknown,
}

fn sniff_format(snippet: &str) -> ManifestFormat {
    let trimmed = snippet.trim_start();
    if trimmed.starts_with("%%%%") {
        return ManifestFormat::Hashdeep;
    }
    if trimmed.starts_with('[') {
        return ManifestFormat::JsonArray;
    }
    if trimmed.starts_with('{') {
        return ManifestFormat::Jsonl;
    }
    // CSV heuristic: first line contains a hash-related header keyword
    if let Some(first_line) = trimmed.lines().next() {
        let lower = first_line.to_lowercase();
        if lower.contains("hash")
            || lower.contains("blake3")
            || lower.contains("md5")
            || lower.contains("sha")
            || lower.contains("filename")
        {
            return ManifestFormat::Csv;
        }
    }
    ManifestFormat::Unknown
}

/// Parse a hashdeep/blazehash format header that accepts BOTH `HASHDEEP-1.0` and
/// `BLAZEHASH-1.0` magic lines.  Returns the ordered list of algorithms.
fn parse_header_universal(content: &str) -> Result<Vec<crate::algorithm::Algorithm>> {
    use std::str::FromStr;
    let mut lines = content.lines();

    let first = lines.next().unwrap_or("");
    // Accept either magic
    if !first.starts_with("%%%% HASHDEEP") && !first.starts_with("%%%% BLAZEHASH") {
        bail!(
            "not a hashdeep/blazehash file: missing header (got {:?})",
            first.chars().take(40).collect::<String>()
        );
    }

    let second = lines.next().unwrap_or("");
    if !second.starts_with("%%%% size,") {
        bail!(
            "not a hashdeep/blazehash file: missing column line (got {:?})",
            second.chars().take(40).collect::<String>()
        );
    }

    let cols = &second["%%%% size,".len()..];
    let parts: Vec<&str> = cols.split(',').collect();

    if parts.is_empty() || parts.last() != Some(&"filename") {
        bail!(
            "not a hashdeep/blazehash file: missing filename column (got {:?})",
            second.chars().take(60).collect::<String>()
        );
    }

    let algo_names = &parts[..parts.len() - 1];
    let mut algorithms = Vec::new();
    for name in algo_names {
        algorithms.push(crate::algorithm::Algorithm::from_str(name)?);
    }

    Ok(algorithms)
}

/// Load a manifest from `path`, auto-detecting the format.
///
/// Currently fully implements hashdeep/blazehash format loading.
/// JSON and CSV formats return an empty record list (stubs for future expansion).
pub fn load_manifest(path: &Path) -> Result<Vec<ManifestRecord>> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read manifest {}: {e}", path.display()))?;

    match sniff_format(&content) {
        ManifestFormat::Hashdeep => {
            let algorithms = parse_header_universal(&content)?;
            Ok(parse_records(&content, &algorithms))
        }
        ManifestFormat::JsonArray => parse_json_array(&content),
        ManifestFormat::Jsonl => parse_jsonl(&content),
        ManifestFormat::Csv => parse_csv(&content),
        ManifestFormat::Unknown => {
            bail!(
                "unrecognised manifest format in {}",
                path.display()
            );
        }
    }
}

/// Convert a string algorithm name to an `Algorithm` variant, or `None` if unrecognised.
fn parse_algorithm_name(name: &str) -> Option<Algorithm> {
    Algorithm::from_str(name).ok()
}

#[derive(serde::Deserialize)]
struct JsonRecord {
    filename: String,
    size: u64,
    hashes: HashMap<String, String>,
}

fn json_record_to_manifest(r: JsonRecord) -> ManifestRecord {
    ManifestRecord {
        path: PathBuf::from(&r.filename),
        size: r.size,
        hashes: r
            .hashes
            .into_iter()
            .filter_map(|(k, v)| parse_algorithm_name(&k).map(|alg| (alg, v)))
            .collect(),
    }
}

fn parse_json_array(content: &str) -> Result<Vec<ManifestRecord>> {
    let records: Vec<JsonRecord> =
        serde_json::from_str(content).context("invalid JSON manifest")?;
    Ok(records.into_iter().map(json_record_to_manifest).collect())
}

fn parse_jsonl(content: &str) -> Result<Vec<ManifestRecord>> {
    let mut records = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let r: JsonRecord = serde_json::from_str(line).context("invalid JSONL line")?;
        records.push(json_record_to_manifest(r));
    }
    Ok(records)
}

fn parse_csv(content: &str) -> Result<Vec<ManifestRecord>> {
    let mut lines = content.lines();
    let header = lines.next().ok_or_else(|| anyhow::anyhow!("empty CSV"))?;
    let cols: Vec<&str> = header.split(',').collect();

    let size_col = cols
        .iter()
        .position(|&c| c == "size")
        .ok_or_else(|| anyhow::anyhow!("CSV missing 'size' column"))?;
    let filename_col = cols
        .iter()
        .position(|&c| c == "filename")
        .ok_or_else(|| anyhow::anyhow!("CSV missing 'filename' column"))?;

    let algo_cols: Vec<(usize, Algorithm)> = cols
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != size_col && i != filename_col)
        .filter_map(|(i, name)| parse_algorithm_name(name).map(|alg| (i, alg)))
        .collect();

    let mut records = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < cols.len() {
            continue;
        }
        let size: u64 = fields[size_col].parse().context("CSV invalid size")?;
        let path = PathBuf::from(fields[filename_col]);
        let hashes: HashMap<Algorithm, String> = algo_cols
            .iter()
            .map(|&(i, alg)| (alg, fields[i].to_string()))
            .collect();
        records.push(ManifestRecord { path, size, hashes });
    }
    Ok(records)
}

/// Scan `search_dirs` for manifest files (by extension + content sniff).
///
/// Returns the single manifest path found, or an error if 0 or 2+ candidates exist.
pub fn find_manifest(search_dirs: &[&Path]) -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    for dir in search_dirs {
        let read_dir = fs::read_dir(dir)
            .map_err(|e| anyhow::anyhow!("cannot read directory {}: {e}", dir.display()))?;

        for entry in read_dir.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if MANIFEST_EXTENSIONS.contains(&ext.as_str()) && looks_like_manifest(&path) {
                candidates.push(path);
            }
        }
    }

    match candidates.len() {
        0 => bail!("no manifest file found in the specified directories"),
        1 => Ok(candidates.remove(0)),
        n => bail!(
            "ambiguous: found {n} manifest candidates — specify one with -k: {}",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}
