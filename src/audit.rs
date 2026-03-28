use crate::algorithm::Algorithm;
use crate::hash::hash_file;
use crate::manifest::parse_header;
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct AuditResult {
    pub matched: usize,
    pub changed: usize,
    pub new_files: usize,
    pub moved: usize,
    pub details: Vec<AuditStatus>,
}

#[derive(Debug)]
pub enum AuditStatus {
    Matched(PathBuf),
    Changed(PathBuf),
    New(PathBuf),
    Moved { path: PathBuf, original: PathBuf },
}

struct KnownEntry {
    size: u64,
    hashes: HashMap<Algorithm, String>,
    path: PathBuf,
}

pub fn audit(
    paths: &[PathBuf],
    known_content: &str,
    _algorithms: &[Algorithm],
    _recursive: bool,
) -> Result<AuditResult> {
    let known_algos = parse_header(known_content)?;
    let known_entries = parse_known_entries(known_content, &known_algos)?;

    let known_by_path: HashMap<&Path, &KnownEntry> = known_entries
        .iter()
        .map(|e| (e.path.as_path(), e))
        .collect();

    let known_by_hash: HashMap<&str, &KnownEntry> = known_entries
        .iter()
        .filter_map(|e| {
            known_algos
                .first()
                .and_then(|a| e.hashes.get(a))
                .map(|h| (h.as_str(), e))
        })
        .collect();

    let mut result = AuditResult::default();

    for path in paths {
        let file_result = hash_file(path, &known_algos)?;

        if let Some(known) = known_by_path.get(path.as_path()) {
            let hashes_match = known_algos
                .iter()
                .all(|a| file_result.hashes.get(a) == known.hashes.get(a));

            if hashes_match && file_result.size == known.size {
                result.matched += 1;
                result.details.push(AuditStatus::Matched(path.clone()));
            } else {
                result.changed += 1;
                result.details.push(AuditStatus::Changed(path.clone()));
            }
        } else {
            let first_hash = known_algos
                .first()
                .and_then(|a| file_result.hashes.get(a));

            if let Some(hash) = first_hash {
                if let Some(original) = known_by_hash.get(hash.as_str()) {
                    result.moved += 1;
                    result.details.push(AuditStatus::Moved {
                        path: path.clone(),
                        original: original.path.clone(),
                    });
                    continue;
                }
            }

            result.new_files += 1;
            result.details.push(AuditStatus::New(path.clone()));
        }
    }

    Ok(result)
}

fn parse_known_entries(content: &str, algorithms: &[Algorithm]) -> Result<Vec<KnownEntry>> {
    let mut entries = Vec::new();

    for line in content.lines() {
        if line.starts_with("%%%%") || line.starts_with('#') || line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(algorithms.len() + 2, ',').collect();
        if parts.len() < algorithms.len() + 2 {
            continue;
        }

        let size: u64 = parts[0].parse()?;
        let mut hashes = HashMap::new();
        for (i, algo) in algorithms.iter().enumerate() {
            hashes.insert(*algo, parts[i + 1].to_string());
        }
        let path = PathBuf::from(parts[algorithms.len() + 1]);

        entries.push(KnownEntry {
            size,
            hashes,
            path,
        });
    }

    Ok(entries)
}
