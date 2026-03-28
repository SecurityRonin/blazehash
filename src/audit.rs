use crate::algorithm::Algorithm;
use crate::hash::hash_file;
use crate::manifest::parse_header;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct AuditResult {
    pub matched: usize,
    pub changed: usize,
    pub new_files: usize,
    pub moved: usize,
    pub missing: usize,
    pub details: Vec<AuditStatus>,
}

#[derive(Debug)]
pub enum AuditStatus {
    Matched(PathBuf),
    Changed(PathBuf),
    New(PathBuf),
    Moved { path: PathBuf, original: PathBuf },
    Missing(PathBuf),
}

struct KnownEntry {
    size: u64,
    hashes: HashMap<Algorithm, String>,
    path: PathBuf,
}

pub fn audit(
    paths: &[PathBuf],
    known_content: &str,
) -> Result<AuditResult> {
    let known_algos = parse_header(known_content)?;
    let known_entries = parse_known_entries(known_content, &known_algos)?;

    let known_by_path: HashMap<&Path, &KnownEntry> = known_entries
        .iter()
        .map(|e| (e.path.as_path(), e))
        .collect();

    let mut result = AuditResult::default();
    let mut seen_known_paths: HashSet<&Path> = HashSet::new();

    for path in paths {
        let file_result = hash_file(path, &known_algos)?;

        if let Some(known) = known_by_path.get(path.as_path()) {
            seen_known_paths.insert(path.as_path());
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
            // Check if file moved (same hashes for ALL algorithms, different path)
            let mut found_move = false;
            for known in &known_entries {
                if known.size != file_result.size {
                    continue;
                }
                let all_match = known_algos.iter().all(|a| {
                    file_result.hashes.get(a) == known.hashes.get(a)
                });
                if all_match {
                    result.moved += 1;
                    result.details.push(AuditStatus::Moved {
                        path: path.clone(),
                        original: known.path.clone(),
                    });
                    seen_known_paths.insert(known.path.as_path());
                    found_move = true;
                    break;
                }
            }

            if !found_move {
                result.new_files += 1;
                result.details.push(AuditStatus::New(path.clone()));
            }
        }
    }

    // Report files in manifest but not found in provided paths
    for known in &known_entries {
        if !seen_known_paths.contains(known.path.as_path()) {
            result.missing += 1;
            result.details.push(AuditStatus::Missing(known.path.clone()));
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

        let size: u64 = match parts[0].parse() {
            Ok(s) => s,
            Err(_) => continue,
        };
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
