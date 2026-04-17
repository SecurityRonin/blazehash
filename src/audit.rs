use crate::algorithm::Algorithm;
use crate::hash::hash_file;
use crate::manifest::{parse_header, parse_records, ManifestRecord};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct AuditResult {
    pub matched: usize,
    pub changed: usize,
    pub new_files: usize,
    pub moved: usize,
    pub missing: usize,
    pub fuzzy_matched: usize,
    pub details: Vec<AuditStatus>,
}

#[derive(Debug)]
pub enum AuditStatus {
    Matched(PathBuf),
    Changed(PathBuf),
    New(PathBuf),
    Moved {
        path: PathBuf,
        original: PathBuf,
    },
    Missing(PathBuf),
    FuzzyMatch {
        path: PathBuf,
        original: PathBuf,
        similarity: u32,
    },
}

pub fn audit(
    paths: &[PathBuf],
    known_content: &str,
    fuzzy_threshold: u32,
    fuzzy_top: usize,
) -> Result<AuditResult> {
    let known_algos = parse_header(known_content)?;
    let known_entries = parse_records(known_content, &known_algos);

    let known_by_path: HashMap<&Path, &ManifestRecord> = known_entries
        .iter()
        .map(|e| (e.path.as_path(), e))
        .collect();

    // Pre-build ssdeep index for efficient block-size-filtered lookup
    let mut ssdeep_idx = crate::fuzzy::ssdeep::SsdeepIndex::new();
    for entry in &known_entries {
        if let Some(h) = entry.hashes.get(&Algorithm::Ssdeep) {
            ssdeep_idx.insert(h, entry.path.clone());
        }
    }

    let mut result = AuditResult::default();
    let mut seen_known_paths: HashSet<&Path> = HashSet::new();

    for path in paths {
        let file_result = hash_file(path, &known_algos, false, false, false, crate::hash::YaraOpts::no_yara())
            .with_context(|| format!("failed to hash {} during audit", path.display()))?;

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
                let all_match = known_algos
                    .iter()
                    .all(|a| file_result.hashes.get(a) == known.hashes.get(a));
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
                // Try fuzzy matching if fuzzy algorithms are in the manifest
                let fuzzy_algos: Vec<Algorithm> = known_algos
                    .iter()
                    .filter(|a| a.is_fuzzy())
                    .copied()
                    .collect();

                let mut best_fuzzy: Option<(u32, PathBuf)> = None;

                if fuzzy_algos.contains(&Algorithm::Ssdeep) {
                    if let Some(query_hash) = file_result.hashes.get(&Algorithm::Ssdeep) {
                        let candidates = ssdeep_idx.candidates(query_hash);
                        let mut matches: Vec<(u32, PathBuf)> = candidates
                            .iter()
                            .filter_map(|(h, p)| {
                                let sim = crate::fuzzy::ssdeep::similarity(query_hash, h);
                                if sim >= fuzzy_threshold {
                                    Some((sim, p.clone()))
                                } else {
                                    None
                                }
                            })
                            .collect();
                        matches.sort_by(|a, b| b.0.cmp(&a.0));
                        matches.truncate(fuzzy_top);
                        if let Some((sim, orig)) = matches.into_iter().next() {
                            if best_fuzzy.as_ref().is_none_or(|(s, _)| sim > *s) {
                                best_fuzzy = Some((sim, orig));
                            }
                        }
                    }
                }

                if fuzzy_algos.contains(&Algorithm::Tlsh) {
                    if let Some(query_hash) = file_result.hashes.get(&Algorithm::Tlsh) {
                        if !query_hash.is_empty() {
                            let mut matches: Vec<(u32, PathBuf)> = known_entries
                                .iter()
                                .filter_map(|entry| {
                                    let h = entry.hashes.get(&Algorithm::Tlsh)?;
                                    if h.is_empty() {
                                        return None;
                                    }
                                    let sim = crate::fuzzy::tlsh::similarity(query_hash, h);
                                    if sim >= fuzzy_threshold {
                                        Some((sim, entry.path.clone()))
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            matches.sort_by(|a, b| b.0.cmp(&a.0));
                            matches.truncate(fuzzy_top);
                            if let Some((sim, orig)) = matches.into_iter().next() {
                                if best_fuzzy.as_ref().is_none_or(|(s, _)| sim > *s) {
                                    best_fuzzy = Some((sim, orig));
                                }
                            }
                        }
                    }
                }

                if let Some((sim, orig)) = best_fuzzy {
                    result.fuzzy_matched += 1;
                    result.details.push(AuditStatus::FuzzyMatch {
                        path: path.clone(),
                        original: orig,
                        similarity: sim,
                    });
                } else {
                    result.new_files += 1;
                    result.details.push(AuditStatus::New(path.clone()));
                }
            }
        }
    }

    // Report files in manifest but not found in provided paths
    for known in &known_entries {
        if !seen_known_paths.contains(known.path.as_path()) {
            result.missing += 1;
            result
                .details
                .push(AuditStatus::Missing(known.path.clone()));
        }
    }

    Ok(result)
}
