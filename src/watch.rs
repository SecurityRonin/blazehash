use crate::algorithm::Algorithm;
use crate::hash::hash_file;
use crate::manifest::ManifestRecord;
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum ChangeStatus {
    New,
    Modified,
    Unchanged,
}

/// Compare a file on disk against a baseline manifest map.
pub fn check_file_against_baseline(
    path: &Path,
    baseline: &HashMap<PathBuf, ManifestRecord>,
    algos: &[Algorithm],
) -> Result<ChangeStatus> {
    let result = hash_file(path, algos, false, false, false)?;
    match baseline.get(path) {
        None => Ok(ChangeStatus::New),
        Some(rec) => {
            for algo in algos {
                if let (Some(expected), Some(actual)) =
                    (rec.hashes.get(algo), result.hashes.get(algo))
                {
                    if expected != actual {
                        return Ok(ChangeStatus::Modified);
                    }
                }
            }
            Ok(ChangeStatus::Unchanged)
        }
    }
}
