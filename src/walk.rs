use crate::algorithm::Algorithm;
use crate::hash::{hash_file, FileHashResult};
use anyhow::Result;
use rayon::prelude::*;
use std::path::Path;
use walkdir::WalkDir;

/// Walk a directory, hash all files, return results.
/// Uses rayon for parallel file hashing.
pub fn walk_and_hash(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
) -> Result<Vec<FileHashResult>> {
    let walker = if recursive {
        WalkDir::new(root)
    } else {
        WalkDir::new(root).max_depth(1)
    };

    let paths: Vec<_> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    let results: Vec<FileHashResult> = paths
        .par_iter()
        .filter_map(|path| hash_file(path, algorithms).ok())
        .collect();

    Ok(results)
}
