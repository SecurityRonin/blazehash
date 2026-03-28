use crate::algorithm::Algorithm;
use crate::hash::{hash_file, FileHashResult};
use anyhow::Result;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use walkdir::WalkDir;

/// Error encountered while walking/hashing a file.
#[derive(Debug)]
pub struct WalkError {
    pub path: PathBuf,
    pub error: String,
}

/// Result of walking a directory — both successful hashes and errors.
pub struct WalkOutput {
    pub results: Vec<FileHashResult>,
    pub errors: Vec<WalkError>,
}

/// Walk a directory and collect file paths (no hashing).
/// Returns file paths and any walk errors encountered.
pub fn walk_paths(root: &Path, recursive: bool) -> (Vec<PathBuf>, Vec<WalkError>) {
    let walker = if recursive {
        WalkDir::new(root)
    } else {
        WalkDir::new(root).max_depth(1)
    };

    let mut paths = Vec::new();
    let mut errors = Vec::new();

    for entry in walker {
        match entry {
            Ok(e) => {
                if e.file_type().is_file() {
                    paths.push(e.into_path());
                }
            }
            Err(err) => {
                let path = err.path().map(|p| p.to_path_buf()).unwrap_or_default();
                errors.push(WalkError {
                    path,
                    error: err.to_string(),
                });
            }
        }
    }

    (paths, errors)
}

/// Walk a directory, hash all files, return results and errors.
/// Uses rayon for parallel file hashing.
pub fn walk_and_hash(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
) -> Result<WalkOutput> {
    let (paths, walk_errors) = walk_paths(root, recursive);

    let hash_errors = Mutex::new(Vec::new());
    let results: Vec<FileHashResult> = paths
        .par_iter()
        .filter_map(|path| match hash_file(path, algorithms) {
            Ok(result) => Some(result),
            Err(err) => {
                hash_errors.lock().unwrap().push(WalkError {
                    path: path.clone(),
                    error: err.to_string(),
                });
                None
            }
        })
        .collect();

    let mut errors = walk_errors;
    errors.extend(hash_errors.into_inner().unwrap());

    Ok(WalkOutput { results, errors })
}
