use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use crate::walk_filter::WalkFilter;
use anyhow::Result;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[cfg(not(target_os = "windows"))]
use crate::hash::{hash_file, YaraOpts};
#[cfg(not(target_os = "windows"))]
use rayon::prelude::*;
#[cfg(not(target_os = "windows"))]
use std::sync::Mutex;

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
/// On Windows, uses tokio IOCP for async I/O. On Linux/macOS, uses rayon.
pub fn walk_and_hash(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
    filter: &WalkFilter,
) -> Result<WalkOutput> {
    walk_and_hash_with_options(root, algorithms, recursive, filter, false)
}

/// Like `walk_and_hash`, but exposes additional per-file options.
/// `compute_entropy`: when true, compute Shannon entropy for each file.
pub fn walk_and_hash_with_options(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
    filter: &WalkFilter,
    compute_entropy: bool,
) -> Result<WalkOutput> {
    #[cfg(target_os = "windows")]
    {
        crate::walk_windows::walk_and_hash_windows(
            root,
            algorithms,
            recursive,
            filter,
            compute_entropy,
        )
    }

    #[cfg(not(target_os = "windows"))]
    {
        let (paths, walk_errors) = walk_paths(root, recursive);

        // Apply filter to paths before hashing.
        let filtered: Vec<PathBuf> = paths
            .into_iter()
            .filter(|path| {
                let rel = path.strip_prefix(root).unwrap_or(path);
                let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
                filter.passes(&rel.to_string_lossy(), size, mtime)
            })
            .collect();

        // File walks are I/O-bound: parallel always wins because it hides syscall
        // latency across cores. The parallel_config threshold applies only to
        // in-memory hashing (e.g., GPU vs CPU) — not to the directory walk.
        let hash_errors = Mutex::new(Vec::new());
        let results: Vec<FileHashResult> = filtered
            .par_iter()
            .filter_map(|path| {
                match hash_file(
                    path,
                    algorithms,
                    false,
                    false,
                    compute_entropy,
                    YaraOpts::no_yara(),
                ) {
                    Ok(result) => Some(result),
                    Err(err) => {
                        hash_errors.lock().unwrap().push(WalkError {
                            path: path.clone(),
                            error: err.to_string(),
                        });
                        None
                    }
                }
            })
            .collect();

        let mut errors = walk_errors;
        errors.extend(hash_errors.into_inner().unwrap());

        Ok(WalkOutput { results, errors })
    }
}
