//! Progress bar support for directory walks using `indicatif`.

use crate::algorithm::Algorithm;
use crate::hash::{hash_file, FileHashResult, YaraOpts};
use crate::walk::{walk_paths, WalkError, WalkOutput};
use crate::walk_filter::WalkFilter;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Walk a directory with a progress bar, hashing all files in parallel.
/// The progress bar is hidden automatically in non-TTY contexts by indicatif.
pub fn walk_and_hash_with_progress(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
    filter: &WalkFilter,
    compute_entropy: bool,
) -> Result<WalkOutput> {
    let (paths, walk_errors) = walk_paths(root, recursive);

    let filtered: Vec<PathBuf> = paths
        .into_iter()
        .filter(|path| {
            let rel = path.strip_prefix(root).unwrap_or(path);
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
            filter.passes(&rel.to_string_lossy(), size, mtime)
        })
        .collect();

    let total_bytes: u64 = filtered
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();

    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})"
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    let hash_errors = Mutex::new(Vec::<WalkError>::new());
    let results: Vec<FileHashResult> = filtered
        .par_iter()
        .filter_map(|path| {
            let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            match hash_file(path, algorithms, false, false, compute_entropy, YaraOpts::no_yara()) {
                Ok(result) => {
                    pb.inc(file_size);
                    Some(result)
                }
                Err(err) => {
                    pb.inc(file_size);
                    hash_errors.lock().unwrap().push(WalkError {
                        path: path.clone(),
                        error: err.to_string(),
                    });
                    None
                }
            }
        })
        .collect();

    pb.finish_and_clear();

    let mut errors = walk_errors;
    errors.extend(hash_errors.into_inner().unwrap());

    Ok(WalkOutput { results, errors })
}
