#![cfg(target_os = "windows")]
//! Windows-specific parallel file walk using tokio IOCP.
//!
//! tokio::fs uses I/O Completion Ports (IOCP) under the hood on Windows,
//! allowing concurrent file I/O with minimal thread overhead.
//! Replaces the rayon-based walk for Windows only.

use crate::algorithm::Algorithm;
use crate::hash::hash_file;
use crate::walk::{WalkError, WalkOutput};
use crate::walk_filter::WalkFilter;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Maximum concurrent open file handles.
const MAX_CONCURRENT: usize = 256;

pub fn walk_and_hash_windows(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
    filter: &WalkFilter,
    compute_entropy: bool,
) -> Result<WalkOutput> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(walk_async(
        root,
        algorithms,
        recursive,
        filter,
        compute_entropy,
    ))
}

async fn walk_async(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
    filter: &WalkFilter,
    compute_entropy: bool,
) -> Result<WalkOutput> {
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let algorithms = Arc::new(algorithms.to_vec());
    let mut handles = tokio::task::JoinSet::new();

    let walker = if recursive {
        walkdir::WalkDir::new(root)
    } else {
        walkdir::WalkDir::new(root).max_depth(1)
    };

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();

        // Apply filter before spawning a hash task.
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let meta = std::fs::metadata(&path);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime = meta.ok().and_then(|m| m.modified().ok());
        if !filter.passes(&rel.to_string_lossy(), size, mtime) {
            continue;
        }
        let sem = Arc::clone(&sem);
        let algos = Arc::clone(&algorithms);

        handles.spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let path_for_error = path.clone();
            tokio::task::spawn_blocking(move || {
                hash_file(&path, &algos, false, false, compute_entropy)
            })
            .await
            .map_err(|e| (path_for_error.clone(), format!("spawn_blocking panic: {e}")))
            .and_then(|inner| inner.map_err(|e| (path_for_error.clone(), e.to_string())))
        });
    }

    let mut results = Vec::new();
    let mut errors = Vec::new();
    while let Some(res) = handles.join_next().await {
        match res {
            Ok(Ok(r)) => results.push(r),
            Ok(Err((path, error))) => errors.push(WalkError { path, error }),
            Err(e) => errors.push(WalkError {
                path: Default::default(),
                error: format!("join error: {e}"),
            }),
        }
    }

    Ok(WalkOutput { results, errors })
}
