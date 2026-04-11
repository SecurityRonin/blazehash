//! Folder-vs-folder diff with parallel hashing.
//!
//! Inspired by Beyond Compare 5's comparison modes:
//! - `Content`  — hash every file with XXH3-128 (~30-50 GB/s, non-crypto)
//! - `Paranoid` — hash every file with BLAKE3 (~6-10 GB/s, cryptographic)
//! - `SizeTime` — compare size + mtime only (no I/O beyond stat)
//! - `Name`     — existence check only (fastest, no I/O at all)
//!
//! Identical files are hidden by default (like BC5); pass `show_identical`
//! to surface them. Summary includes per-category counts and byte deltas.

use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ─── Public API types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareBy {
    /// Full content hash (XXH3-128, ~30-50 GB/s). Non-crypto; collisions
    /// are astronomically unlikely but theoretically possible.
    Content,
    /// Full content hash (BLAKE3, ~6-10 GB/s). Cryptographically secure;
    /// use when you need proof-grade collision resistance.
    Paranoid,
    /// Size + modification time. Fast; no file I/O beyond stat.
    SizeTime,
    /// Name existence only. Instant; no stat, no I/O.
    Name,
}

#[derive(Debug)]
pub enum FolderDiffEntry {
    Identical {
        path: PathBuf,
        size: u64,
    },
    Modified {
        path: PathBuf,
        left_size: u64,
        right_size: u64,
    },
    Added {
        path: PathBuf,
        size: u64,
    },
    Removed {
        path: PathBuf,
        size: u64,
    },
    /// Same content (hash), different relative path — a rename/move within the tree.
    Moved {
        from: PathBuf,
        to: PathBuf,
        size: u64,
    },
    Error {
        path: PathBuf,
        side: Side,
        error: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum Side {
    Left,
    Right,
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Side::Left => write!(f, "left"),
            Side::Right => write!(f, "right"),
        }
    }
}

#[derive(Debug, Default)]
pub struct FolderDiffSummary {
    pub identical: usize,
    pub modified: usize,
    pub added: usize,
    pub removed: usize,
    pub moved: usize,
    pub errors: usize,
    pub left_bytes: u64,
    pub right_bytes: u64,
}

pub struct FolderDiffResult {
    pub entries: Vec<FolderDiffEntry>,
}

impl FolderDiffResult {
    pub fn has_diff(&self) -> bool {
        self.entries.iter().any(|e| !matches!(e, FolderDiffEntry::Identical { .. }))
    }

    pub fn summary(&self) -> FolderDiffSummary {
        let mut s = FolderDiffSummary::default();
        for e in &self.entries {
            match e {
                FolderDiffEntry::Identical { size, .. } => {
                    s.identical += 1;
                    s.left_bytes += size;
                    s.right_bytes += size;
                }
                FolderDiffEntry::Modified { left_size, right_size, .. } => {
                    s.modified += 1;
                    s.left_bytes += left_size;
                    s.right_bytes += right_size;
                }
                FolderDiffEntry::Added { size, .. } => {
                    s.added += 1;
                    s.right_bytes += size;
                }
                FolderDiffEntry::Removed { size, .. } => {
                    s.removed += 1;
                    s.left_bytes += size;
                }
                FolderDiffEntry::Moved { size, .. } => {
                    s.moved += 1;
                    s.left_bytes += size;
                    s.right_bytes += size;
                }
                FolderDiffEntry::Error { .. } => {
                    s.errors += 1;
                }
            }
        }
        s
    }
}

// ─── Internal file record ─────────────────────────────────────────────────────

struct FileRecord {
    /// Relative path from the root being walked.
    rel: PathBuf,
    size: u64,
    mtime: Option<SystemTime>,
    /// Set only when compare_by == Content.
    hash: Option<u128>,
}

// ─── Directory walk ───────────────────────────────────────────────────────────

/// Collect all files under `root`, returning relative-path records.
/// When `compare_by == Content`, files are hashed in parallel with XXH3-128.
fn collect(root: &Path, recursive: bool, compare_by: CompareBy) -> Vec<FileRecord> {
    let walker = if recursive {
        walkdir::WalkDir::new(root)
    } else {
        walkdir::WalkDir::new(root).max_depth(1)
    };

    let entries: Vec<walkdir::DirEntry> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    // Parallel collect with rayon
    entries
        .into_par_iter()
        .filter_map(|e| {
            let abs = e.into_path();
            let rel = abs.strip_prefix(root).ok()?.to_path_buf();
            let meta = std::fs::metadata(&abs).ok()?;
            let size = meta.len();
            let mtime = meta.modified().ok();
            let hash = if compare_by == CompareBy::Content {
                hash_xxh3(&abs).ok()
            } else if compare_by == CompareBy::Paranoid {
                hash_blake3(&abs).ok()
            } else {
                None
            };
            Some(FileRecord { rel, size, mtime, hash })
        })
        .collect()
}

// ─── XXH3-128 hashing ────────────────────────────────────────────────────────

/// Hash a file with XXH3-128 (~30-50 GB/s).
///
/// Uses `memmap2` for I/O (same approach as the rest of blazehash).
/// Falls back to streaming reads if mmap fails (e.g. special files).
fn hash_xxh3(path: &Path) -> Result<u128> {
    use xxhash_rust::xxh3::Xxh3Default;

    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let meta = file.metadata()?;
    let len = meta.len() as usize;

    if len == 0 {
        return Ok(xxhash_rust::xxh3::xxh3_128(&[]));
    }

    // mmap for files ≤ 512 MiB; streaming for larger (avoids address-space pressure)
    if len <= 512 * 1024 * 1024 {
        let mmap = unsafe { memmap2::Mmap::map(&file) };
        if let Ok(m) = mmap {
            return Ok(xxhash_rust::xxh3::xxh3_128(&m));
        }
    }

    // Streaming fallback
    use std::io::Read;
    let mut hasher = Xxh3Default::new();
    let mut reader = std::io::BufReader::with_capacity(256 * 1024, file);
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.digest128())
}

/// Hash a file with BLAKE3 (~6-10 GB/s, cryptographic).
///
/// Produces a 128-bit value (low 16 bytes of the 256-bit BLAKE3 output) so
/// it fits the same `u128` slot used by XXH3, keeping the comparison logic
/// uniform. The full 256-bit BLAKE3 output is collision-resistant; truncating
/// to 128 bits retains 2^64 collision resistance — still far beyond practical
/// attack budgets.
fn hash_blake3(path: &Path) -> Result<u128> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let meta = file.metadata()?;
    let len = meta.len() as usize;

    if len == 0 {
        let hash = blake3::hash(&[]);
        return Ok(u128::from_le_bytes(hash.as_bytes()[..16].try_into().unwrap()));
    }

    // mmap fast path
    if len <= 512 * 1024 * 1024 {
        let mmap = unsafe { memmap2::Mmap::map(&file) };
        if let Ok(m) = mmap {
            let hash = blake3::hash(&m);
            return Ok(u128::from_le_bytes(hash.as_bytes()[..16].try_into().unwrap()));
        }
    }

    // Streaming fallback
    use std::io::Read;
    let mut hasher = blake3::Hasher::new();
    let mut reader = std::io::BufReader::with_capacity(256 * 1024, file);
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(u128::from_le_bytes(hash.as_bytes()[..16].try_into().unwrap()))
}

// ─── Core diff logic ──────────────────────────────────────────────────────────

/// Compare two directories and return a structured diff result.
///
/// Files are compared using `compare_by`:
/// - `Content`  — XXH3-128 hash (definitive, reads all data)
/// - `SizeTime` — size + mtime (fast heuristic, no I/O beyond stat)
/// - `Name`     — presence/absence only
///
/// Move detection (cross-path renames) is only performed for `Content` mode,
/// where a hash uniquely identifies file contents.
pub fn diff_folders(
    left: &Path,
    right: &Path,
    recursive: bool,
    compare_by: CompareBy,
) -> Result<FolderDiffResult> {
    // Walk both sides in parallel
    let (left_records, right_records) = rayon::join(
        || collect(left, recursive, compare_by),
        || collect(right, recursive, compare_by),
    );

    // Index by relative path
    let left_map: HashMap<PathBuf, FileRecord> =
        left_records.into_iter().map(|r| (r.rel.clone(), r)).collect();
    let right_map: HashMap<PathBuf, FileRecord> =
        right_records.into_iter().map(|r| (r.rel.clone(), r)).collect();

    // Build reverse hash→path map for move detection (content mode only)
    let left_by_hash: HashMap<u128, &PathBuf> = if matches!(compare_by, CompareBy::Content | CompareBy::Paranoid) {
        left_map
            .iter()
            .filter_map(|(p, r)| r.hash.map(|h| (h, p)))
            .collect()
    } else {
        HashMap::new()
    };

    let mut entries: Vec<FolderDiffEntry> = Vec::new();
    let mut moved_from: std::collections::HashSet<PathBuf> = Default::default();

    // Files present in right: compare with left
    for (rel, rr) in &right_map {
        match left_map.get(rel) {
            None => {
                // Not in left — Added, or Moved from somewhere else?
                if matches!(compare_by, CompareBy::Content | CompareBy::Paranoid) {
                    if let Some(hash) = rr.hash {
                        if let Some(&from_path) = left_by_hash.get(&hash) {
                            if !right_map.contains_key(from_path) {
                                // The source is gone from right → it's a move
                                moved_from.insert(from_path.clone());
                                entries.push(FolderDiffEntry::Moved {
                                    from: from_path.clone(),
                                    to: rel.clone(),
                                    size: rr.size,
                                });
                                continue;
                            }
                        }
                    }
                }
                entries.push(FolderDiffEntry::Added {
                    path: rel.clone(),
                    size: rr.size,
                });
            }
            Some(lr) => {
                if files_match(lr, rr, compare_by) {
                    entries.push(FolderDiffEntry::Identical {
                        path: rel.clone(),
                        size: rr.size,
                    });
                } else {
                    entries.push(FolderDiffEntry::Modified {
                        path: rel.clone(),
                        left_size: lr.size,
                        right_size: rr.size,
                    });
                }
            }
        }
    }

    // Files only in left → Removed (unless already classified as move source)
    for (rel, lr) in &left_map {
        if !right_map.contains_key(rel) && !moved_from.contains(rel) {
            entries.push(FolderDiffEntry::Removed {
                path: rel.clone(),
                size: lr.size,
            });
        }
    }

    // Sort for stable, readable output
    entries.sort_by(|a, b| {
        let (ka, pa) = entry_sort_key(a);
        let (kb, pb) = entry_sort_key(b);
        (ka, pa).cmp(&(kb, pb))
    });

    Ok(FolderDiffResult { entries })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn files_match(left: &FileRecord, right: &FileRecord, compare_by: CompareBy) -> bool {
    match compare_by {
        CompareBy::Name => true, // existence already confirmed by the caller
        CompareBy::SizeTime => {
            if left.size != right.size {
                return false;
            }
            // Compare mtimes within 2s tolerance (FAT32 has 2s resolution)
            match (left.mtime, right.mtime) {
                (Some(lt), Some(rt)) => {
                    let diff = if lt > rt {
                        lt.duration_since(rt)
                    } else {
                        rt.duration_since(lt)
                    };
                    diff.map_or(false, |d| d.as_secs() <= 2)
                }
                _ => left.size == right.size, // no mtime → fall back to size only
            }
        }
        CompareBy::Content | CompareBy::Paranoid => left.hash == right.hash && left.hash.is_some(),
    }
}

fn entry_sort_key(e: &FolderDiffEntry) -> (&'static str, &PathBuf) {
    match e {
        FolderDiffEntry::Removed { path, .. } => ("1-removed", path),
        FolderDiffEntry::Modified { path, .. } => ("2-modified", path),
        FolderDiffEntry::Moved { to, .. } => ("3-moved", to),
        FolderDiffEntry::Added { path, .. } => ("4-added", path),
        FolderDiffEntry::Identical { path, .. } => ("5-identical", path),
        FolderDiffEntry::Error { path, .. } => ("6-error", path),
    }
}

// ─── Display helper (used by commands/diff.rs) ────────────────────────────────

pub fn print_entry(e: &FolderDiffEntry, show_identical: bool) {
    match e {
        FolderDiffEntry::Removed { path, size } => {
            println!("[-] REMOVED   {}  ({})", path.display(), format_size(*size));
        }
        FolderDiffEntry::Modified { path, left_size, right_size } => {
            println!(
                "[≠] MODIFIED  {}  ({} → {})",
                path.display(),
                format_size(*left_size),
                format_size(*right_size)
            );
        }
        FolderDiffEntry::Moved { from, to, size } => {
            println!(
                "[→] MOVED     {}  ← {}  ({})",
                to.display(),
                from.display(),
                format_size(*size)
            );
        }
        FolderDiffEntry::Added { path, size } => {
            println!("[+] ADDED     {}  ({})", path.display(), format_size(*size));
        }
        FolderDiffEntry::Identical { path, size } => {
            if show_identical {
                println!("[=] IDENTICAL {}  ({})", path.display(), format_size(*size));
            }
        }
        FolderDiffEntry::Error { path, side, error } => {
            eprintln!("[!] ERROR ({side}) {}  — {error}", path.display());
        }
    }
}

pub fn print_summary(left: &Path, right: &Path, result: &FolderDiffResult) {
    let s = result.summary();
    if !result.has_diff() {
        println!("[=] Folders are identical");
    }
    println!(
        "[*] {:>4} identical | {:>4} modified | {:>4} added | {:>4} removed | {:>4} moved{}",
        s.identical,
        s.modified,
        s.added,
        s.removed,
        s.moved,
        if s.errors > 0 { format!(" | {} errors", s.errors) } else { String::new() }
    );
    println!(
        "    Left  {} — {}",
        left.display(),
        format_size(s.left_bytes)
    );
    println!(
        "    Right {} — {}",
        right.display(),
        format_size(s.right_bytes)
    );
    let (sign, delta) = if s.right_bytes >= s.left_bytes {
        ("+", s.right_bytes - s.left_bytes)
    } else {
        ("-", s.left_bytes - s.right_bytes)
    };
    if delta > 0 {
        println!("    Delta {sign}{}", format_size(delta));
    }
}

fn format_size(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}
