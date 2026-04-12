use anyhow::Result;
use blazehash::manifest_loader::load_manifest;
use std::collections::HashMap;
use std::path::PathBuf;

pub enum DiffEntry {
    Added(PathBuf),
    Removed(PathBuf),
    Modified { path: PathBuf },
    Moved { from: PathBuf, to: PathBuf },
}

/// A map from path to (first_hash, size) for patch output.
type RecordMap = HashMap<PathBuf, (String, u64)>;

pub fn run(
    paths: &[PathBuf],
    recursive: bool,
    compare_by: &str,
    show_identical: bool,
    patch: bool,
) -> Result<bool> {
    // paths[0] = "diff", paths[1] = left/before, paths[2] = right/after
    if paths.len() < 3 {
        anyhow::bail!("usage: blazehash diff <left> <right>");
    }
    let left = &paths[1];
    let right = &paths[2];

    // ── Folder-vs-folder diff ─────────────────────────────────────────────────
    if left.is_dir() && right.is_dir() {
        use blazehash::folder_diff::{diff_folders, print_entry, print_summary, CompareBy};
        let cmp = match compare_by {
            "paranoid" => CompareBy::Paranoid,
            "size-time" => CompareBy::SizeTime,
            "name" => CompareBy::Name,
            _ => CompareBy::Content,
        };
        let result = diff_folders(left, right, recursive, cmp)?;
        for e in &result.entries {
            print_entry(e, show_identical);
        }
        print_summary(left, right, &result);
        return Ok(result.has_diff());
    }

    // ── Manifest-vs-manifest diff (existing behaviour) ────────────────────────
    let before_records = load_manifest(left)?;
    let after_records = load_manifest(right)?;

    // path -> (first hash value, size)
    let before_map: RecordMap = before_records
        .iter()
        .filter_map(|r| {
            r.hashes
                .values()
                .next()
                .map(|h| (r.path.clone(), (h.clone(), r.size)))
        })
        .collect();
    let after_map: RecordMap = after_records
        .iter()
        .filter_map(|r| {
            r.hashes
                .values()
                .next()
                .map(|h| (r.path.clone(), (h.clone(), r.size)))
        })
        .collect();

    // hash -> path (for move detection)
    let before_by_hash: HashMap<String, PathBuf> = before_map
        .iter()
        .map(|(p, (h, _))| (h.clone(), p.clone()))
        .collect();

    let mut diffs: Vec<DiffEntry> = Vec::new();
    let mut moved_froms: std::collections::HashSet<PathBuf> = Default::default();

    for (path, (hash, _)) in &after_map {
        match before_map.get(path) {
            None => {
                if let Some(from) = before_by_hash.get(hash) {
                    if !after_map.contains_key(from) {
                        moved_froms.insert(from.clone());
                        diffs.push(DiffEntry::Moved {
                            from: from.clone(),
                            to: path.clone(),
                        });
                        continue;
                    }
                }
                diffs.push(DiffEntry::Added(path.clone()));
            }
            Some((bh, _)) if bh != hash => diffs.push(DiffEntry::Modified { path: path.clone() }),
            _ => {}
        }
    }

    for path in before_map.keys() {
        if !after_map.contains_key(path) && !moved_froms.contains(path) {
            diffs.push(DiffEntry::Removed(path.clone()));
        }
    }

    let has_diff = !diffs.is_empty();

    if patch {
        println!("--- {}", left.display());
        println!("+++ {}", right.display());
        println!("@@ manifest diff @@");
        for d in &diffs {
            match d {
                DiffEntry::Added(p) => {
                    if let Some((hash, size)) = after_map.get(p) {
                        println!("+{size},{hash},{}", p.display());
                    }
                }
                DiffEntry::Removed(p) => {
                    if let Some((hash, size)) = before_map.get(p) {
                        println!("-{size},{hash},{}", p.display());
                    }
                }
                DiffEntry::Modified { path } => {
                    if let Some((bhash, bsize)) = before_map.get(path) {
                        println!("-{bsize},{bhash},{}", path.display());
                    }
                    if let Some((ahash, asize)) = after_map.get(path) {
                        println!("+{asize},{ahash},{}", path.display());
                    }
                }
                DiffEntry::Moved { from, to } => {
                    if let Some((hash, size)) = before_map.get(from) {
                        println!("-{size},{hash},{}", from.display());
                        println!("+{size},{hash},{}", to.display());
                    }
                }
            }
        }
        return Ok(has_diff);
    }

    for d in &diffs {
        match d {
            DiffEntry::Added(p) => println!("[+] ADDED    {}", p.display()),
            DiffEntry::Removed(p) => println!("[-] REMOVED  {}", p.display()),
            DiffEntry::Modified { path } => println!("[!] MODIFIED {}", path.display()),
            DiffEntry::Moved { from, to } => {
                println!("[*] MOVED    {} <- {}", to.display(), from.display())
            }
        }
    }
    if !has_diff {
        println!("[=] Manifests are identical");
    }
    Ok(has_diff)
}
