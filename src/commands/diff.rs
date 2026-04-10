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

pub fn run(paths: &[PathBuf]) -> Result<bool> {
    // paths[0] = "diff", paths[1] = before, paths[2] = after
    if paths.len() < 3 {
        anyhow::bail!("usage: blazehash diff <before.hash> <after.hash>");
    }
    let before_records = load_manifest(&paths[1])?;
    let after_records = load_manifest(&paths[2])?;

    // path -> first hash value
    let before_map: HashMap<PathBuf, String> = before_records
        .iter()
        .filter_map(|r| r.hashes.values().next().map(|h| (r.path.clone(), h.clone())))
        .collect();
    let after_map: HashMap<PathBuf, String> = after_records
        .iter()
        .filter_map(|r| r.hashes.values().next().map(|h| (r.path.clone(), h.clone())))
        .collect();

    // hash -> path (for move detection)
    let before_by_hash: HashMap<String, PathBuf> = before_map
        .iter()
        .map(|(p, h)| (h.clone(), p.clone()))
        .collect();

    let mut diffs: Vec<DiffEntry> = Vec::new();
    let mut moved_froms: std::collections::HashSet<PathBuf> = Default::default();

    for (path, hash) in &after_map {
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
            Some(bh) if bh != hash => diffs.push(DiffEntry::Modified { path: path.clone() }),
            _ => {}
        }
    }

    for path in before_map.keys() {
        if !after_map.contains_key(path) && !moved_froms.contains(path) {
            diffs.push(DiffEntry::Removed(path.clone()));
        }
    }

    let has_diff = !diffs.is_empty();
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
