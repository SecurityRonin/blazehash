use anyhow::Result;
use blazehash::algorithm::Algorithm;
use blazehash::hash::FileHashResult;
use blazehash::manifest_loader::load_manifest;
use blazehash::walk::{walk_and_hash, WalkOutput};
use blazehash::walk_filter::WalkFilter;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::path::PathBuf;

pub fn run(
    paths: &[PathBuf],
    algorithms: &[Algorithm],
    recursive: bool,
    dedup_unique: bool,
    dedup_dupes: bool,
) -> Result<bool> {
    let targets = &paths[1..]; // paths[0] is "dedup"
    if targets.is_empty() {
        anyhow::bail!("usage: blazehash dedup <directory|manifest> ...");
    }

    let results = load_results(targets, algorithms, recursive)?;

    // Group by first hash value
    let mut groups: HashMap<String, Vec<&FileHashResult>> = HashMap::new();
    for r in &results {
        if let Some(hash) = r.hashes.values().next() {
            groups.entry(hash.clone()).or_default().push(r);
        }
    }

    let has_dupes;
    let mut total_redundant = 0usize;
    let mut reclaimable = 0u64;

    let mut sorted_groups: Vec<_> = groups.values().filter(|g| g.len() >= 2).collect();
    sorted_groups.sort_by_key(|g| Reverse(g.len()));

    has_dupes = !sorted_groups.is_empty();

    for group in &sorted_groups {
        total_redundant += group.len() - 1;
        reclaimable += group[1..].iter().map(|r| r.size).sum::<u64>();

        if dedup_unique {
            println!("{}", group[0].path.display());
        } else if dedup_dupes {
            for r in group.iter() {
                println!("{}", r.path.display());
            }
        } else {
            println!("## {} copies:", group.len());
            for r in group.iter() {
                println!("  {}", r.path.display());
            }
        }
    }

    let unique = groups.values().filter(|g| g.len() == 1).count();
    let dup_groups = sorted_groups.len();
    eprintln!(
        "[+] {} files — {} unique, {} duplicate groups, {} redundant ({:.1} MiB reclaimable)",
        results.len(),
        unique,
        dup_groups,
        total_redundant,
        reclaimable as f64 / (1024.0 * 1024.0)
    );

    Ok(has_dupes)
}

fn load_results(
    targets: &[PathBuf],
    algorithms: &[Algorithm],
    recursive: bool,
) -> Result<Vec<FileHashResult>> {
    let mut all = Vec::new();
    for target in targets {
        if target.is_file() {
            match load_manifest(target) {
                Ok(records) => {
                    for rec in records {
                        all.push(FileHashResult {
                            path: rec.path,
                            size: rec.size,
                            hashes: rec.hashes,
                        });
                    }
                }
                Err(_) => {
                    let r = blazehash::hash::hash_file(target, algorithms, false, false)?;
                    all.push(r);
                }
            }
        } else {
            let WalkOutput { results, errors } =
                walk_and_hash(target, algorithms, recursive, &WalkFilter::default())?;
            super::report_walk_errors(&errors);
            all.extend(results);
        }
    }
    Ok(all)
}
