use anyhow::Result;
use blazehash::algorithm::Algorithm;
use blazehash::hash::FileHashResult;
use blazehash::manifest_loader::load_manifest;
use blazehash::walk::{walk_and_hash, WalkOutput};
use blazehash::walk_filter::WalkFilter;
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

    // Group by hash value — use a deterministic key by preferring algorithms in
    // a fixed priority order, then falling back to a sorted key, so the grouping
    // is stable regardless of HashMap iteration order.
    let mut groups: HashMap<String, Vec<&FileHashResult>> = HashMap::new();
    for r in &results {
        let hash = r
            .hashes
            .get(&Algorithm::Blake3)
            .or_else(|| r.hashes.get(&Algorithm::Sha256))
            .or_else(|| r.hashes.get(&Algorithm::Sha1))
            .or_else(|| r.hashes.get(&Algorithm::Md5))
            .or_else(|| r.hashes.get(&Algorithm::Whirlpool))
            .or_else(|| r.hashes.get(&Algorithm::Tiger))
            .or_else(|| {
                let mut keys: Vec<&Algorithm> = r.hashes.keys().collect();
                keys.sort_by_key(|k| format!("{k:?}"));
                keys.into_iter().next().and_then(|k| r.hashes.get(k))
            });
        if let Some(hash) = hash {
            groups.entry(hash.clone()).or_default().push(r);
        } else {
            eprintln!("[!] Skipping {} — no hashes available", r.path.display());
        }
    }

    let mut total_redundant = 0usize;
    let mut reclaimable = 0u64;

    let mut sorted_groups: Vec<Vec<&FileHashResult>> = groups
        .into_values()
        .filter(|g| g.len() >= 2)
        .map(|mut g| {
            g.sort_by_key(|r| r.path.to_string_lossy().into_owned());
            g
        })
        .collect();
    sorted_groups.sort_by(|a, b| {
        b.len()
            .cmp(&a.len())
            .then_with(|| a[0].path.cmp(&b[0].path))
    });

    let has_dupes = !sorted_groups.is_empty();

    for group in &sorted_groups {
        total_redundant += group.len() - 1;
        reclaimable += group[1..].iter().map(|r| r.size).sum::<u64>();

        if dedup_unique {
            println!("{}", group[0].path.display());
        } else if dedup_dupes {
            for r in group[1..].iter() {
                println!("{}", r.path.display());
            }
        } else {
            println!("## {} copies:", group.len());
            for r in group.iter() {
                println!("  {}", r.path.display());
            }
        }
    }

    let unique = results.len() - sorted_groups.iter().map(|g| g.len()).sum::<usize>();
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
                            entropy: None,
                            #[cfg(feature = "yara")]
                            yara_matches: None,
                            #[cfg(feature = "nomicon")]
                            nomicon_match: None,
                            #[cfg(feature = "nomicon")]
                            is_lolbin: false,
                            #[cfg(all(feature = "nomicon", feature = "yara"))]
                            yara_enrichments: Vec::new(),
                        });
                    }
                }
                Err(_) => {
                    let r = blazehash::hash::hash_file(target, algorithms, false, false, false, blazehash::hash::YaraOpts::no_yara())?;
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
