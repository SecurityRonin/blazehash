use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ManifestStats {
    pub total_entries: usize,
    pub algorithms: HashMap<String, usize>,
    pub extensions: HashMap<String, usize>,
    pub unique_paths: usize,
}

pub fn compute_stats(manifest_path: &Path) -> Result<ManifestStats> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut stats = ManifestStats::default();
    let mut paths: std::collections::HashSet<String> = Default::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            stats.total_entries += 1;
            let algo = parts[0].trim().to_lowercase();
            *stats.algorithms.entry(algo).or_insert(0) += 1;

            let path = parts[2].trim();
            paths.insert(path.to_string());

            let ext = std::path::Path::new(path)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_else(|| "(none)".to_string());
            *stats.extensions.entry(ext).or_insert(0) += 1;
        }
    }

    stats.unique_paths = paths.len();
    Ok(stats)
}

pub fn run_stats(manifest_path: &std::path::Path, json: bool) -> anyhow::Result<()> {
    let stats = compute_stats(manifest_path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        print_stats(&stats);
    }
    Ok(())
}

pub fn print_stats(stats: &ManifestStats) {
    println!("Entries:  {}", stats.total_entries);
    println!("Unique:   {}", stats.unique_paths);
    println!();
    println!("Algorithms:");
    let mut algos: Vec<_> = stats.algorithms.iter().collect();
    algos.sort_by_key(|(k, _)| k.as_str());
    for (algo, count) in algos {
        println!("  {algo:<12} {count}");
    }
    println!();
    println!("Extensions:");
    let mut exts: Vec<_> = stats.extensions.iter().collect();
    exts.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (ext, count) in exts.iter().take(20) {
        println!("  {ext:<12} {count}");
    }
}
