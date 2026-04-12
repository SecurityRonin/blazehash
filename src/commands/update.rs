use blazehash::algorithm::Algorithm;
use blazehash::hash::hash_file;
use blazehash::manifest::ManifestRecord;
use blazehash::manifest_loader::load_manifest;
use anyhow::Result;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct UpdateArgs {
    pub manifest: PathBuf,
    pub path: PathBuf,
    pub algos: Vec<Algorithm>,
    pub output: PathBuf,
}

pub fn run_update(args: UpdateArgs) -> Result<()> {
    // Build a lookup keyed by absolute/canonical path so that records loaded from
    // a manifest (which may use absolute paths) can be matched against walkdir entries.
    let existing: HashMap<PathBuf, ManifestRecord> = load_manifest(&args.manifest)?
        .into_iter()
        .map(|r| (r.path.clone(), r))
        .collect();

    let mut updated: HashMap<PathBuf, ManifestRecord> = HashMap::new();

    for entry in walkdir::WalkDir::new(&args.path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let fpath = entry.path().to_path_buf();
        let meta = std::fs::metadata(&fpath)?;
        let fsize = meta.len();

        if let Some(rec) = existing.get(&fpath) {
            if rec.size == fsize {
                updated.insert(fpath, rec.clone());
                continue;
            }
        }

        // File is new or size changed — re-hash it.
        let result = hash_file(&fpath, &args.algos, false, false, false)?;
        updated.insert(
            fpath.clone(),
            ManifestRecord {
                path: fpath,
                size: result.size,
                hashes: result.hashes,
            },
        );
    }

    write_manifest(&args.output, &updated)
}

fn write_manifest(out: &Path, records: &HashMap<PathBuf, ManifestRecord>) -> Result<()> {
    let mut sorted: Vec<&ManifestRecord> = records.values().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut f = std::fs::File::create(out)?;
    writeln!(f, "%%%% BLAZEHASH-1.0")?;
    writeln!(f, "%%%% size,blake3,filename")?;
    writeln!(f, "##")?;
    for r in sorted {
        let hash = r.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
        writeln!(f, "{},{},{}", r.size, hash, r.path.display())?;
    }
    Ok(())
}
