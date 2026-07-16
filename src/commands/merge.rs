use anyhow::{bail, Result};
use blazehash::manifest::ManifestRecord;
use blazehash::manifest_loader::load_manifest;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct MergeArgs {
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
}

pub fn run_merge(args: MergeArgs) -> Result<()> {
    if args.inputs.len() < 2 {
        bail!(
            "merge requires at least 2 input manifests; got {}",
            args.inputs.len()
        );
    }

    let mut by_path: HashMap<PathBuf, ManifestRecord> = HashMap::new();
    for input in &args.inputs {
        for record in load_manifest(input)? {
            by_path.insert(record.path.clone(), record);
        }
    }

    let mut records: Vec<ManifestRecord> = by_path.into_values().collect();
    records.sort_by(|a, b| a.path.cmp(&b.path));

    write_merged(&args.output, &records)
}

fn write_merged(out: &Path, records: &[ManifestRecord]) -> Result<()> {
    let mut f = std::fs::File::create(out)?;
    writeln!(f, "%%%% BLAZEHASH-1.0")?;
    writeln!(f, "%%%% size,blake3,filename")?;
    writeln!(f, "##")?;
    for r in records {
        let hash = r.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
        writeln!(f, "{},{},{}", r.size, hash, r.path.display())?;
    }
    Ok(())
}
