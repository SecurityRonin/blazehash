use anyhow::{bail, Result};
use rand::rngs::StdRng;
use rand::{seq::SliceRandom, SeedableRng};
use std::io::Write;
use std::path::Path;

pub fn shuffle_manifest(
    manifest_path: &Path,
    seed: Option<u64>,
    out: &mut impl Write,
) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<String> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(trimmed.to_string());
        } else {
            entries.push(line.to_string());
        }
    }
    let mut rng: StdRng = match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };
    entries.shuffle(&mut rng);
    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for e in &entries {
        writeln!(out, "{e}")?;
    }
    Ok(())
}
