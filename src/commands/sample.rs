//! Draw a pseudo-random sample of N entries from a manifest.
//! Uses a deterministic LCG seeded from the manifest path for reproducibility.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn sample_manifest(manifest_path: &Path, count: usize, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

    let mut headers: Vec<&str> = Vec::new();
    let mut entries: Vec<&str> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }

    // Deterministic LCG seed derived from manifest path bytes
    let seed: u64 = manifest_path
        .to_string_lossy()
        .bytes()
        .fold(0x517cc1b727220a95u64, |acc, b| {
            acc.wrapping_mul(6364136223846793005).wrapping_add(b as u64)
        });

    let take = count.min(entries.len());
    let sampled = lcg_sample(&entries, take, seed);

    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for e in sampled {
        writeln!(out, "{e}")?;
    }
    Ok(())
}

/// Partial Fisher-Yates shuffle using an LCG PRNG — no external crate needed.
fn lcg_sample<'a>(entries: &[&'a str], take: usize, seed: u64) -> Vec<&'a str> {
    if take >= entries.len() {
        return entries.to_vec();
    }
    let mut rng = seed;
    let mut indices: Vec<usize> = (0..entries.len()).collect();

    for i in 0..take {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = i + (rng >> 33) as usize % (entries.len() - i);
        indices.swap(i, j);
    }

    indices[..take].iter().map(|&i| entries[i]).collect()
}
