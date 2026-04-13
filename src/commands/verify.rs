use anyhow::Result;
use blazehash::algorithm::Algorithm;
use std::io::Write;
use std::path::Path;

pub struct VerifyResult {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

pub fn verify_manifest(
    manifest_path: &Path,
    algo_filter: Option<&str>,
    out: &mut impl Write,
) -> Result<VerifyResult> {
    let records = blazehash::manifest_loader::load_manifest(manifest_path)?;
    let mut result = VerifyResult { total: 0, passed: 0, failed: 0 };

    // Determine which algorithms to verify
    let filter_algo: Option<Algorithm> = if let Some(f) = algo_filter {
        Some(f.parse().map_err(|e| anyhow::anyhow!("unknown algorithm {f:?}: {e}"))?)
    } else {
        None
    };

    for record in &records {
        let path_str = record.path.to_string_lossy();

        // Collect hashes to verify based on filter
        let hashes_to_verify: Vec<(Algorithm, &str)> = record
            .hashes
            .iter()
            .filter(|(algo, _)| {
                filter_algo.map_or(true, |fa| **algo == fa)
            })
            .map(|(algo, hash)| (*algo, hash.as_str()))
            .collect();

        if hashes_to_verify.is_empty() {
            continue;
        }

        result.total += hashes_to_verify.len();

        let file_path = &record.path;
        if !file_path.exists() {
            for _ in &hashes_to_verify {
                writeln!(out, "MISS  {path_str}")?;
                result.failed += 1;
            }
            continue;
        }

        let bytes = std::fs::read(file_path)?;

        for (algo, stored_hash) in &hashes_to_verify {
            let computed = blazehash::algorithm::hash_bytes(*algo, &bytes);
            if &computed == stored_hash {
                writeln!(out, "PASS  {path_str}")?;
                result.passed += 1;
            } else {
                writeln!(
                    out,
                    "FAIL  {path_str}  expected={stored_hash}  got={computed}"
                )?;
                result.failed += 1;
            }
        }
    }

    Ok(result)
}
