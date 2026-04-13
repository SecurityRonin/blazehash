//! Convert a manifest to sumfile format for a single algorithm.
//!
//! For each entry whose algorithm matches `algo`, emits:
//!   `<hash>  <path>`  (two spaces, like sha256sum output)
//!
//! Header lines (starting with `##` or `%%`) are silently skipped in output.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn pivot_manifest(manifest_path: &Path, algo: &str, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)
        .map_err(|e| anyhow::anyhow!("failed to read manifest {}: {e}", manifest_path.display()))?;

    let algo_upper = algo.to_uppercase();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        // Format: `<algo>  <hash>  <path>`
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }
        let entry_algo = parts[0].trim();
        let hash = parts[1].trim();
        let path = parts[2].trim();

        if entry_algo.to_uppercase() == algo_upper {
            writeln!(out, "{hash}  {path}")?;
        }
    }
    Ok(())
}
