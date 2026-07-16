use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn checksum_manifest(manifest_path: &Path, json: bool, out: &mut impl Write) -> Result<()> {
    let bytes = std::fs::read(manifest_path)?;
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let path_str = manifest_path.display().to_string();

    if json {
        writeln!(
            out,
            "{}",
            serde_json::json!({
                "algorithm": "blake3",
                "hash": hash,
                "path": path_str,
            })
        )?;
    } else {
        writeln!(out, "blake3  {hash}  {path_str}")?;
    }
    Ok(())
}
