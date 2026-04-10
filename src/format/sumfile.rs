use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::{bail, Result};
use std::io::Write;

pub fn write_sumfile<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    if algorithms.len() != 1 {
        bail!(
            "sha256sum/md5sum format requires exactly one algorithm (got {})",
            algorithms.len()
        );
    }
    let algo = &algorithms[0];
    for result in results {
        if let Some(hash) = result.hashes.get(algo) {
            writeln!(w, "{hash}  {}", result.path.display())?;
        }
    }
    Ok(())
}
