use anyhow::Result;
use opendal::blocking::Operator;
use std::io::Write;

use crate::algorithm::{hash_bytes, Algorithm};

/// List all objects under `prefix` in the remote operator, hash each one with
/// all specified algorithms, and write manifest lines to `out`.
///
/// Each output line follows the standard hashdeep format:
/// `<algo>  <hash>  <path>`
///
/// Returns the count of objects hashed (directory entries are skipped).
pub fn hash_remote_prefix(
    op: &Operator,
    prefix: &str,
    algos: &[Algorithm],
    out: &mut impl Write,
) -> Result<usize> {
    let mut count = 0;
    let entries = op.list(prefix)?;
    for entry in entries {
        // Skip directory entries
        if entry.metadata().is_dir() {
            continue;
        }
        let path = entry.path().to_string();
        let buf = op.read(&path)?;
        let bytes: Vec<u8> = buf.to_vec();
        for algo in algos {
            let h = hash_bytes(*algo, &bytes);
            writeln!(out, "{algo}  {h}  {path}")?;
        }
        count += 1;
    }
    Ok(count)
}
