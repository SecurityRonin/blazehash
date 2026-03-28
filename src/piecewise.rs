use crate::algorithm::{hash_bytes, Algorithm};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub struct PiecewiseResult {
    pub offset: u64,
    pub chunk_size: u64,
    pub hashes: HashMap<Algorithm, String>,
}

pub fn hash_file_piecewise(
    path: &Path,
    algorithms: &[Algorithm],
    chunk_size: usize,
) -> Result<Vec<PiecewiseResult>> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut buf = vec![0u8; chunk_size];
    let mut offset: u64 = 0;
    let mut results = Vec::new();

    loop {
        let mut total_read = 0;
        while total_read < chunk_size {
            let n = file.read(&mut buf[total_read..])?;
            if n == 0 {
                break;
            }
            total_read += n;
        }
        if total_read == 0 {
            break;
        }

        let chunk = &buf[..total_read];
        let mut hashes = HashMap::new();
        for algo in algorithms {
            hashes.insert(*algo, hash_bytes(*algo, chunk));
        }

        results.push(PiecewiseResult {
            offset,
            chunk_size: total_read as u64,
            hashes,
        });

        offset += total_read as u64;
    }

    Ok(results)
}
