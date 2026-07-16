use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct SelfCheckResult {
    pub path: PathBuf,
    pub size: u64,
    pub blake3: String,
    pub sha256: String,
}

pub fn selfcheck() -> Result<SelfCheckResult> {
    let exe = std::env::current_exe()?;
    let bytes = std::fs::read(&exe)?;
    let size = bytes.len() as u64;

    let blake3 = {
        let mut h = blake3::Hasher::new();
        h.update(&bytes);
        h.finalize().to_hex().to_string()
    };

    let sha256 = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    };

    Ok(SelfCheckResult {
        path: exe,
        size,
        blake3,
        sha256,
    })
}

pub fn print_selfcheck(r: &SelfCheckResult) {
    println!("Binary:   {}", r.path.display());
    let mb = r.size as f64 / 1_048_576.0;
    println!("Size:     {} bytes ({:.2} MB)", r.size, mb);
    println!("BLAKE3:   {}", r.blake3);
    println!("SHA-256:  {}", r.sha256);
}
