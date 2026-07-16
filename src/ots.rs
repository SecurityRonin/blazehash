//! OpenTimestamps (OTS) notarization — minimal calendar protocol client.
//!
//! Protocol:
//! 1. Compute SHA-256 digest of the manifest file
//! 2. POST raw 32-byte digest to calendar server: `POST /digest`
//! 3. Save binary response as `.ots` sidecar file

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const CALENDAR_SERVERS: &[&str] = &[
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
];

/// Compute the `.ots` sidecar path for a given manifest.
pub fn ots_path_for(manifest_path: &Path) -> PathBuf {
    let mut s = manifest_path.as_os_str().to_os_string();
    s.push(".ots");
    PathBuf::from(s)
}

/// Compute SHA-256 digest of a manifest file.
pub fn compute_manifest_digest(manifest_path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;
    Ok(Sha256::digest(&bytes).to_vec())
}

/// Submit a SHA-256 digest to an OTS calendar server and return the binary proof.
fn submit_to_calendar(digest: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut last_err = None;
    for server in CALENDAR_SERVERS {
        let url = format!("{server}/digest");
        eprintln!("[*] Submitting to {url}...");
        match ureq::post(&url)
            .set("Content-Type", "application/octet-stream")
            .set("Accept", "application/octet-stream")
            .send_bytes(digest)
        {
            Ok(response) => {
                let mut body = Vec::new();
                response
                    .into_reader()
                    .read_to_end(&mut body)
                    .context("failed to read OTS response")?;
                if body.is_empty() {
                    last_err = Some(anyhow::anyhow!("empty response from {server}"));
                    continue;
                }
                return Ok(body);
            }
            Err(e) => {
                eprintln!("[!] Failed: {e}");
                last_err = Some(anyhow::anyhow!("calendar {server}: {e}"));
            }
        }
    }
    bail!(
        "all OTS calendar servers failed: {}",
        last_err.unwrap_or_else(|| anyhow::anyhow!("no servers configured"))
    )
}

/// Stamp a manifest: compute digest, submit to calendar, save `.ots` proof.
pub fn stamp(manifest_path: &Path) -> Result<()> {
    let digest = compute_manifest_digest(manifest_path)?;
    eprintln!("[*] Manifest SHA-256: {}", hex::encode(&digest));

    let proof = submit_to_calendar(&digest)?;

    let ots_path = ots_path_for(manifest_path);
    std::fs::write(&ots_path, &proof)
        .with_context(|| format!("cannot write {}", ots_path.display()))?;

    eprintln!(
        "[+] OTS proof saved: {} ({} bytes)",
        ots_path.display(),
        proof.len()
    );
    Ok(())
}

/// Verify an existing `.ots` proof file exists and is non-empty.
pub fn verify(manifest_path: &Path) -> Result<bool> {
    let ots_path = ots_path_for(manifest_path);
    if !ots_path.exists() {
        bail!("no .ots file found at {}", ots_path.display());
    }

    let digest = compute_manifest_digest(manifest_path)?;
    let proof =
        std::fs::read(&ots_path).with_context(|| format!("cannot read {}", ots_path.display()))?;

    if proof.is_empty() {
        eprintln!("[!] OTS proof file is empty");
        return Ok(false);
    }

    eprintln!("[*] Manifest SHA-256: {}", hex::encode(&digest));
    eprintln!(
        "[*] OTS proof: {} ({} bytes)",
        ots_path.display(),
        proof.len()
    );
    eprintln!("[+] OTS proof file exists and is non-empty.");
    eprintln!(
        "[*] For full Bitcoin verification, use: ots verify {}",
        ots_path.display()
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_ots_stamp_unit_hash() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("test.hash");
        std::fs::write(&manifest, "test content for OTS").unwrap();

        let digest = compute_manifest_digest(&manifest).unwrap();
        assert_eq!(digest.len(), 32, "SHA-256 digest must be 32 bytes");

        let expected = Sha256::digest(b"test content for OTS");
        assert_eq!(digest, expected.as_slice());
    }

    #[test]
    fn test_ots_sidecar_path() {
        let p = PathBuf::from("/evidence/manifest.hash");
        assert_eq!(
            ots_path_for(&p),
            PathBuf::from("/evidence/manifest.hash.ots")
        );
    }
}
