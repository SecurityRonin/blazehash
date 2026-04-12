//! Multi-party manifest signing (N-of-M cosigning).
//!
//! `.msig` format: JSON object with `manifest_sha256` (integrity check),
//! `signatures` array of `{ pubkey, sig, signed_at }` entries.

use crate::signing::{derive_key_from_password, read_password};
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct MsigFile {
    pub manifest_sha256: String,
    pub signatures: Vec<MsigEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MsigEntry {
    pub pubkey: String,
    pub sig: String,
    pub signed_at: u64,
}

fn msig_path_for(manifest_path: &Path) -> std::path::PathBuf {
    let name = format!(
        "{}.msig",
        manifest_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("manifest")
    );
    manifest_path.with_file_name(name)
}

fn manifest_sha256(manifest_path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Add a cosignature to the `.msig` file (create if absent).
pub fn cosign(manifest_path: &Path) -> Result<()> {
    let password = read_password()?;
    let signing_key = derive_key_from_password(&password)?;
    let verifying_key = signing_key.verifying_key();

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;
    let manifest_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&manifest_bytes))
    };

    let signature: Signature = signing_key.sign(&manifest_bytes);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pubkey_hex = hex::encode(verifying_key.to_bytes());
    let entry = MsigEntry {
        pubkey: pubkey_hex.clone(),
        sig: hex::encode(signature.to_bytes()),
        signed_at: timestamp,
    };

    let msig_path = msig_path_for(manifest_path);
    let mut msig = if msig_path.exists() {
        let content = std::fs::read_to_string(&msig_path)
            .with_context(|| format!("cannot read {}", msig_path.display()))?;
        let existing: MsigFile = serde_json::from_str(&content).context("invalid .msig file")?;
        if existing.manifest_sha256 != manifest_hash {
            bail!(
                "manifest SHA-256 mismatch: .msig was created for {} but manifest is now {}",
                existing.manifest_sha256,
                manifest_hash
            );
        }
        existing
    } else {
        MsigFile {
            manifest_sha256: manifest_hash,
            signatures: Vec::new(),
        }
    };

    // Replace if same key already present
    if msig.signatures.iter().any(|e| e.pubkey == pubkey_hex) {
        eprintln!("[!] Warning: this key has already cosigned this manifest (replacing)");
        msig.signatures.retain(|e| e.pubkey != pubkey_hex);
    }

    msig.signatures.push(entry);

    let json = serde_json::to_string_pretty(&msig)?;
    std::fs::write(&msig_path, json)
        .with_context(|| format!("cannot write {}", msig_path.display()))?;

    eprintln!("[+] Cosigned: {}", manifest_path.display());
    eprintln!("[+] Public key: {pubkey_hex}");
    eprintln!("[+] Total signatures: {}", msig.signatures.len());
    Ok(())
}

/// Verify that at least `threshold` valid signatures exist in the `.msig` file.
pub fn verify_msig(manifest_path: &Path, threshold: usize) -> Result<bool> {
    let msig_path = msig_path_for(manifest_path);
    let content = std::fs::read_to_string(&msig_path)
        .with_context(|| format!("cannot read {}", msig_path.display()))?;
    let msig: MsigFile = serde_json::from_str(&content).context("invalid .msig file")?;

    let current_hash = manifest_sha256(manifest_path)?;
    if msig.manifest_sha256 != current_hash {
        eprintln!(
            "[!] Manifest SHA-256 mismatch: .msig={}, current={}",
            msig.manifest_sha256, current_hash
        );
        return Ok(false);
    }

    let manifest_bytes = std::fs::read(manifest_path)?;
    let mut valid_count = 0usize;

    for entry in &msig.signatures {
        let pub_bytes = match hex::decode(&entry.pubkey) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let pub_arr: [u8; 32] = match pub_bytes.try_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let sig_bytes = match hex::decode(&entry.sig) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let signature = Signature::from_bytes(&sig_arr);

        if verifying_key.verify(&manifest_bytes, &signature).is_ok() {
            eprintln!("[+] Valid signature from {}", &entry.pubkey[..16]);
            valid_count += 1;
        } else {
            eprintln!("[!] INVALID signature from {}", &entry.pubkey[..16]);
        }
    }

    eprintln!(
        "[*] {valid_count}/{} signatures valid, threshold={threshold}",
        msig.signatures.len()
    );

    if valid_count >= threshold {
        eprintln!("[+] Threshold met");
        Ok(true)
    } else {
        eprintln!("[!] Threshold NOT met");
        Ok(false)
    }
}
