use anyhow::{Context, Result};
use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa65, Signature, VerifyingKey};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use std::path::Path;

const APP_SALT: &[u8] = b"blazehash-pq-signing-v1";

/// A PQ key pair with helper methods.
pub struct PqKeyPair {
    vk_hex: String,
    sk: ml_dsa::SigningKey<MlDsa65>,
}

impl PqKeyPair {
    /// Return the hex-encoded verifying (public) key.
    pub fn verifying_key_hex(&self) -> String {
        self.vk_hex.clone()
    }
}

fn pqsig_path_for(manifest_path: &Path) -> std::path::PathBuf {
    let new_name = format!(
        "{}.pqsig",
        manifest_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("manifest")
    );
    manifest_path.with_file_name(new_name)
}

/// Derive an ML-DSA-65 signing key from a password using Argon2id.
/// Same password always produces the same 32-byte seed → same keypair.
pub fn derive_pq_key(password: &str) -> Result<PqKeyPair> {
    let params =
        Params::new(65536, 3, 1, Some(32)).map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
    let mut seed_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), APP_SALT, &mut seed_bytes)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;

    let seed_arr: ml_dsa::B32 = seed_bytes.into();
    let sk = MlDsa65::from_seed(&seed_arr);
    let vk = sk.verifying_key();
    let vk_hex = hex::encode(vk.encode().as_slice());

    Ok(PqKeyPair { vk_hex, sk })
}

/// Sign `manifest_path` using a password-derived ML-DSA-65 key.
/// Writes a `.pqsig` sidecar file next to the manifest.
pub fn pq_sign_with_password(manifest_path: &Path, password: &str) -> Result<()> {
    let kp = derive_pq_key(password)?;
    let vk_hex = kp.verifying_key_hex();

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;

    let signature: Signature<MlDsa65> = kp.sk.sign(&manifest_bytes);
    let sig_hex = hex::encode(signature.encode().as_slice());

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let content = format!(
        "blazehash-pqsig-v1\nalgorithm: ml-dsa-65\npubkey: {vk_hex}\nsigned: {timestamp}\nsig: {sig_hex}\n"
    );

    let sig_path = pqsig_path_for(manifest_path);
    std::fs::write(&sig_path, &content)
        .with_context(|| format!("cannot write {}", sig_path.display()))?;

    eprintln!("[+] PQ-Signed: {}", manifest_path.display());
    eprintln!("[+] PQ Public key: {vk_hex}");
    eprintln!("[+] PQ Signature: {}", sig_path.display());
    Ok(())
}

/// Verify `manifest_path` against its `.pqsig` sidecar.
/// If `expected_pubkey_hex` is non-empty, it is compared against the embedded pubkey.
/// Returns Ok(true) if valid, Ok(false) if invalid.
pub fn pq_verify_sig(manifest_path: &Path, expected_pubkey_hex: &str) -> Result<bool> {
    let sig_path = pqsig_path_for(manifest_path);

    let sig_content = std::fs::read_to_string(&sig_path)
        .with_context(|| format!("cannot read pqsig file {}", sig_path.display()))?;

    let mut sig_hex: Option<String> = None;
    let mut embedded_pubkey_hex: Option<String> = None;
    for line in sig_content.lines() {
        if let Some(v) = line.strip_prefix("sig: ") {
            sig_hex = Some(v.to_string());
        }
        if let Some(v) = line.strip_prefix("pubkey: ") {
            embedded_pubkey_hex = Some(v.to_string());
        }
    }

    // Use expected pubkey (caller-supplied) or fall back to embedded pubkey
    let pub_hex = if expected_pubkey_hex.is_empty() {
        embedded_pubkey_hex.ok_or_else(|| anyhow::anyhow!("no pubkey: line in pqsig file"))?
    } else {
        // Verify embedded pubkey matches expected (tamper check on sig file itself)
        if let Some(ref embedded) = embedded_pubkey_hex {
            if embedded.trim() != expected_pubkey_hex.trim() {
                eprintln!("[!] PQ sig file pubkey does not match --expected-pubkey");
                return Ok(false);
            }
        }
        expected_pubkey_hex.to_string()
    };

    // Decode public key
    let pub_bytes = hex::decode(pub_hex.trim()).context("invalid pubkey hex")?;
    let enc_vk = EncodedVerifyingKey::<MlDsa65>::try_from(pub_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("pubkey wrong length: expected 1952 bytes, got {}", pub_bytes.len()))?;
    let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);

    // Decode signature
    let sig_hex = sig_hex.ok_or_else(|| anyhow::anyhow!("no sig: line in pqsig file"))?;
    let sig_bytes = hex::decode(sig_hex.trim()).context("invalid sig hex")?;
    let enc_sig = EncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("sig wrong length: expected 3309 bytes, got {}", sig_bytes.len()))?;
    let signature = Signature::<MlDsa65>::decode(&enc_sig)
        .ok_or_else(|| anyhow::anyhow!("invalid ML-DSA-65 signature encoding"))?;

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;

    match vk.verify(&manifest_bytes, &signature) {
        Ok(()) => {
            eprintln!("[+] PQ Signature valid — {}", manifest_path.display());
            Ok(true)
        }
        Err(_) => {
            eprintln!("[!] PQ Signature INVALID — {}", manifest_path.display());
            Ok(false)
        }
    }
}
