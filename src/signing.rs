use anyhow::{Context, Result};
use argon2::{Argon2, Params, Algorithm as Argon2Algorithm, Version};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use std::path::Path;

const APP_SALT: &[u8] = b"blazehash-signing-v1";

/// Derive an Ed25519 signing key from a password using Argon2id.
/// Same password always produces the same 32-byte seed → same keypair.
fn sig_path_for(manifest_path: &Path) -> std::path::PathBuf {
    let mut p = manifest_path.to_path_buf();
    let new_name = format!(
        "{}.sig",
        manifest_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("manifest")
    );
    p.set_file_name(new_name);
    p
}

fn derive_key(password: &str) -> Result<SigningKey> {
    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
    let mut seed = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), APP_SALT, &mut seed)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Read password from BLAZEHASH_SIGN_PASSWORD env var (with warning) or /dev/tty.
pub fn read_password() -> Result<String> {
    if let Ok(pw) = std::env::var("BLAZEHASH_SIGN_PASSWORD") {
        eprintln!("[!] Warning: using BLAZEHASH_SIGN_PASSWORD env var — not recommended for production");
        return Ok(pw);
    }
    let pw = rpassword::prompt_password("Enter signing password: ")
        .context("failed to read password from terminal")?;
    Ok(pw)
}

/// Sign `manifest_path`. Writes `.sig` sidecar. Prints public key to stderr.
pub fn sign(manifest_path: &Path) -> Result<()> {
    let password = read_password()?;
    let signing_key = derive_key(&password)?;
    let verifying_key = signing_key.verifying_key();

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;
    let signature: Signature = signing_key.sign(&manifest_bytes);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pubkey_hex = hex::encode(verifying_key.to_bytes());
    let sig_content = format!(
        "blazehash-sig-v1\npubkey: {pubkey_hex}\nsigned: {timestamp}\nsig: {}\n",
        hex::encode(signature.to_bytes()),
    );

    // .sig sidecar path: manifest.hash → manifest.hash.sig
    let sig_path = sig_path_for(manifest_path);

    std::fs::write(&sig_path, &sig_content)
        .with_context(|| format!("cannot write {}", sig_path.display()))?;

    eprintln!("[+] Signed: {}", manifest_path.display());
    eprintln!("[+] Public key: {pubkey_hex}");
    eprintln!("[+] Signature: {}", sig_path.display());
    Ok(())
}

/// Verify `manifest_path` against its `.sig` sidecar and an expected public key hex.
/// Returns Ok(true) if valid, Ok(false) if invalid.
pub fn verify_sig(manifest_path: &Path, expected_pubkey_hex: &str) -> Result<bool> {
    let sig_path = sig_path_for(manifest_path);

    let sig_content = std::fs::read_to_string(&sig_path)
        .with_context(|| format!("cannot read sig file {}", sig_path.display()))?;

    let mut sig_hex = None;
    let mut embedded_pubkey_hex = None;
    for line in sig_content.lines() {
        if let Some(v) = line.strip_prefix("sig: ") { sig_hex = Some(v.to_string()); }
        if let Some(v) = line.strip_prefix("pubkey: ") { embedded_pubkey_hex = Some(v.to_string()); }
    }

    // Use expected pubkey (caller-supplied, for chain-of-custody) over embedded pubkey
    let pub_hex = if expected_pubkey_hex.is_empty() {
        embedded_pubkey_hex.ok_or_else(|| anyhow::anyhow!("no pubkey: line in sig file"))?
    } else {
        // Verify embedded pubkey matches expected (tamper check on sig file itself)
        if let Some(ref embedded) = embedded_pubkey_hex {
            if embedded.trim() != expected_pubkey_hex.trim() {
                eprintln!("[!] Sig file pubkey does not match --expected-pubkey");
                return Ok(false);
            }
        }
        expected_pubkey_hex.to_string()
    };

    let pub_bytes = hex::decode(pub_hex.trim())
        .context("invalid pubkey hex")?;
    let pub_arr: [u8; 32] = pub_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("invalid pubkey length"))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_arr)?;

    let sig_hex = sig_hex.ok_or_else(|| anyhow::anyhow!("no sig: line in sig file"))?;
    let sig_bytes = hex::decode(sig_hex.trim()).context("invalid sig hex")?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("invalid sig length"))?;
    let signature = Signature::from_bytes(&sig_arr);

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;

    match verifying_key.verify(&manifest_bytes, &signature) {
        Ok(()) => {
            eprintln!("[+] Signature valid — {}", manifest_path.display());
            Ok(true)
        }
        Err(_) => {
            eprintln!("[!] Signature INVALID — {}", manifest_path.display());
            Ok(false)
        }
    }
}

/// Auto-verify `.sig` sidecar if present. Returns Ok(false) if no sidecar (not an error).
pub fn auto_verify_sidecar(manifest_path: &Path, expected_pubkey_hex: Option<&str>) -> Result<bool> {
    let sig_path = sig_path_for(manifest_path);
    if !sig_path.exists() {
        return Ok(false);
    }
    eprintln!("[*] Found signature sidecar: {}", sig_path.display());
    let pubkey = expected_pubkey_hex.unwrap_or("");
    let valid = verify_sig(manifest_path, pubkey)?;
    if !valid {
        anyhow::bail!("manifest signature is INVALID — aborting. Use --ignore-sig to override.");
    }
    eprintln!("[K] Signature verified — {}", manifest_path.display());
    Ok(true)
}
