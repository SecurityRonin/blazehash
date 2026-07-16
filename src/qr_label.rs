//! QR code evidence label generation.
//!
//! Encodes manifest metadata (SHA-256 of manifest bytes, optional Ed25519 pubkey,
//! case ID, examiner name) into a QR code PNG for chain-of-custody labelling.

use anyhow::Result;
use std::path::Path;

/// Build the QR content string from a manifest file.
///
/// Format: `BLAZEHASH:sha256=<hex>[&pubkey=<hex>][&case=<id>][&examiner=<name>]`
///
/// - `sha256` is the SHA-256 of the manifest file bytes.
/// - `pubkey` is included only if a `.pub` sidecar exists alongside the manifest
///   and its content is <= 64 hex chars (Ed25519 only; ML-DSA-65 is too long for QR).
/// - `case` and `examiner` are parsed from `## case:` / `## examiner:` header lines.
/// - `pubkey_override` lets callers supply a pubkey directly (overrides sidecar).
/// - `ec_level` is unused in the string but accepted for API symmetry.
pub fn build_qr_content(
    manifest_path: &Path,
    pubkey_override: Option<&str>,
    _ec_level: Option<qrcode::EcLevel>,
) -> Result<String> {
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(manifest_path)?;

    // SHA-256 of the manifest file itself
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let manifest_sha256 = hex::encode(hasher.finalize());

    // Parse header lines for case / examiner
    let text = String::from_utf8_lossy(&bytes);
    let mut case_id: Option<String> = None;
    let mut examiner: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("## case:") {
            case_id = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("## examiner:") {
            examiner = Some(rest.trim().to_string());
        }
    }

    // Resolve pubkey: override > sidecar .pub file
    let pubkey: Option<String> = if let Some(pk) = pubkey_override {
        let pk = pk.trim().to_string();
        if !pk.is_empty() && pk.len() <= 64 {
            Some(pk)
        } else {
            None
        }
    } else {
        // Try sidecar: <manifest>.pub
        let pub_path = {
            let mut p = manifest_path.to_path_buf();
            let name = p
                .file_name()
                .map(|n| format!("{}.pub", n.to_string_lossy()))
                .unwrap_or_default();
            p.set_file_name(name);
            p
        };
        if pub_path.exists() {
            let raw = std::fs::read_to_string(&pub_path)?;
            let trimmed = raw.trim().to_string();
            // Only Ed25519 (64 hex chars) fits in a QR code at error level M
            if trimmed.len() <= 64 {
                Some(trimmed)
            } else {
                None
            }
        } else {
            None
        }
    };

    // Build query string
    let mut parts: Vec<String> = vec![format!("sha256={manifest_sha256}")];
    if let Some(pk) = pubkey {
        parts.push(format!("pubkey={pk}"));
    }
    if let Some(c) = case_id {
        parts.push(format!("case={c}"));
    }
    if let Some(e) = examiner {
        // URL-encode spaces as +
        let encoded = e.replace(' ', "+");
        parts.push(format!("examiner={encoded}"));
    }

    Ok(format!("BLAZEHASH:{}", parts.join("&")))
}

/// Render a QR code as Unicode block characters (Dense1x2) for terminal/stdout output.
pub fn generate_qr_text(manifest_path: &Path, pubkey_override: Option<&str>) -> Result<String> {
    let content = build_qr_content(manifest_path, pubkey_override, None)?;
    let code = qrcode::QrCode::with_error_correction_level(content.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| anyhow::anyhow!("QR encoding error: {e:?}"))?;
    Ok(code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build())
}

/// Generate a QR code PNG at `out_path` from the manifest at `manifest_path`.
pub fn generate_qr_png(
    manifest_path: &Path,
    out_path: &Path,
    pubkey_override: Option<&str>,
) -> Result<()> {
    let content = build_qr_content(manifest_path, pubkey_override, None)?;

    let code = qrcode::QrCode::with_error_correction_level(content.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| anyhow::anyhow!("QR encoding error: {e:?}"))?;

    // Render as grayscale image (black on white, 8px per module, with quiet zone)
    let img = code
        .render::<image::Luma<u8>>()
        .quiet_zone(true)
        .module_dimensions(8, 8)
        .build();

    img.save(out_path)
        .map_err(|e| anyhow::anyhow!("failed to write PNG: {e}"))?;

    Ok(())
}
