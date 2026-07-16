use std::io::Write;
use tempfile::NamedTempFile;

fn write_temp_manifest(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

#[test]
fn test_pq_derive_key_deterministic() {
    use blazehash::pq_signing::derive_pq_key;
    let k1 = derive_pq_key("password123").unwrap();
    let k2 = derive_pq_key("password123").unwrap();
    assert_eq!(k1.verifying_key_hex(), k2.verifying_key_hex());
}

#[test]
fn test_pq_derive_key_different_passwords() {
    use blazehash::pq_signing::derive_pq_key;
    let k1 = derive_pq_key("password123").unwrap();
    let k2 = derive_pq_key("different").unwrap();
    assert_ne!(k1.verifying_key_hex(), k2.verifying_key_hex());
}

#[test]
fn test_pq_sign_creates_pqsig_file() {
    use blazehash::pq_signing::pq_sign_with_password;
    let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc123,/foo/bar\n");
    let manifest_path = manifest.path();
    pq_sign_with_password(manifest_path, "testpass").unwrap();
    let sig_path = {
        let name = format!(
            "{}.pqsig",
            manifest_path.file_name().unwrap().to_str().unwrap()
        );
        manifest_path.with_file_name(name)
    };
    assert!(sig_path.exists(), ".pqsig file must be created");
    let content = std::fs::read_to_string(&sig_path).unwrap();
    assert!(
        content.starts_with("blazehash-pqsig-v1\n"),
        "must have version header"
    );
    assert!(
        content.contains("algorithm: ml-dsa-65"),
        "must declare algorithm"
    );
    assert!(content.contains("pubkey: "), "must embed pubkey");
    assert!(content.contains("sig: "), "must embed signature");
}

#[test]
fn test_pq_verify_valid_signature() {
    use blazehash::pq_signing::{pq_sign_with_password, pq_verify_sig};
    let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc123,/foo/bar\n");
    let manifest_path = manifest.path();
    pq_sign_with_password(manifest_path, "mypassword").unwrap();
    let result = pq_verify_sig(manifest_path, "").unwrap();
    assert!(result, "valid PQ signature must verify");
}

#[test]
fn test_pq_verify_tampered_manifest_fails() {
    use blazehash::pq_signing::{pq_sign_with_password, pq_verify_sig};
    let mut manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc123,/foo/bar\n");
    let manifest_path = manifest.path().to_path_buf();
    pq_sign_with_password(&manifest_path, "mypassword").unwrap();
    manifest.write_all(b"\ntampered").unwrap();
    let result = pq_verify_sig(&manifest_path, "").unwrap();
    assert!(!result, "tampered manifest must fail PQ verification");
}

#[test]
fn test_pq_verify_wrong_pubkey_fails() {
    use blazehash::pq_signing::{pq_sign_with_password, pq_verify_sig};
    let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc123,/foo/bar\n");
    let manifest_path = manifest.path();
    pq_sign_with_password(manifest_path, "mypassword").unwrap();
    let wrong_pubkey = "a".repeat(3904); // 1952 bytes hex = 3904 chars
    let result = pq_verify_sig(manifest_path, &wrong_pubkey).unwrap();
    assert!(!result, "wrong expected pubkey must fail");
}

use assert_cmd::Command;

#[test]
fn test_cli_pq_sign_creates_pqsig() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("evidence.hash");
    std::fs::write(&manifest, "%%blazehash-1.0\nblake3,path\nabc,/foo\n").unwrap();

    let mut cmd = Command::cargo_bin("blazehash").unwrap();
    cmd.env("BLAZEHASH_SIGN_PASSWORD", "testpass")
        .arg("pq-sign")
        .arg(&manifest);
    cmd.assert().success();

    let pqsig = dir.path().join("evidence.hash.pqsig");
    assert!(pqsig.exists(), ".pqsig file must exist after pq-sign");
}

#[test]
fn test_cli_pq_verify_sig_valid() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("evidence.hash");
    std::fs::write(&manifest, "%%blazehash-1.0\nblake3,path\nabc,/foo\n").unwrap();

    // First sign
    let mut cmd = Command::cargo_bin("blazehash").unwrap();
    cmd.env("BLAZEHASH_SIGN_PASSWORD", "testpass")
        .arg("pq-sign")
        .arg(&manifest);
    cmd.assert().success();

    // Then verify
    let mut cmd = Command::cargo_bin("blazehash").unwrap();
    cmd.arg("pq-verify-sig").arg(&manifest);
    cmd.assert().success();
}
