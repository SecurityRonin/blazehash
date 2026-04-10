use assert_cmd::Command;
use predicates;
use tempfile::tempdir;
use std::fs;

#[test]
fn test_sign_creates_sig_sidecar() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .assert().success();

    assert!(dir.path().join("manifest.hash.sig").exists(), ".sig file not created");
}

#[test]
fn test_verify_sig_roundtrip() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

    // Sign
    let sign_output = Command::cargo_bin("blazehash").unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output().unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    let pubkey = stderr.lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not printed to stderr");

    // Verify
    Command::cargo_bin("blazehash").unwrap()
        .args(["verify-sig", manifest.to_str().unwrap(), "--expected-pubkey", pubkey])
        .assert().success()
        .stderr(predicates::str::contains("[+]"));
}

#[test]
fn test_verify_sig_fails_on_tampered_manifest() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

    let sign_output = Command::cargo_bin("blazehash").unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output().unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    let pubkey = stderr.lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not printed to stderr");

    // Tamper
    fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,TAMPERED,/f.bin\n").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .args(["verify-sig", manifest.to_str().unwrap(), "--expected-pubkey", pubkey])
        .assert().failure()
        .stderr(predicates::str::contains("[!]"));
}
