use assert_cmd::Command;
use blazehash::signing;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_sign_creates_sig_sidecar() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .assert()
        .success();

    assert!(
        dir.path().join("manifest.hash.sig").exists(),
        ".sig file not created"
    );
}

#[test]
fn test_verify_sig_roundtrip() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    // Sign
    let sign_output = Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    let pubkey = stderr
        .lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not printed to stderr");

    // Verify
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "verify-sig",
            manifest.to_str().unwrap(),
            "--expected-pubkey",
            pubkey,
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("[+]"));
}

#[test]
fn test_verify_sig_fails_on_tampered_manifest() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    let sign_output = Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    let pubkey = stderr
        .lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not printed to stderr");

    // Tamper
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,TAMPERED,/f.bin\n",
    )
    .unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "verify-sig",
            manifest.to_str().unwrap(),
            "--expected-pubkey",
            pubkey,
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("[!]"));
}

#[test]
fn test_verify_sig_returns_true_for_valid_sig() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    let sign_output = Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    let pubkey = stderr
        .lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not in stderr");

    let result = signing::verify_sig(&manifest, pubkey).unwrap();
    assert!(result, "verify_sig should return true for valid sig");
}

#[test]
fn test_verify_sig_returns_false_for_tampered_manifest() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    let sign_output = Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    let pubkey = stderr
        .lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not in stderr");

    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,TAMPERED,/f.bin\n",
    )
    .unwrap();

    let result = signing::verify_sig(&manifest, pubkey).unwrap();
    assert!(
        !result,
        "verify_sig should return false for tampered manifest"
    );
}

#[test]
fn test_auto_verify_sidecar_no_sig() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();
    // No .sig file — should return Ok(false)
    let result = signing::auto_verify_sidecar(&manifest, None).unwrap();
    assert!(!result, "expected Ok(false) when no .sig exists");
}

#[test]
fn test_auto_verify_sidecar_valid() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    // Sign to produce .sig
    let sign_output = Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    let pubkey = stderr
        .lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not in stderr");

    // auto_verify_sidecar with correct pubkey — should return Ok(true)
    let result = signing::auto_verify_sidecar(&manifest, Some(pubkey)).unwrap();
    assert!(result, "expected Ok(true) for valid sig");
}

#[test]
fn test_auto_verify_sidecar_invalid() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    // Sign, then tamper
    let sign_output = Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    let pubkey = stderr
        .lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not in stderr");

    // Tamper the manifest
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,TAMPERED,/f.bin\n",
    )
    .unwrap();

    // auto_verify_sidecar should return Err (invalid sig)
    let result = signing::auto_verify_sidecar(&manifest, Some(pubkey));
    assert!(result.is_err(), "expected Err for tampered manifest");
}

#[test]
fn test_sign_creates_pub_file() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .assert()
        .success();

    let pub_path = dir.path().join("manifest.hash.pub");
    assert!(pub_path.exists(), ".pub file not created");

    let pubkey = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(
        pubkey.trim().len(),
        64,
        "pubkey should be 64 hex chars, got: {pubkey}"
    );
}

#[test]
fn test_cosign_creates_msig_file() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    std::fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-1")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();

    let msig_path = dir.path().join("manifest.hash.msig");
    assert!(msig_path.exists(), ".msig file not created");

    let content = std::fs::read_to_string(&msig_path).unwrap();
    let msig: serde_json::Value = serde_json::from_str(&content).expect("msig must be valid JSON");
    let sigs = msig["signatures"]
        .as_array()
        .expect("must have signatures array");
    assert_eq!(
        sigs.len(),
        1,
        "first cosign should create 1 signature entry"
    );
}

#[test]
fn test_cosign_appends_second_signature() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    std::fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    // First cosign
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-1")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();

    // Second cosign (different password = different key)
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-2")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();

    let msig_path = dir.path().join("manifest.hash.msig");
    let content = std::fs::read_to_string(&msig_path).unwrap();
    let msig: serde_json::Value = serde_json::from_str(&content).unwrap();
    let sigs = msig["signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), 2, "second cosign should add 2nd signature");
}

#[test]
fn test_verify_msig_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    std::fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    // Two cosigns
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-1")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-2")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();

    // Verify with threshold=2 -- should pass
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "verify-msig",
            manifest.to_str().unwrap(),
            "--threshold",
            "2",
        ])
        .assert()
        .success();

    // Verify with threshold=3 -- should fail (only 2 sigs)
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "verify-msig",
            manifest.to_str().unwrap(),
            "--threshold",
            "3",
        ])
        .assert()
        .failure();
}

#[test]
fn test_pub_file_matches_stderr_pubkey() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let stderr_pubkey = stderr
        .lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not in stderr");

    let pub_file_contents = fs::read_to_string(dir.path().join("manifest.hash.pub")).unwrap();
    assert_eq!(
        stderr_pubkey,
        pub_file_contents.trim(),
        "stderr pubkey must match .pub file contents"
    );
}
