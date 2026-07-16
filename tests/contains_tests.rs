use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const MANIFEST_CONTENT: &str = "\
## case: CONTAINS-TEST\n\
sha256  deadbeef11111111111111111111111111111111111111111111111111111111  /evidence/malware.exe\n\
sha256  cafe1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab  /docs/readme.txt\n\
blake3  aaaa5678901234567890123456789012345678901234567890123456789012345  /images/photo.jpg\n\
";

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    fs::write(&p, MANIFEST_CONTENT).unwrap();
    p
}

#[test]
fn test_contains_found_by_path_substring() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["contains", manifest.to_str().unwrap(), "malware"])
        .assert()
        .success()
        .stdout(predicates::str::contains("FOUND"))
        .stdout(predicates::str::contains("/evidence/malware.exe"));
}

#[test]
fn test_contains_found_by_hash_substring() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["contains", manifest.to_str().unwrap(), "deadbeef"])
        .assert()
        .success()
        .stdout(predicates::str::contains("FOUND"));
}

#[test]
fn test_contains_not_found_exits_one() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["contains", manifest.to_str().unwrap(), "xyz_no_match"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "expected non-zero exit for not-found"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("NOT FOUND"),
        "expected 'NOT FOUND' in stdout, got: {stdout}"
    );
}

#[test]
fn test_contains_missing_manifest_errors() {
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["contains", "/no/such/path.hash", "someterm"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "expected non-zero exit for missing manifest"
    );
    assert!(
        !output.stderr.is_empty(),
        "expected non-empty stderr for missing manifest"
    );
}

#[test]
fn test_contains_multiple_matches_all_printed() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("multi.hash");
    fs::write(
        &p,
        "## case: MULTI\n\
         sha256  aabbcc1111111111111111111111111111111111111111111111111111111111  /evidence/file1.bin\n\
         sha256  ddeeff2222222222222222222222222222222222222222222222222222222222  /evidence/file2.bin\n\
         blake3  001122333333333333333333333333333333333333333333333333333333333  /other/notes.txt\n",
    )
    .unwrap();
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["contains", p.to_str().unwrap(), "evidence"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "expected exit 0 when matches found"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("/evidence/file1.bin"),
        "expected /evidence/file1.bin in stdout, got: {stdout}"
    );
    assert!(
        stdout.contains("/evidence/file2.bin"),
        "expected /evidence/file2.bin in stdout, got: {stdout}"
    );
}
