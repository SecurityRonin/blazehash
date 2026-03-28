use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn e2e_hash_and_audit() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("file1.txt"), b"content one").unwrap();
    fs::write(dir.path().join("file2.txt"), b"content two").unwrap();
    let manifest = dir.path().join("manifest.hash");

    // Step 1: Hash the directory
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-r")
        .arg("-c")
        .arg("blake3,sha256")
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success();

    // Verify manifest exists and has content
    let contents = fs::read_to_string(&manifest).unwrap();
    assert!(contents.contains("HASHDEEP-1.0"));
    assert!(contents.contains("file1.txt"));
    assert!(contents.contains("file2.txt"));
    assert!(contents.contains("blake3"));
    assert!(contents.contains("sha256"));

    // Step 2: Audit should show all matched
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-a")
        .arg("-k")
        .arg(manifest.to_str().unwrap())
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn e2e_bare_output() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-b")
        .arg(dir.path().join("test.txt").to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("HASHDEEP"));
    assert!(stdout.contains("test.txt"));
}

#[test]
fn e2e_csv_format() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("csv")
        .arg(dir.path().join("test.txt").to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("size,blake3,filename"));
}

#[test]
fn e2e_json_format() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("json")
        .arg(dir.path().join("test.txt").to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array());
}
