use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_checksum_outputs_hash_and_path() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("case.hash");
    fs::write(&p, "blake3  aaaa  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("blake3"));
    assert!(s.contains("case.hash"));
}

#[test]
fn test_checksum_is_deterministic() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  file.txt\n").unwrap();
    let r1 = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .output()
        .unwrap()
        .stdout;
    let r2 = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(r1, r2);
}

#[test]
fn test_checksum_changes_when_file_changes() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  file.txt\n").unwrap();
    let h1 = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .output()
        .unwrap()
        .stdout;
    fs::write(&p, "blake3  bbbb  file.txt\n").unwrap();
    let h2 = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .output()
        .unwrap()
        .stdout;
    assert_ne!(h1, h2);
}

#[test]
fn test_checksum_json_output() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["checksum", p.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
    assert!(v["hash"].as_str().is_some());
    assert!(v["path"].as_str().is_some());
}

#[test]
fn test_checksum_missing_file_fails() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["checksum", "/no/such.hash"])
        .assert()
        .failure();
}
