use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, "## case-id: CASE-001\n## examiner: Alice\n## algorithm: blake3\nblake3  aaaa  file1.txt\nblake3  bbbb  file2.txt\n").unwrap();
    p
}

#[test]
fn test_info_shows_case_id() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("CASE-001"), "should display case-id value");
}

#[test]
fn test_info_shows_entry_count() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains('2'), "should show 2 entries");
}

#[test]
fn test_info_json_output() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", m.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    let v: serde_json::Value = serde_json::from_str(&s).expect("should be valid JSON");
    assert_eq!(v["headers"]["case-id"], "CASE-001");
    assert_eq!(v["entries"], 2);
}

#[test]
fn test_info_shows_algorithms() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("blake3"), "should list algorithms used");
}

#[test]
fn test_info_missing_manifest_fails() {
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", "/no/such/file.hash"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
