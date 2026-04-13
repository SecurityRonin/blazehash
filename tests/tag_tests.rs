use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("m.hash");
    fs::write(&p, "## case-id: OLD\n## examiner: Alice\nblake3  aaaa  file.txt\n").unwrap();
    p
}

#[test]
fn test_tag_set_adds_new_header() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["tag", m.to_str().unwrap(), "--set", "reviewed-by=Bob"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## reviewed-by: Bob"), "new header should appear");
}

#[test]
fn test_tag_set_updates_existing_header() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["tag", m.to_str().unwrap(), "--set", "case-id=NEW-999"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## case-id: NEW-999"), "header should be updated");
    assert!(!s.contains("OLD"), "old value should be gone");
}

#[test]
fn test_tag_unset_removes_header() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["tag", m.to_str().unwrap(), "--unset", "examiner"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(!s.contains("examiner"), "unset header should be removed");
}

#[test]
fn test_tag_preserves_data_entries() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["tag", m.to_str().unwrap(), "--set", "foo=bar"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("blake3  aaaa  file.txt"), "data entries must be preserved");
}

#[test]
fn test_tag_output_to_file() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out_file = dir.path().join("tagged.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["tag", m.to_str().unwrap(), "--set", "status=reviewed",
               "-o", out_file.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("## status: reviewed"));
}
