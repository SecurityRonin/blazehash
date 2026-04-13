use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir, name: &str, header: &str, entries: &[(&str, &str)]) -> std::path::PathBuf {
    let p = dir.path().join(name);
    let mut content = format!("{header}\n");
    for (hash, path) in entries {
        content.push_str(&format!("blake3  {hash}  {path}\n"));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_cat_combines_entries_from_both() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## case-id: A", &[("aaaa", "a.txt")]);
    let b = write_manifest(&dir, "b.hash", "## case-id: B", &[("bbbb", "b.txt")]);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("a.txt"));
    assert!(s.contains("b.txt"));
}

#[test]
fn test_cat_headers_from_first_only() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## case-id: FIRST", &[("aaaa", "a.txt")]);
    let b = write_manifest(&dir, "b.hash", "## case-id: SECOND", &[("bbbb", "b.txt")]);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("FIRST"));
    assert!(!s.contains("SECOND"));
}

#[test]
fn test_cat_output_to_file() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## x: 1", &[("aaaa", "a.txt")]);
    let b = write_manifest(&dir, "b.hash", "## x: 2", &[("bbbb", "b.txt")]);
    let out_file = dir.path().join("merged.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap(), b.to_str().unwrap(),
               "-o", out_file.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("a.txt") && content.contains("b.txt"));
}

#[test]
fn test_cat_requires_at_least_two_inputs() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## x: 1", &[("aaaa", "a.txt")]);
    Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap()])
        .assert().failure();
}

#[test]
fn test_cat_three_manifests() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## h: 1", &[("aaaa", "a.txt")]);
    let b = write_manifest(&dir, "b.hash", "## h: 2", &[("bbbb", "b.txt")]);
    let c = write_manifest(&dir, "c.hash", "## h: 3", &[("cccc", "c.txt")]);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap(), b.to_str().unwrap(), c.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("a.txt") && s.contains("b.txt") && s.contains("c.txt"));
}
