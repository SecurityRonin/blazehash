use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_uniq_removes_duplicate_paths() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  file.txt\nblake3  bbbb  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let data: Vec<_> = s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 1);
}

#[test]
fn test_uniq_keeps_last_occurrence() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    // Use full 64-char hashes so the manifest line parses correctly
    fs::write(&p, concat!(
        "blake3  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  file.txt\n",
        "blake3  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  file.txt\n",
    )).unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("bbbb"), "should keep the last occurrence");
    assert!(!s.contains("aaaa"), "should discard the first occurrence");
}

#[test]
fn test_uniq_preserves_unique_entries() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  a.txt\nblake3  bbbb  b.txt\nblake3  cccc  c.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let data: usize = String::from_utf8_lossy(&out).lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .count();
    assert_eq!(data, 3);
}

#[test]
fn test_uniq_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "## case-id: X\nblake3  aaaa  a.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    assert!(String::from_utf8_lossy(&out).contains("## case-id: X"));
}

#[test]
fn test_uniq_output_to_file() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  dup.txt\nblake3  bbbb  dup.txt\n").unwrap();
    let out_file = dir.path().join("out.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap(), "-o", out_file.to_str().unwrap()])
        .assert().success();
    let data_count = fs::read_to_string(&out_file).unwrap().lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .count();
    assert_eq!(data_count, 1);
}
