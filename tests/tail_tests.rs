use assert_cmd::prelude::*;
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir, n: usize) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    let mut content = String::from("## algorithm: blake3\n");
    for i in 1..=n {
        content.push_str(&format!("blake3  {:064x}  file{i:03}.txt\n", i));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_tail_default_10() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 15);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tail", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    let data_lines: Vec<_> = s
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('%') && !l.is_empty())
        .collect();
    assert_eq!(
        data_lines.len(),
        10,
        "default tail should return 10 entries"
    );
    assert!(
        data_lines.last().unwrap().contains("file015.txt"),
        "last entry should be file015"
    );
}

#[test]
fn test_tail_count_3() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 10);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tail", m.to_str().unwrap(), "--count", "3"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    let data_lines: Vec<_> = s
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('%') && !l.is_empty())
        .collect();
    assert_eq!(data_lines.len(), 3);
    assert!(data_lines.last().unwrap().contains("file010.txt"));
}

#[test]
fn test_tail_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tail", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(
        s.contains("## algorithm: blake3"),
        "headers must be preserved"
    );
}

#[test]
fn test_tail_count_larger_than_manifest_returns_all() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 4);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tail", m.to_str().unwrap(), "--count", "100"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    let data_lines: Vec<_> = s
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('%') && !l.is_empty())
        .collect();
    assert_eq!(
        data_lines.len(),
        4,
        "should return all 4 when count > total"
    );
}

#[test]
fn test_tail_output_to_file() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out_file = dir.path().join("out.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "tail",
            m.to_str().unwrap(),
            "-o",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("file005.txt"));
}
