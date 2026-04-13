use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir, n: usize) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    let mut content = String::from("## algorithm: blake3\n");
    for i in 1..=n {
        content.push_str(&format!("blake3  {:064x}  file{i}.txt\n", i));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_count_returns_correct_number() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 7);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["count", m.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    assert_eq!(String::from_utf8_lossy(&out).trim(), "7");
}

#[test]
fn test_count_ignores_header_lines() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("with_headers.hash");
    fs::write(&p, "## case-id: X\n## examiner: Y\nblake3  aaaa  a.txt\nblake3  bbbb  b.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["count", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    assert_eq!(String::from_utf8_lossy(&out).trim(), "2");
}

#[test]
fn test_count_empty_manifest_returns_zero() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("empty.hash");
    fs::write(&p, "## algorithm: blake3\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["count", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    assert_eq!(String::from_utf8_lossy(&out).trim(), "0");
}

#[test]
fn test_count_missing_manifest_fails() {
    Command::cargo_bin("blazehash").unwrap()
        .args(["count", "/no/such.hash"])
        .assert().failure();
}
