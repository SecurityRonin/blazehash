use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/contract.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  images/photo.jpg\n",
        "blake3  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  docs/notes.txt\n",
        "sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  README.md\n",
    )).unwrap();
    p
}

#[test]
fn test_search_by_path_substring() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "search",
            manifest.to_str().unwrap(),
            "--search-path",
            "docs/",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("contract.pdf"),
        "docs/contract.pdf must match"
    );
    assert!(stdout.contains("notes.txt"), "docs/notes.txt must match");
    assert!(!stdout.contains("photo.jpg"), "images/ must not match");
}

#[test]
fn test_search_by_hash_prefix() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["search", manifest.to_str().unwrap(), "--hash", "aaa"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("contract.pdf"),
        "hash prefix 'aaa' must match contract.pdf"
    );
    assert!(
        !stdout.contains("photo.jpg"),
        "hash 'bbb...' must not match"
    );
}

#[test]
fn test_search_no_match_exits_nonzero_or_empty() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "search",
            manifest.to_str().unwrap(),
            "--search-path",
            "nonexistent",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data_lines: Vec<_> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert!(
        data_lines.is_empty() || !out.status.success(),
        "no-match should produce empty output or nonzero exit"
    );
}

#[test]
fn test_search_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "search",
            manifest.to_str().unwrap(),
            "--search-path",
            "docs/",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("## case: CASE-001"),
        "headers must be preserved"
    );
}

#[test]
fn test_search_case_insensitive_flag() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "search",
            manifest.to_str().unwrap(),
            "--search-path",
            "readme",
            "--ignore-case",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("README.md"),
        "case-insensitive match must find README.md"
    );
}
