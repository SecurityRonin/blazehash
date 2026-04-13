use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

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
fn test_stats_total_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stats", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("4"), "expected 4 in output, got:\n{stdout}");
}

#[test]
fn test_stats_algorithm_breakdown() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stats", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sha256") || stdout.contains("SHA-256"), "expected sha256 breakdown");
    assert!(stdout.contains("blake3") || stdout.contains("BLAKE3"), "expected blake3 breakdown");
}

#[test]
fn test_stats_extension_breakdown() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stats", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(".pdf") || stdout.contains("pdf"), "expected .pdf in output");
}

#[test]
fn test_stats_json_output() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stats", manifest.to_str().unwrap(), "--json"])
        .output().unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("output should be valid JSON");
    assert!(json["total_entries"].as_u64().unwrap_or(0) > 0);
    assert!(json["algorithms"].is_object() || json["algorithms"].is_array());
}

#[test]
fn test_stats_missing_manifest_fails() {
    Command::cargo_bin("blazehash").unwrap()
        .args(["stats", "/nonexistent/file.hash"])
        .assert().failure();
}
