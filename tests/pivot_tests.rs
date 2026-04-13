use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "%% created: 2026-04-14\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /evidence/file1.bin\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /evidence/file2.bin\n",
        "blake3  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  /evidence/file1.bin\n",
    )).unwrap();
    p
}

/// 1. Basic: emits `<hash>  <path>` pairs (two spaces) for the selected algo
#[test]
fn test_pivot_emits_hash_path_pairs() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["pivot", manifest.to_str().unwrap(), "--pivot-algo", "sha256"])
        .output().unwrap();
    assert!(out.status.success(), "exit code should be 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Two entries for sha256
    assert!(
        stdout.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /evidence/file1.bin"),
        "expected sha256 hash + two spaces + path for file1, got:\n{stdout}"
    );
    assert!(
        stdout.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /evidence/file2.bin"),
        "expected sha256 hash + two spaces + path for file2, got:\n{stdout}"
    );
}

/// 2. Only the requested algorithm's entries appear; others are silently skipped
#[test]
fn test_pivot_skips_other_algos() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["pivot", manifest.to_str().unwrap(), "--pivot-algo", "sha256"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // blake3 hash must NOT appear
    assert!(
        !stdout.contains("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "blake3 hash must not appear in sha256 pivot, got:\n{stdout}"
    );
    // sha256 hashes must appear
    assert!(stdout.contains("aaaaaaaaaaaaaaaaaaaaaa"), "sha256 hash for file1 expected");
}

/// 3. Algorithm matching is case-insensitive
#[test]
fn test_pivot_case_insensitive_algo() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["pivot", manifest.to_str().unwrap(), "--pivot-algo", "SHA256"])
        .output().unwrap();
    assert!(out.status.success(), "exit code should be 0 even with uppercase algo");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "SHA256 (uppercase) should match sha256 entries, got:\n{stdout}"
    );
}

/// 4. Output to file via -o
#[test]
fn test_pivot_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("pivot.txt");
    Command::cargo_bin("blazehash").unwrap()
        .args([
            "pivot", manifest.to_str().unwrap(),
            "--pivot-algo", "sha256",
            "-o", out_path.to_str().unwrap(),
        ])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /evidence/file1.bin"),
        "output file must contain sha256 hash + two spaces + path, got:\n{content}"
    );
    assert!(
        content.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /evidence/file2.bin"),
        "output file must contain second sha256 entry, got:\n{content}"
    );
    // Header lines must NOT appear in the sumfile output
    assert!(
        !content.contains("## case:"),
        "header lines must not appear in pivot output, got:\n{content}"
    );
}

/// 5. Missing manifest exits non-zero
#[test]
fn test_pivot_missing_manifest_fails() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("nonexistent.hash");
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["pivot", missing.to_str().unwrap(), "--pivot-algo", "sha256"])
        .output().unwrap();
    assert!(
        !out.status.success(),
        "missing manifest must exit non-zero, got: {:?}", out.status
    );
}
