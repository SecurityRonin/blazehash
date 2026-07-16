use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const MANIFEST_CONTENT: &str = "\
## case: HASH-ONLY-TEST
sha256  aaaa1111111111111111111111111111111111111111111111111111111111111111  /evidence/file1.exe
sha256  bbbb2222222222222222222222222222222222222222222222222222222222222222  /docs/readme.txt
blake3  cccc3333333333333333333333333333333333333333333333333333333333333333  /images/photo.jpg
";

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    fs::write(&p, MANIFEST_CONTENT).unwrap();
    p
}

#[test]
fn test_hash_only_emits_hashes_for_algo() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "hash-only",
            manifest.to_str().unwrap(),
            "--hash-only-algo",
            "sha256",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "exit code must be 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        2,
        "expected exactly 2 lines for sha256, got: {stdout:?}"
    );
    assert!(
        lines.contains(&"aaaa1111111111111111111111111111111111111111111111111111111111111111"),
        "sha256 hash aaaa1111... must be present, got: {stdout:?}"
    );
    assert!(
        lines.contains(&"bbbb2222222222222222222222222222222222222222222222222222222222222222"),
        "sha256 hash bbbb2222... must be present, got: {stdout:?}"
    );
}

#[test]
fn test_hash_only_skips_other_algos() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "hash-only",
            manifest.to_str().unwrap(),
            "--hash-only-algo",
            "sha256",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "exit code must be 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("cccc3333"),
        "blake3 hash cccc3333 must NOT appear in sha256-filtered output, got: {stdout:?}"
    );
}

#[test]
fn test_hash_only_algo_case_insensitive() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "hash-only",
            manifest.to_str().unwrap(),
            "--hash-only-algo",
            "SHA256",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "exit code must be 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        2,
        "SHA256 (uppercase) must match sha256 entries, got: {stdout:?}"
    );
    assert!(
        lines.contains(&"aaaa1111111111111111111111111111111111111111111111111111111111111111"),
        "sha256 hash aaaa1111... must be present, got: {stdout:?}"
    );
}

#[test]
fn test_hash_only_no_algo_filter_emits_all_hashes() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["hash-only", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "exit code must be 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        3,
        "no filter must emit all 3 hashes, got: {stdout:?}"
    );
    assert!(
        lines.contains(&"aaaa1111111111111111111111111111111111111111111111111111111111111111"),
        "sha256 hash aaaa1111... must be present"
    );
    assert!(
        lines.contains(&"bbbb2222222222222222222222222222222222222222222222222222222222222222"),
        "sha256 hash bbbb2222... must be present"
    );
    assert!(
        lines.contains(&"cccc3333333333333333333333333333333333333333333333333333333333333333"),
        "blake3 hash cccc3333... must be present"
    );
}

#[test]
fn test_hash_only_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("hashes.txt");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "hash-only",
            manifest.to_str().unwrap(),
            "--hash-only-algo",
            "blake3",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "output file must have exactly 1 line (blake3), got: {content:?}"
    );
    assert!(
        lines.contains(&"cccc3333333333333333333333333333333333333333333333333333333333333333"),
        "blake3 hash cccc3333... must be in output file, got: {content:?}"
    );
    assert!(
        !content.contains("aaaa1111"),
        "sha256 hashes must NOT appear in blake3-filtered output file, got: {content:?}"
    );
}
