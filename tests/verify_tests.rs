use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_file_and_manifest(
    dir: &TempDir,
    content: &[u8],
    algo: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let file_path = dir.path().join("evidence.bin");
    fs::write(&file_path, content).unwrap();
    let hash_out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--algo", algo, file_path.to_str().unwrap()])
        .output()
        .unwrap();
    let manifest_path = dir.path().join("evidence.hash");
    fs::write(&manifest_path, &hash_out.stdout).unwrap();
    (file_path, manifest_path)
}

#[test]
fn test_verify_passes_when_file_matches() {
    let dir = TempDir::new().unwrap();
    let (_file, manifest) = write_file_and_manifest(&dir, b"hello world", "blake3");
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["verify", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "verify should exit 0 when all match");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PASS"), "should print PASS");
}

#[test]
fn test_verify_fails_when_file_modified() {
    let dir = TempDir::new().unwrap();
    let (file, manifest) = write_file_and_manifest(&dir, b"original content", "blake3");
    fs::write(&file, b"tampered content").unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["verify", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "verify should exit 1 on mismatch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("FAIL"),
        "should print FAIL for tampered file"
    );
}

#[test]
fn test_verify_fails_when_file_missing() {
    let dir = TempDir::new().unwrap();
    let (file, manifest) = write_file_and_manifest(&dir, b"data", "blake3");
    fs::remove_file(&file).unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["verify", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "verify should exit 1 when file missing"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("MISS") || stdout.contains("FAIL"),
        "should indicate missing file"
    );
}

#[test]
fn test_verify_algo_filter() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("data.bin");
    fs::write(&file_path, b"test data").unwrap();
    let hash_out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--algo", "blake3,sha256", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    let manifest_path = dir.path().join("data.hash");
    fs::write(&manifest_path, &hash_out.stdout).unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "verify",
            manifest_path.to_str().unwrap(),
            "--verify-algo",
            "blake3",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PASS"));
}

#[test]
fn test_verify_missing_manifest_fails() {
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["verify", "/nonexistent/path.hash"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
