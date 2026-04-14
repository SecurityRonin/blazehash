use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const MANIFEST_CONTENT: &str = "\
## case: PATH-ONLY-TEST
%% created: 2026-04-14
sha256  aaaa1111111111111111111111111111111111111111111111111111111111111111  /evidence/file1.exe
blake3  bbbb2222222222222222222222222222222222222222222222222222222222222222  /docs/readme.txt
sha256  cccc3333333333333333333333333333333333333333333333333333333333333333  /images/photo.jpg
";

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    fs::write(&p, MANIFEST_CONTENT).unwrap();
    p
}

#[test]
fn test_path_only_emits_paths_one_per_line() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["path-only", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "exit code must be 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3, "expected exactly 3 output lines, got: {stdout:?}");
    assert!(lines[0].starts_with('/'), "each line must be a path, got: {}", lines[0]);
    assert!(lines[1].starts_with('/'), "each line must be a path, got: {}", lines[1]);
    assert!(lines[2].starts_with('/'), "each line must be a path, got: {}", lines[2]);
}

#[test]
fn test_path_only_skips_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["path-only", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("##"),
        "output must not contain ## headers, got: {stdout:?}"
    );
    assert!(
        !stdout.contains("%%"),
        "output must not contain %% headers, got: {stdout:?}"
    );
}

#[test]
fn test_path_only_no_algo_or_hash_in_output() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["path-only", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("sha256"),
        "output must not contain algorithm name, got: {stdout:?}"
    );
    assert!(
        !stdout.contains("aaaa111"),
        "output must not contain hash value, got: {stdout:?}"
    );
}

#[test]
fn test_path_only_missing_manifest_fails() {
    let dir = TempDir::new().unwrap();
    let nonexistent = dir.path().join("does_not_exist.hash");
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["path-only", nonexistent.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "must exit non-zero for missing manifest"
    );
}

#[test]
fn test_path_only_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("paths.txt");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "path-only",
            manifest.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3, "output file must have exactly 3 lines, got: {content:?}");
}
