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
fn test_filter_by_path_glob() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("filtered.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "filter",
            manifest.to_str().unwrap(),
            "--include",
            "docs/**",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("contract.pdf"),
        "expected docs/contract.pdf"
    );
    assert!(content.contains("notes.txt"), "expected docs/notes.txt");
    assert!(!content.contains("photo.jpg"), "images/ should be excluded");
    assert!(
        !content.contains("README.md"),
        "README.md should be excluded"
    );
}

#[test]
fn test_filter_by_algorithm() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("filtered.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "filter",
            manifest.to_str().unwrap(),
            "--algo",
            "blake3",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("blake3"), "should keep blake3 entries");
    assert!(
        !content.contains("sha256"),
        "should not keep sha256 entries"
    );
}

#[test]
fn test_filter_stdout_when_no_output() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["filter", manifest.to_str().unwrap(), "--include", "*.md"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("README.md"),
        "README.md should pass *.md filter"
    );
    assert!(!stdout.contains("contract.pdf"), "PDF should be excluded");
}

#[test]
fn test_filter_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["filter", manifest.to_str().unwrap(), "--include", "docs/**"])
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
fn test_filter_no_match_outputs_only_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "filter",
            manifest.to_str().unwrap(),
            "--include",
            "nonexistent/**",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("sha256") && !stdout.contains("blake3"),
        "no hash lines when no match, got:\n{stdout}"
    );
}
