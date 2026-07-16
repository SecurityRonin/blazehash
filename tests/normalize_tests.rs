use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /mnt/evidence/docs/contract.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /mnt/evidence/images/photo.jpg\n",
    )).unwrap();
    p
}

#[test]
fn test_normalize_strip_prefix() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "normalize",
            manifest.to_str().unwrap(),
            "--strip-prefix",
            "/mnt/evidence/",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("docs/contract.pdf"), "should strip prefix");
    assert!(!stdout.contains("/mnt/evidence/"), "prefix must be removed");
}

#[test]
fn test_normalize_add_prefix() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "normalize",
            manifest.to_str().unwrap(),
            "--add-prefix",
            "/case/001/",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("/case/001/"), "should add prefix");
}

#[test]
fn test_normalize_strip_and_add_prefix() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "normalize",
            manifest.to_str().unwrap(),
            "--strip-prefix",
            "/mnt/evidence/",
            "--add-prefix",
            "/case/001/",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("/case/001/docs/contract.pdf"),
        "strip+add should rebase paths"
    );
}

#[test]
fn test_normalize_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "normalize",
            manifest.to_str().unwrap(),
            "--strip-prefix",
            "/mnt/",
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
fn test_normalize_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("normalized.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "normalize",
            manifest.to_str().unwrap(),
            "--strip-prefix",
            "/mnt/evidence/",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("docs/contract.pdf"));
    assert!(!content.contains("/mnt/evidence/"));
}
