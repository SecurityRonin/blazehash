use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("evidence.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  unchanged.txt\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  modified.txt\n",
        "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  removed.txt\n",
    )).unwrap();
    p
}

fn write_patch(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("changes.diff");
    fs::write(&p, concat!(
        "--- evidence.hash\n",
        "+++ evidence.hash\n",
        "-sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  modified.txt\n",
        "+sha256  9999999999999999999999999999999999999999999999999999999999999999  modified.txt\n",
        "-sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  removed.txt\n",
        "+sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  added.txt\n",
    )).unwrap();
    p
}

#[test]
fn test_apply_patch_removes_minus_lines() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success(), "apply-patch failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "removed entry must be gone");
    assert!(!stdout.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        "modified old hash must be gone");
}

#[test]
fn test_apply_patch_adds_plus_lines() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("added.txt"), "added entry must appear");
    assert!(stdout.contains("9999999999999999999999999999999999999999999999999999999999999999"),
        "modified new hash must appear");
}

#[test]
fn test_apply_patch_preserves_unchanged_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("unchanged.txt"), "unchanged entry must be preserved");
    assert!(stdout.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "unchanged hash must be preserved");
}

#[test]
fn test_apply_patch_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## case: CASE-001"), "headers must be preserved");
}

#[test]
fn test_apply_patch_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out_path = dir.path().join("updated.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap(),
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("unchanged.txt"));
    assert!(content.contains("added.txt"));
}
