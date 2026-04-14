use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest_a(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("manifest_a.hash");
    fs::write(&p, concat!(
        "# manifest_a.hash\n",
        "## case: A\n",
        "sha256  aaaa1111111111111111111111111111111111111111111111111111111111111111  /a/file1.txt\n",
        "sha256  bbbb2222222222222222222222222222222222222222222222222222222222222222  /a/file2.txt\n",
        "sha256  cccc3333333333333333333333333333333333333333333333333333333333333333  /shared.txt\n",
    )).unwrap();
    p
}

fn write_manifest_b(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("manifest_b.hash");
    fs::write(&p, concat!(
        "# manifest_b.hash\n",
        "## case: B\n",
        "sha256  dddd4444444444444444444444444444444444444444444444444444444444444444  /b/file3.txt\n",
        "sha256  eeee5555555555555555555555555555555555555555555555555555555555555555  /b/file4.txt\n",
        "sha256  cccc3333333333333333333333333333333333333333333333333333333333333333  /shared.txt\n",
    )).unwrap();
    p
}

#[test]
fn test_sym_diff_finds_a_only_entries() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sym-diff", a.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success(), "sym-diff must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("/a/file1.txt"), "/a/file1.txt must appear (A-only)");
    assert!(stdout.contains("/a/file2.txt"), "/a/file2.txt must appear (A-only)");
}

#[test]
fn test_sym_diff_finds_b_only_entries() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sym-diff", a.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success(), "sym-diff must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("/b/file3.txt"), "/b/file3.txt must appear (B-only)");
    assert!(stdout.contains("/b/file4.txt"), "/b/file4.txt must appear (B-only)");
}

#[test]
fn test_sym_diff_excludes_shared_entries() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sym-diff", a.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success(), "sym-diff must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("/shared.txt"), "/shared.txt must NOT appear (in both manifests)");
}

#[test]
fn test_sym_diff_missing_manifest_fails() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does_not_exist.hash");
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sym-diff", missing.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    assert!(!out.status.success(), "sym-diff must fail when first manifest is missing");
}

#[test]
fn test_sym_diff_output_to_file() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out_path = dir.path().join("sym_diff.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["sym-diff", a.to_str().unwrap(), b.to_str().unwrap(),
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("/a/file1.txt"), "output file must contain A-only entry");
    assert!(content.contains("/a/file2.txt"), "output file must contain second A-only entry");
    assert!(content.contains("/b/file3.txt"), "output file must contain B-only entry");
    assert!(content.contains("/b/file4.txt"), "output file must contain second B-only entry");
    assert!(!content.contains("/shared.txt"), "output file must NOT contain shared entry");
}
