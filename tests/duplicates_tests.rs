use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("evidence.hash");
    fs::write(
        &p,
        concat!(
            "## case: DUP-TEST\n",
            "sha256  aaaa1111111111111111111111111111111111111111111111111111111111111111  /evidence/file1.exe\n",
            "sha256  bbbb2222222222222222222222222222222222222222222222222222222222222222  /evidence/file2.bin\n",
            "sha256  aaaa1111111111111111111111111111111111111111111111111111111111111111  /copies/file3.dll\n",
            "sha256  bbbb2222222222222222222222222222222222222222222222222222222222222222  /copies/file4.txt\n",
            "sha256  cccc3333333333333333333333333333333333333333333333333333333333333333  /unique/file5.jpg\n",
        ),
    )
    .unwrap();
    p
}

#[test]
fn test_duplicates_finds_shared_hashes() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["duplicates", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("/evidence/file1.exe"),
        "should include file1.exe: {stdout}"
    );
    assert!(
        stdout.contains("/copies/file3.dll"),
        "should include file3.dll: {stdout}"
    );
}

#[test]
fn test_duplicates_emits_all_occurrences() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["duplicates", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        4,
        "should emit exactly 4 lines (both pairs): got {lines:?}"
    );
}

#[test]
fn test_duplicates_excludes_unique_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["duplicates", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("/unique/file5.jpg"),
        "unique file must NOT appear in output: {stdout}"
    );
}

#[test]
fn test_duplicates_missing_manifest_fails() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("nonexistent.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["duplicates", missing.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn test_duplicates_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("dups.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "duplicates",
            manifest.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("file1.exe"),
        "output file should contain file1.exe: {content}"
    );
    assert!(
        content.contains("file3.dll"),
        "output file should contain file3.dll: {content}"
    );
}
