use assert_cmd::Command;
use std::io::Write;
use tempfile::TempDir;

const H1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const H2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const H3: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("manifest.txt");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "# blazehash manifest").unwrap();
    writeln!(f, "sha256  {H1}  file1.exe").unwrap();
    writeln!(f, "sha256  {H2}  file2.bin").unwrap();
    writeln!(f, "sha256  {H1}  file3.dll").unwrap();
    writeln!(f, "sha256  {H2}  file4.txt").unwrap();
    writeln!(f, "sha256  {H3}  file5.jpg").unwrap();
    path
}

#[test]
fn test_unique_hash_keeps_first_of_each_hash() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["unique-hash", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("file1.exe"), "expected file1.exe in output");
    assert!(stdout.contains("file2.bin"), "expected file2.bin in output");
}

#[test]
fn test_unique_hash_keeps_unique_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["unique-hash", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("file5.jpg"), "expected file5.jpg (unique hash) in output");
}

#[test]
fn test_unique_hash_drops_duplicate_hash_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["unique-hash", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(!stdout.contains("file3.dll"), "file3.dll should be dropped (duplicate of H1)");
    assert!(!stdout.contains("file4.txt"), "file4.txt should be dropped (duplicate of H2)");
}

#[test]
fn test_unique_hash_missing_manifest_fails() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["unique-hash", "/nonexistent/path/manifest.txt"])
        .assert()
        .failure();
}

#[test]
fn test_unique_hash_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_file = dir.path().join("out.txt");

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "unique-hash",
            manifest.to_str().unwrap(),
            "-o",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&out_file).unwrap();
    // Should have exactly 3 hash entries (file1.exe, file2.bin, file5.jpg)
    let hash_lines: Vec<&str> = content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('%') && !l.is_empty())
        .collect();
    assert_eq!(hash_lines.len(), 3, "expected 3 unique-hash entries, got: {hash_lines:?}");
}
