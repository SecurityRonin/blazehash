use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    path
}

const MANIFEST_CONTENT: &str = "\
## case: SHUFFLE_TEST\n\
sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /tmp/file1.txt\n\
sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /tmp/file2.txt\n\
sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  /tmp/file3.txt\n\
sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  /tmp/file4.txt\n\
sha256  eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  /tmp/file5.txt\n";

#[test]
fn test_shuffle_contains_all_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir, "manifest.hash", MANIFEST_CONTENT);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("shuffle")
        .arg(&manifest)
        .arg("--seed")
        .arg("42")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shuffle should succeed: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for path in &[
        "/tmp/file1.txt",
        "/tmp/file2.txt",
        "/tmp/file3.txt",
        "/tmp/file4.txt",
        "/tmp/file5.txt",
    ] {
        assert!(
            stdout.contains(path),
            "output should contain {path}, got: {stdout}"
        );
    }
    let data_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| {
            !l.trim().starts_with('#') && !l.trim().starts_with('%') && !l.trim().is_empty()
        })
        .collect();
    assert_eq!(
        data_lines.len(),
        5,
        "output should have exactly 5 data entries, got: {}",
        data_lines.len()
    );
}

#[test]
fn test_shuffle_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir, "manifest.hash", MANIFEST_CONTENT);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("shuffle")
        .arg(&manifest)
        .arg("--seed")
        .arg("42")
        .output()
        .unwrap();
    assert!(out.status.success(), "shuffle should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("## case: SHUFFLE_TEST"),
        "output should contain header '## case: SHUFFLE_TEST', got: {stdout}"
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.first().map(|l| l.trim()) == Some("## case: SHUFFLE_TEST"),
        "header should appear first, got: {stdout}"
    );
}

#[test]
fn test_shuffle_seed_is_reproducible() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir, "manifest.hash", MANIFEST_CONTENT);
    let out1 = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("shuffle")
        .arg(&manifest)
        .arg("--seed")
        .arg("42")
        .output()
        .unwrap();
    assert!(out1.status.success(), "first shuffle should succeed");
    let out2 = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("shuffle")
        .arg(&manifest)
        .arg("--seed")
        .arg("42")
        .output()
        .unwrap();
    assert!(out2.status.success(), "second shuffle should succeed");
    assert_eq!(
        out1.stdout, out2.stdout,
        "two runs with same seed should produce identical output"
    );
}

#[test]
fn test_shuffle_missing_manifest_fails() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("shuffle")
        .arg("/nonexistent/path/manifest.hash")
        .assert()
        .failure();
}

#[test]
fn test_shuffle_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir, "manifest.hash", MANIFEST_CONTENT);
    let out_path = dir.path().join("shuffled.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("shuffle")
        .arg(&manifest)
        .arg("--seed")
        .arg("99")
        .arg("-o")
        .arg(&out_path)
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    for path in &[
        "/tmp/file1.txt",
        "/tmp/file2.txt",
        "/tmp/file3.txt",
        "/tmp/file4.txt",
        "/tmp/file5.txt",
    ] {
        assert!(
            content.contains(path),
            "output file should contain {path}, got: {content}"
        );
    }
}
