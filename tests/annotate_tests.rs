use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn test_annotate_adds_note_header() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(
        &dir,
        "manifest.hash",
        "## case: CASE001\n\
         sha256  abc123def456abc123def456abc123def456abc123def456abc123def456abc1  /tmp/file.txt\n",
    );
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("annotate")
        .arg(&manifest)
        .arg("--note")
        .arg("test message")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("## note: test message"),
        "output should contain '## note: test message', got: {stdout}"
    );
}

#[test]
fn test_annotate_replaces_existing_note() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(
        &dir,
        "manifest.hash",
        "## case: CASE001\n\
         ## note: old note\n\
         sha256  abc123def456abc123def456abc123def456abc123def456abc123def456abc1  /tmp/file.txt\n",
    );
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("annotate")
        .arg(&manifest)
        .arg("--note")
        .arg("new note")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("## note: new note"),
        "output should contain new note, got: {stdout}"
    );
    assert!(
        !stdout.contains("## note: old note"),
        "output should not contain old note, got: {stdout}"
    );
    let count = stdout.matches("## note:").count();
    assert_eq!(count, 1, "note should appear exactly once, got: {stdout}");
}

#[test]
fn test_annotate_preserves_other_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(
        &dir,
        "manifest.hash",
        "## case: CASE_X\n\
         sha256  abc123def456abc123def456abc123def456abc123def456abc123def456abc1  /tmp/file.txt\n",
    );
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("annotate")
        .arg(&manifest)
        .arg("--note")
        .arg("preserve test")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("## case: CASE_X"),
        "output should contain original case header, got: {stdout}"
    );
}

#[test]
fn test_annotate_preserves_data_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(
        &dir,
        "manifest.hash",
        "## case: CASE001\n\
         sha256  abc123def456abc123def456abc123def456abc123def456abc123def456abc1  /tmp/file.txt\n",
    );
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("annotate")
        .arg(&manifest)
        .arg("--note")
        .arg("data test")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("abc123def456abc123def456abc123def456abc123def456abc123def456abc1"),
        "output should contain original data entry, got: {stdout}"
    );
    assert!(
        stdout.contains("/tmp/file.txt"),
        "output should contain file path from data entry, got: {stdout}"
    );
}

#[test]
fn test_annotate_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(
        &dir,
        "manifest.hash",
        "## case: CASE001\n\
         sha256  abc123def456abc123def456abc123def456abc123def456abc123def456abc1  /tmp/file.txt\n",
    );
    let out_path = dir.path().join("annotated.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("annotate")
        .arg(&manifest)
        .arg("--note")
        .arg("file output test")
        .arg("-o")
        .arg(&out_path)
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("## note: file output test"),
        "output file should contain note, got: {content}"
    );
}
