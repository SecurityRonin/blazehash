use assert_cmd::Command;
use std::io::Write;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    path
}

#[test]
fn test_rename_substitutes_path() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(
        &dir,
        "case.hash",
        "## case: TEST-001\nsha256  abc123def456789012345678901234567890123456789012345678901234567890  /old/evidence/file.bin\n",
    );

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "rename",
            manifest.to_str().unwrap(),
            "--rename-from",
            "/old/evidence",
            "--rename-to",
            "/new/evidence",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("/new/evidence/file.bin"), "Expected /new/evidence/file.bin in:\n{stdout}");
    assert!(!stdout.contains("/old/evidence/file.bin"), "Old path should not appear in:\n{stdout}");
}

#[test]
fn test_rename_preserves_hash() {
    let dir = TempDir::new().unwrap();
    let hash = "abc123def456789012345678901234567890123456789012345678901234567890";
    let manifest = write_manifest(
        &dir,
        "case.hash",
        &format!("## case: TEST-001\nsha256  {hash}  /old/evidence/file.bin\n"),
    );

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "rename",
            manifest.to_str().unwrap(),
            "--rename-from",
            "/old/evidence",
            "--rename-to",
            "/new/evidence",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains(hash), "Hash should be preserved in:\n{stdout}");
    assert!(stdout.contains("/new/evidence/file.bin"), "Path should be updated in:\n{stdout}");
}

#[test]
fn test_rename_no_match_passes_through() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(
        &dir,
        "case.hash",
        "sha256  abc123def456789012345678901234567890123456789012345678901234567890  /completely/different/path.bin\n",
    );

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "rename",
            manifest.to_str().unwrap(),
            "--rename-from",
            "/old/evidence",
            "--rename-to",
            "/new/evidence",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(
        stdout.contains("/completely/different/path.bin"),
        "Unmatched path should pass through unchanged in:\n{stdout}"
    );
}

#[test]
fn test_rename_to_defaults_to_empty() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(
        &dir,
        "case.hash",
        "sha256  abc123def456789012345678901234567890123456789012345678901234567890  /prefix/file.bin\n",
    );

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "rename",
            manifest.to_str().unwrap(),
            "--rename-from",
            "/prefix",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(
        stdout.contains("/file.bin"),
        "Expected /file.bin (prefix removed) in:\n{stdout}"
    );
    assert!(
        !stdout.contains("/prefix/file.bin"),
        "Old prefixed path should not appear in:\n{stdout}"
    );
}

#[test]
fn test_rename_output_to_file() {
    let dir = TempDir::new().unwrap();
    let hash = "abc123def456789012345678901234567890123456789012345678901234567890";
    let manifest = write_manifest(
        &dir,
        "case.hash",
        &format!("sha256  {hash}  /old/path/file.bin\n"),
    );
    let out_file = dir.path().join("renamed.hash");

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "rename",
            manifest.to_str().unwrap(),
            "--rename-from",
            "/old/path",
            "--rename-to",
            "/new/path",
            "-o",
            out_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(out_file.exists(), "Output file should exist");
    let content = std::fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("/new/path/file.bin"), "Expected /new/path/file.bin in file:\n{content}");
    assert!(content.contains(hash), "Hash should be in file:\n{content}");
}
