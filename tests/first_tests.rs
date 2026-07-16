use assert_cmd::Command;
use std::io::Write;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("manifest.txt");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "## case: first occurrence test").unwrap();
    writeln!(
        f,
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  file1.txt"
    )
    .unwrap();
    writeln!(
        f,
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  file2.txt"
    )
    .unwrap();
    writeln!(
        f,
        "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  file1.txt"
    )
    .unwrap();
    path
}

#[test]
fn test_first_keeps_first_occurrence() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["first", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "command failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    // First occurrence of file1.txt should have hash 'aaa...'
    assert!(
        stdout.contains(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  file1.txt"
        ),
        "expected first hash for file1.txt in output:\n{stdout}"
    );
    // Second occurrence (ccc...) should NOT appear
    assert!(
        !stdout.contains("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "duplicate hash for file1.txt should be dropped:\n{stdout}"
    );
}

#[test]
fn test_first_unique_paths_unaffected() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["first", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // file2.txt appears once and should still be in output
    assert!(
        stdout.contains(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  file2.txt"
        ),
        "file2.txt should remain in output:\n{stdout}"
    );
}

#[test]
fn test_first_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["first", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("## case: first occurrence test"),
        "header line should be preserved:\n{stdout}"
    );
}

#[test]
fn test_first_missing_manifest_fails() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("nonexistent.txt");

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["first", missing.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success(), "should fail on missing manifest");
}

#[test]
fn test_first_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);
    let out_path = dir.path().join("out.txt");

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "first",
            manifest.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let content = std::fs::read_to_string(&out_path).unwrap();

    // Count occurrences of file1.txt — should be exactly 1
    let count = content.lines().filter(|l| l.contains("file1.txt")).count();
    assert_eq!(
        count, 1,
        "file1.txt should appear exactly once in output:\n{content}"
    );
}
