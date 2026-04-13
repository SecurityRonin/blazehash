use assert_cmd::Command;
use std::io::Write;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    path
}

const MANIFEST: &str = "\
## case: GREP-TEST
sha256  abc123def456789012345678901234567890123456789012345678901234567890  /evidence/evidence.exe
sha256  deadbeef56789012345678901234567890123456789012345678901234567890ab  /docs/readme.txt
sha256  cafe1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd  /malware/malware.bin
";

#[test]
fn test_grep_matches_by_path() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir, "case.hash", MANIFEST);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["grep", manifest.to_str().unwrap(), "--pattern", r"\.exe"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("/evidence/evidence.exe"),
        "Expected evidence.exe line in:\n{stdout}"
    );
    assert!(
        !stdout.contains("/docs/readme.txt"),
        "readme.txt should not appear in:\n{stdout}"
    );
    assert!(
        !stdout.contains("/malware/malware.bin"),
        "malware.bin should not appear in:\n{stdout}"
    );
    // Header should be preserved
    assert!(
        stdout.contains("## case: GREP-TEST"),
        "Header should be preserved in:\n{stdout}"
    );
}

#[test]
fn test_grep_matches_by_hash() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir, "case.hash", MANIFEST);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["grep", manifest.to_str().unwrap(), "--pattern", "deadbeef"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("deadbeef"),
        "Expected deadbeef hash entry in:\n{stdout}"
    );
    assert!(
        stdout.contains("/docs/readme.txt"),
        "Expected readme.txt path in:\n{stdout}"
    );
    assert!(
        !stdout.contains("/evidence/evidence.exe"),
        "evidence.exe should not appear in:\n{stdout}"
    );
}

#[test]
fn test_grep_ignore_case() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(
        &dir,
        "case.hash",
        "## case: GREP-TEST\nsha256  abc123def456789012345678901234567890123456789012345678901234567890  /Evidence/photo.JPG\n",
    );

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "grep",
            manifest.to_str().unwrap(),
            "--pattern",
            "evidence",
            "--ignore-case",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("/Evidence/photo.JPG"),
        "Expected /Evidence/photo.JPG in:\n{stdout}"
    );
}

#[test]
fn test_grep_no_match_empty_data() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir, "case.hash", MANIFEST);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "grep",
            manifest.to_str().unwrap(),
            "--pattern",
            "THIS_PATTERN_WILL_NEVER_MATCH_ANYTHING_XYZ",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "exit code should be 0 even with no matches; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Header should still appear
    assert!(
        stdout.contains("## case: GREP-TEST"),
        "Header should be preserved even when no entries match:\n{stdout}"
    );
    // No data lines
    assert!(
        !stdout.contains("/evidence/evidence.exe"),
        "No data entries should appear:\n{stdout}"
    );
    assert!(
        !stdout.contains("/docs/readme.txt"),
        "No data entries should appear:\n{stdout}"
    );
}

#[test]
fn test_grep_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir, "case.hash", MANIFEST);
    let out_file = dir.path().join("grep_out.hash");

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "grep",
            manifest.to_str().unwrap(),
            "--pattern",
            r"\.exe",
            "-o",
            out_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_file.exists(), "Output file should exist");
    let content = std::fs::read_to_string(&out_file).unwrap();
    assert!(
        content.contains("/evidence/evidence.exe"),
        "Expected evidence.exe in output file:\n{content}"
    );
    assert!(
        !content.contains("/docs/readme.txt"),
        "readme.txt should not appear in output file:\n{content}"
    );
    assert!(
        content.contains("## case: GREP-TEST"),
        "Header should be preserved in output file:\n{content}"
    );
}
