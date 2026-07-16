use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

static REPAIR_MANIFEST: &str = concat!(
    "## case: REPAIR-TEST\n",
    "\n",
    "sha256    aaaa1111111111111111111111111111111111111111111111111111111111111111    /evidence/file1.exe\n",
    "just-a-malformed-line-with-no-spaces-at-all\n",
    "sha256  bbbb2222222222222222222222222222222222222222222222222222222222222222  /docs/readme.txt\n",
    "\n",
);

fn write_repair_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("messy.hash");
    fs::write(&p, REPAIR_MANIFEST).unwrap();
    p
}

#[test]
fn test_repair_removes_blank_lines() {
    let dir = TempDir::new().unwrap();
    let manifest = write_repair_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["repair", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "expected success: {:?}", output);
    let content = String::from_utf8(output.stdout).unwrap();
    for line in content.lines() {
        assert!(
            !line.trim().is_empty(),
            "blank line found in output: {:?}",
            content
        );
    }
}

#[test]
fn test_repair_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_repair_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["repair", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let content = String::from_utf8(output.stdout).unwrap();
    assert!(
        content.contains("## case: REPAIR-TEST"),
        "header not preserved in:\n{content}"
    );
}

#[test]
fn test_repair_normalizes_extra_spaces() {
    let dir = TempDir::new().unwrap();
    let manifest = write_repair_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["repair", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let content = String::from_utf8(output.stdout).unwrap();

    // The first data line used 4 spaces between fields; after repair it must use exactly 2
    let data_lines: Vec<&str> = content
        .lines()
        .filter(|l| l.starts_with("sha256"))
        .collect();
    assert!(!data_lines.is_empty(), "no data lines found");
    for line in &data_lines {
        // Must contain exactly "  " (two spaces), not "    " (four spaces)
        assert!(!line.contains("    "), "4-space separator found in: {line}");
        assert!(line.contains("  "), "2-space separator missing in: {line}");
    }
}

#[test]
fn test_repair_drops_malformed_lines() {
    let dir = TempDir::new().unwrap();
    let manifest = write_repair_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["repair", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let content = String::from_utf8(output.stdout).unwrap();
    assert!(
        !content.contains("just-a-malformed-line-with-no-spaces-at-all"),
        "malformed line must be dropped"
    );
}

#[test]
fn test_repair_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_repair_manifest(&dir);
    let out = dir.path().join("clean.hash");

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "repair",
            manifest.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = fs::read_to_string(&out).unwrap();
    // No blank lines
    for line in content.lines() {
        assert!(!line.trim().is_empty(), "blank line found in output file");
    }
    // Header preserved
    assert!(
        content.contains("## case: REPAIR-TEST"),
        "header missing from output file"
    );
}
