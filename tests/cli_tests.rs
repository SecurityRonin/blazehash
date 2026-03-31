use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn cli_version() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("blazehash"));
}

#[test]
fn cli_hash_single_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("HASHDEEP-1.0"))
        .stdout(predicate::str::contains("blake3"))
        .stdout(predicate::str::contains("test.txt"));
}

#[test]
fn cli_hash_directory_recursive() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("b.txt"), b"bbb").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("a.txt"))
        .stdout(predicate::str::contains("b.txt"));
}

#[test]
fn cli_multiple_algorithms() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-c")
        .arg("blake3,sha256")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("size,blake3,sha256,filename"));
}

#[test]
fn cli_output_to_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();
    let output = dir.path().join("output.hash");

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-o")
        .arg(output.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&output).unwrap();
    assert!(contents.contains("HASHDEEP-1.0"));
    assert!(contents.contains("test.txt"));
}

#[test]
fn cli_size_only_mode() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-s")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("11"));
}

#[test]
fn cli_piecewise_hashing() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    // Write 2000 bytes to ensure multiple chunks at 1K chunk size
    let data = vec![0x42u8; 2000];
    fs::write(&file, &data).unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-p")
        .arg("1K")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("test.txt"));
}

#[test]
fn cli_resume_flag() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    fs::write(dir.path().join("b.txt"), b"bbb").unwrap();
    let manifest = dir.path().join("manifest.hash");

    // First run: hash only a.txt
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(dir.path().join("a.txt").to_str().unwrap())
        .assert()
        .success();

    // Second run with --resume: should append b.txt but not re-hash a.txt
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--resume")
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&manifest).unwrap();
    assert!(contents.contains("a.txt"));
    assert!(contents.contains("b.txt"));
}

#[test]
fn cli_no_args_exits_ok() {
    // With MCP subcommand support, no args is valid (produces no output, exits 0)
    Command::cargo_bin("blazehash").unwrap().assert().success();
}

#[test]
fn cli_nonexistent_file_returns_error() {
    // blazehash exits 0 but produces no file entries for nonexistent paths
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("/nonexistent/file.txt")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    // Header is present but no data lines (no hash lines after the ## comments)
    assert!(stdout.contains("HASHDEEP-1.0"));
    // There should be no actual hash line (only header/comment lines start with % or #)
    let data_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.starts_with('%') && !l.starts_with('#') && !l.is_empty())
        .collect();
    assert!(
        data_lines.is_empty(),
        "expected no data lines, got: {data_lines:?}"
    );
}

#[test]
fn cli_size_only_directory() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    fs::write(dir.path().join("b.txt"), b"bbbb").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-s")
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("3"))
        .stdout(predicate::str::contains("4"));
}

#[test]
fn cli_bare_mode_no_header() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-b")
        .arg(file.to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("HASHDEEP"));
    assert!(!stdout.contains("%%%%"));
    assert!(stdout.contains("test.txt"));
}

#[test]
fn cli_jsonl_format() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    fs::write(dir.path().join("b.txt"), b"bbb").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("jsonl")
        .arg(dir.path().join("a.txt").to_str().unwrap())
        .arg(dir.path().join("b.txt").to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    // Each line should be valid JSON
    for line in &lines {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
}

#[test]
fn cli_audit_shows_summary() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();
    let manifest = dir.path().join("manifest.hash");

    // First hash
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    // Audit
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-a")
        .arg("-k")
        .arg(manifest.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Files matched: 1"))
        .stdout(predicate::str::contains("Files changed: 0"))
        .stdout(predicate::str::contains("Files missing: 0"));
}

#[test]
fn cli_audit_detects_changes() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"original content").unwrap();
    let manifest = dir.path().join("manifest.hash");

    // Hash original
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    // Modify file
    fs::write(&file, b"modified content").unwrap();

    // Audit should detect change
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-a")
        .arg("-k")
        .arg(manifest.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Files changed: 1"));
}

#[test]
fn cli_piecewise_bare_mode() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    let data = vec![0x42u8; 2000];
    fs::write(&file, &data).unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-p")
        .arg("1K")
        .arg("-b")
        .arg(file.to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("HASHDEEP"));
    assert!(stdout.contains("test.txt"));
}

#[test]
fn cli_multiple_c_flags() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-c")
        .arg("blake3")
        .arg("-c")
        .arg("sha256")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("blake3"))
        .stdout(predicate::str::contains("sha256"));
}

#[test]
fn cli_resume_without_output_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();

    // --resume without -o should still work (just doesn't actually resume)
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--resume")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("test.txt"));
}
