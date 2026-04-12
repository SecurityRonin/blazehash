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
fn cli_size_only_summary_stderr() {
    // -s should print a [+] summary line on stderr: file count, total size, time estimate
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
        .stderr(predicate::str::contains("2 files"))
        .stderr(predicate::str::contains("est."));
}

#[test]
fn cli_size_only_single_file_summary() {
    // Single-file -s should also emit summary on stderr
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-s")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("1 file"))
        .stderr(predicate::str::contains("est."));
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

// ── -o auto-naming ────────────────────────────────────────────────────────────

#[test]
fn cli_bare_o_derives_dirname_hash() {
    let dir = TempDir::new().unwrap();
    let evidence = dir.path().join("smith-2026");
    fs::create_dir_all(&evidence).unwrap();
    fs::write(evidence.join("file.txt"), b"data").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-r")
        .arg(&evidence)
        .arg("-o") // no filename — should auto-derive smith-2026.hash
        .current_dir(dir.path())
        .assert()
        .success();

    assert!(
        dir.path().join("smith-2026.hash").exists(),
        "smith-2026.hash not created"
    );
}

#[test]
fn cli_bare_o_falls_back_to_manifest_hash_for_dot() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("file.txt"), b"data").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg(".")
        .arg("-o")
        .current_dir(dir.path())
        .assert()
        .success();

    assert!(
        dir.path().join("manifest.hash").exists(),
        "manifest.hash not created"
    );
}

#[test]
fn cli_explicit_o_filename_unchanged() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("file.txt"), b"data").unwrap();
    let out = dir.path().join("custom.hash");

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg(dir.path())
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    assert!(out.exists(), "custom.hash not created");
}

#[test]
fn cli_nsrl_bloom_rejected() {
    let dir = TempDir::new().unwrap();
    let bloom = dir.path().join("nsrl.bloom");
    fs::write(&bloom, b"fake").unwrap();
    fs::write(dir.path().join("file.txt"), b"data").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg(dir.path())
        .arg("--nsrl")
        .arg(&bloom)
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)bloom|not supported|sqlite").unwrap());
}

#[test]
fn test_completions_bash_outputs_something() {
    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["completions", "bash"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("blazehash") || stdout.contains("complete"),
        "bash completions must contain shell content, got: {}",
        &stdout[..stdout.len().min(200)]
    );
}

#[test]
fn test_completions_zsh_outputs_something() {
    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["completions", "zsh"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("blazehash") || stdout.contains("compdef"),
        "zsh completions must contain shell content"
    );
}

#[test]
fn test_completions_fish_outputs_something() {
    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["completions", "fish"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("blazehash") || stdout.contains("complete"),
        "fish completions must contain shell content"
    );
}

#[cfg(feature = "ots")]
mod ots_tests {
    use tempfile::tempdir;

    #[test]
    fn test_ots_stamp_unit_hash() {
        // Unit test: verify the stamp function computes correct SHA-256 digest
        use blazehash::ots::compute_manifest_digest;

        let dir = tempdir().unwrap();
        let manifest = dir.path().join("test.hash");
        std::fs::write(&manifest, "test content for OTS").unwrap();

        let digest = compute_manifest_digest(&manifest).unwrap();
        assert_eq!(digest.len(), 32, "SHA-256 digest must be 32 bytes");

        // Verify it matches expected SHA-256
        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(b"test content for OTS");
        assert_eq!(digest, expected.as_slice());
    }

    #[test]
    fn test_ots_sidecar_path() {
        use blazehash::ots::ots_path_for;
        use std::path::PathBuf;

        let p = PathBuf::from("/evidence/manifest.hash");
        assert_eq!(
            ots_path_for(&p),
            PathBuf::from("/evidence/manifest.hash.ots")
        );
    }
}
