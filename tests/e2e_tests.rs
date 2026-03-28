use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn e2e_hash_and_audit() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("file1.txt"), b"content one").unwrap();
    fs::write(dir.path().join("file2.txt"), b"content two").unwrap();
    let manifest = dir.path().join("manifest.hash");

    // Step 1: Hash the directory
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-r")
        .arg("-c")
        .arg("blake3,sha256")
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success();

    // Verify manifest exists and has content
    let contents = fs::read_to_string(&manifest).unwrap();
    assert!(contents.contains("HASHDEEP-1.0"));
    assert!(contents.contains("file1.txt"));
    assert!(contents.contains("file2.txt"));
    assert!(contents.contains("blake3"));
    assert!(contents.contains("sha256"));

    // Step 2: Audit should show all matched
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-a")
        .arg("-k")
        .arg(manifest.to_str().unwrap())
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn e2e_bare_output() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-b")
        .arg(dir.path().join("test.txt").to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("HASHDEEP"));
    assert!(stdout.contains("test.txt"));
}

#[test]
fn e2e_csv_format() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("csv")
        .arg(dir.path().join("test.txt").to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("size,blake3,filename"));
}

#[test]
fn e2e_json_format() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("json")
        .arg(dir.path().join("test.txt").to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array());
}

#[test]
fn e2e_size_only_single_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-s")
        .arg(file.to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("11")); // file size
    assert!(stdout.contains("test.txt"));
    // Size-only should NOT contain hash headers
    assert!(!stdout.contains("HASHDEEP"));
}

#[test]
fn e2e_size_only_directory_recursive() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("b.txt"), b"bb").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-s")
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("3")); // a.txt size
    assert!(stdout.contains("2")); // b.txt size
    assert!(stdout.contains("a.txt"));
    assert!(stdout.contains("b.txt"));
}

#[test]
fn e2e_size_only_to_output_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();
    let output_path = dir.path().join("sizes.txt");

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-s")
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&output_path).unwrap();
    assert!(contents.contains("5"));
    assert!(contents.contains("test.txt"));
}

#[test]
fn e2e_audit_detects_missing_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"original content").unwrap();
    let manifest = dir.path().join("manifest.hash");

    // Hash the file
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    // Delete the file
    fs::remove_file(&file).unwrap();

    // Audit with no paths — file should be missing
    // We need to pass at least a directory, so pass the empty dir
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-a")
        .arg("-k")
        .arg(manifest.to_str().unwrap())
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Files missing: 1"));
}

#[test]
fn e2e_audit_to_output_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();
    let manifest = dir.path().join("manifest.hash");
    let audit_output = dir.path().join("audit.txt");

    // Hash
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    // Audit with -o
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-a")
        .arg("-k")
        .arg(manifest.to_str().unwrap())
        .arg("-o")
        .arg(audit_output.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&audit_output).unwrap();
    assert!(contents.contains("Files matched: 1"));
}

#[test]
fn e2e_jsonl_format() {
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
    for line in &lines {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(parsed.get("filename").is_some());
        assert!(parsed.get("size").is_some());
        assert!(parsed.get("hashes").is_some());
    }
}

#[test]
fn e2e_hashdeep_format_explicit() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("hashdeep")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("HASHDEEP-1.0"))
        .stdout(predicate::str::contains("test.txt"));
}

#[test]
fn e2e_piecewise_with_output_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    let data = vec![0x42u8; 2000];
    fs::write(&file, &data).unwrap();
    let output_path = dir.path().join("pieces.hash");

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-p")
        .arg("1K")
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&output_path).unwrap();
    assert!(contents.contains("HASHDEEP-1.0"));
    assert!(contents.contains("test.txt"));
    // Should have multiple data lines (2000 bytes / 1K chunks = 2 chunks)
    let data_lines: Vec<&str> = contents.lines()
        .filter(|l| !l.starts_with("%%") && !l.starts_with('#') && !l.is_empty())
        .collect();
    assert_eq!(data_lines.len(), 2);
}

#[test]
fn e2e_piecewise_multiple_algorithms() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"piecewise multi").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-p")
        .arg("100")
        .arg("-c")
        .arg("blake3,sha256")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("blake3"))
        .stdout(predicate::str::contains("sha256"));
}

#[test]
fn e2e_resume_new_output_file() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    let manifest = dir.path().join("manifest.hash");

    // --resume with non-existent output file — should create it
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--resume")
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(dir.path().join("a.txt").to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&manifest).unwrap();
    // Resume mode writes data lines without the HASHDEEP header
    assert!(contents.contains("a.txt"));
}

#[test]
fn e2e_resume_appends_new_files() {
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

    let first_contents = fs::read_to_string(&manifest).unwrap();
    assert!(first_contents.contains("a.txt"));
    assert!(!first_contents.contains("b.txt"));

    // Second run with --resume: should add b.txt, skip a.txt
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--resume")
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(dir.path().join("a.txt").to_str().unwrap())
        .arg(dir.path().join("b.txt").to_str().unwrap())
        .assert()
        .success();

    let final_contents = fs::read_to_string(&manifest).unwrap();
    assert!(final_contents.contains("a.txt"));
    assert!(final_contents.contains("b.txt"));
    // Header should only appear once (not duplicated on resume)
    assert_eq!(final_contents.matches("HASHDEEP-1.0").count(), 1);
}

#[test]
fn e2e_resume_skips_already_hashed() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();
    let manifest = dir.path().join("manifest.hash");

    // First run
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let first_size = fs::metadata(&manifest).unwrap().len();

    // Second run with --resume — same file, should not add duplicate
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--resume")
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let second_size = fs::metadata(&manifest).unwrap().len();
    assert_eq!(first_size, second_size, "resume should not duplicate already-hashed files");
}

#[test]
fn e2e_walk_errors_to_stderr() {
    // Create an unreadable file — should produce warning on stderr
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("good.txt"), b"good").unwrap();
    let bad = dir.path().join("bad.txt");
    fs::write(&bad, b"secret").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o000)).unwrap();

        let output = Command::cargo_bin("blazehash")
            .unwrap()
            .arg("-r")
            .arg(dir.path().to_str().unwrap())
            .output()
            .unwrap();

        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("warning"), "expected warning on stderr for unreadable file");

        // Cleanup permissions
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o644)).unwrap();
    }
}

#[test]
fn e2e_multiple_paths() {
    let dir = TempDir::new().unwrap();
    let f1 = dir.path().join("one.txt");
    let f2 = dir.path().join("two.txt");
    fs::write(&f1, b"one").unwrap();
    fs::write(&f2, b"two").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg(f1.to_str().unwrap())
        .arg(f2.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("one.txt"))
        .stdout(predicate::str::contains("two.txt"));
}

#[test]
fn e2e_csv_to_output_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"csv output test").unwrap();
    let output_path = dir.path().join("output.csv");

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("csv")
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&output_path).unwrap();
    assert!(contents.starts_with("size,blake3,filename"));
    assert!(contents.contains("test.txt"));
}

#[test]
fn e2e_json_to_output_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"json output test").unwrap();
    let output_path = dir.path().join("output.json");

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("json")
        .arg("-o")
        .arg(output_path.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}

#[test]
fn e2e_directory_without_recursive_flag() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("root.txt"), b"root").unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("nested.txt"), b"nested").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg(dir.path().to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("root.txt"));
    // Without -r, nested file should NOT appear
    assert!(!stdout.contains("nested.txt"));
}
