use assert_cmd::Command;
use tempfile::tempdir;
use std::fs;

#[test]
fn test_dedup_finds_duplicate_files() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("file1.bin"), b"same content").unwrap();
    fs::write(dir.path().join("file2.bin"), b"same content").unwrap();
    fs::write(dir.path().join("unique.bin"), b"unique content").unwrap();

    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", dir.path().to_str().unwrap(), "-c", "blake3"])
        .output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("file1.bin") || stdout.contains("file2.bin"),
        "expected duplicate files in output: {stdout}");
}

#[test]
fn test_dedup_exits_one_when_duplicates_found() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("a.bin"), b"dup").unwrap();
    fs::write(dir.path().join("b.bin"), b"dup").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", dir.path().to_str().unwrap()])
        .assert().code(1);
}

#[test]
fn test_dedup_exits_zero_when_no_duplicates() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("a.bin"), b"aaa").unwrap();
    fs::write(dir.path().join("b.bin"), b"bbb").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", dir.path().to_str().unwrap()])
        .assert().code(0);
}

#[test]
fn test_dedup_from_manifest() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    std::fs::write(&manifest,
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n##\n5,aaaa,/a.bin\n5,aaaa,/b.bin\n5,bbbb,/c.bin\n"
    ).unwrap();

    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", manifest.to_str().unwrap()])
        .output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("a.bin") || stdout.contains("b.bin"),
        "expected duplicate files: {stdout}");
}

#[test]
fn test_dedup_dupes_excludes_canonical() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("a.bin"), b"same").unwrap();
    fs::write(dir.path().join("b.bin"), b"same").unwrap();
    fs::write(dir.path().join("c.bin"), b"same").unwrap();

    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", "--dedup-dupes", dir.path().to_str().unwrap()])
        .output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    // Should print 2 redundant copies (not 3 — canonical is excluded)
    assert_eq!(lines.len(), 2, "expected 2 redundant copies, got: {stdout}");
}

#[test]
fn test_dedup_grouping_is_deterministic() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("a.bin"), b"dup").unwrap();
    fs::write(dir.path().join("b.bin"), b"dup").unwrap();

    let out1 = Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", dir.path().to_str().unwrap(), "-c", "blake3"])
        .output().unwrap();
    let out2 = Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", dir.path().to_str().unwrap(), "-c", "blake3"])
        .output().unwrap();
    assert_eq!(out1.stdout, out2.stdout, "dedup output must be deterministic");
}
