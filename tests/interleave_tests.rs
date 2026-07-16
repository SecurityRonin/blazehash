use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir, name: &str, header: &str, entries: &[&str]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "{header}").unwrap();
    for e in entries {
        writeln!(f, "sha256  aabbccdd  {e}").unwrap();
    }
    path
}

#[test]
fn test_interleave_alternates_entries() {
    let dir = TempDir::new().unwrap();
    let a = make_manifest(
        &dir,
        "a.txt",
        "## case: A",
        &["file_a1.txt", "file_a2.txt", "file_a3.txt"],
    );
    let b = make_manifest(&dir, "b.txt", "## case: B", &["file_b1.txt", "file_b2.txt"]);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["interleave", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    let lines: Vec<&str> = stdout.lines().filter(|l| l.contains("file_")).collect();
    assert_eq!(lines.len(), 5);

    let pos_a1 = stdout.find("file_a1.txt").unwrap();
    let pos_b1 = stdout.find("file_b1.txt").unwrap();
    let pos_a2 = stdout.find("file_a2.txt").unwrap();
    let pos_b2 = stdout.find("file_b2.txt").unwrap();
    let pos_a3 = stdout.find("file_a3.txt").unwrap();

    assert!(pos_a1 < pos_b1, "a1 should come before b1");
    assert!(pos_b1 < pos_a2, "b1 should come before a2");
    assert!(pos_a2 < pos_b2, "a2 should come before b2");
    assert!(pos_b2 < pos_a3, "b2 should come before a3");
}

#[test]
fn test_interleave_preserves_headers_from_a() {
    let dir = TempDir::new().unwrap();
    let a = make_manifest(&dir, "a.txt", "## case: A", &["file_a1.txt"]);
    let b = make_manifest(&dir, "b.txt", "## case: B", &["file_b1.txt"]);

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["interleave", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("## case: A"));
}

#[test]
fn test_interleave_skips_headers_from_b() {
    let dir = TempDir::new().unwrap();
    let a = make_manifest(&dir, "a.txt", "## case: A", &["file_a1.txt"]);
    let b = make_manifest(&dir, "b.txt", "## case: B", &["file_b1.txt"]);

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["interleave", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("## case: B").not());
}

#[test]
fn test_interleave_missing_manifest_fails() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("nonexistent_a.txt");
    let b = dir.path().join("nonexistent_b.txt");

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["interleave", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn test_interleave_output_to_file() {
    let dir = TempDir::new().unwrap();
    let a = make_manifest(
        &dir,
        "a.txt",
        "## case: A",
        &["file_a1.txt", "file_a2.txt", "file_a3.txt"],
    );
    let b = make_manifest(&dir, "b.txt", "## case: B", &["file_b1.txt", "file_b2.txt"]);
    let out = dir.path().join("out.txt");

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "interleave",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&out).unwrap();
    assert!(
        content.contains("file_a1.txt"),
        "output missing file_a1.txt"
    );
    assert!(
        content.contains("file_a2.txt"),
        "output missing file_a2.txt"
    );
    assert!(
        content.contains("file_a3.txt"),
        "output missing file_a3.txt"
    );
    assert!(
        content.contains("file_b1.txt"),
        "output missing file_b1.txt"
    );
    assert!(
        content.contains("file_b2.txt"),
        "output missing file_b2.txt"
    );
}
