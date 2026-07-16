use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest_with_paths(dir: &TempDir, paths: &[&str]) -> std::path::PathBuf {
    let manifest = dir.path().join("test.hash");
    let mut content = String::new();
    for p in paths {
        content.push_str(&format!("blake3  {:064x}  {p}\n", 1u64));
    }
    fs::write(&manifest, &content).unwrap();
    manifest
}

#[test]
fn test_missing_exits_zero_when_all_present() {
    let dir = TempDir::new().unwrap();
    let f1 = dir.path().join("a.txt");
    let f2 = dir.path().join("b.txt");
    fs::write(&f1, b"a").unwrap();
    fs::write(&f2, b"b").unwrap();
    let manifest = write_manifest_with_paths(&dir, &[f1.to_str().unwrap(), f2.to_str().unwrap()]);
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["missing", manifest.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn test_missing_exits_nonzero_when_file_absent() {
    let dir = TempDir::new().unwrap();
    let f1 = dir.path().join("present.txt");
    fs::write(&f1, b"x").unwrap();
    let manifest =
        write_manifest_with_paths(&dir, &[f1.to_str().unwrap(), "/nonexistent/ghost.txt"]);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["missing", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "should exit 1 when files missing");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ghost.txt"),
        "should report the missing file"
    );
}

#[test]
fn test_missing_relative_paths_resolved_with_root() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("data.txt");
    fs::write(&f, b"content").unwrap();
    let manifest = dir.path().join("rel.hash");
    fs::write(
        &manifest,
        "blake3  0000000000000000000000000000000000000000000000000000000000000000  data.txt\n",
    )
    .unwrap();
    // Without --root, relative path won't resolve correctly to the file
    // With --root <dir>, data.txt resolves to dir/data.txt which exists
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "missing",
            manifest.to_str().unwrap(),
            "--root",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn test_missing_reports_all_missing_paths() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest_with_paths(&dir, &["/no/a.txt", "/no/b.txt", "/no/c.txt"]);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["missing", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<_> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3, "should list all 3 missing files");
}

#[test]
fn test_missing_missing_manifest_fails() {
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["missing", "/no/such.hash"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
