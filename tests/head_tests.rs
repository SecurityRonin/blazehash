use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  file1.txt\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  file2.txt\n",
        "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  file3.txt\n",
        "sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  file4.txt\n",
        "sha256  eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  file5.txt\n",
    )).unwrap();
    p
}

#[test]
fn test_head_default_10() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for i in 1..=5 {
        assert!(stdout.contains(&format!("file{i}.txt")), "file{i}.txt should be present");
    }
}

#[test]
fn test_head_n_limits_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap(), "--count", "2"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("file1.txt"), "first entry must be present");
    assert!(stdout.contains("file2.txt"), "second entry must be present");
    assert!(!stdout.contains("file3.txt"), "third entry must be absent");
}

#[test]
fn test_head_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap(), "--count", "1"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## case: CASE-001"), "headers must be preserved");
}

#[test]
fn test_head_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("head.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap(), "--count", "3",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    let data_lines: Vec<_> = content.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data_lines.len(), 3, "file should have exactly 3 data lines");
}

#[test]
fn test_head_count_zero_outputs_headers_only() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap(), "--count", "0"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data_lines: Vec<_> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert!(data_lines.is_empty(), "count=0 must output no data entries");
}
