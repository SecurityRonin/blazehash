use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_large_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("large.hash");
    let mut content = String::from("## case: LARGE\n");
    for i in 0..20u8 {
        content.push_str(&format!(
            "sha256  {:0>64}  file{:02}.txt\n",
            format!("{:x}", i as u64), i
        ));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_sample_count_limits_output() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "5"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<_> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 5, "sample --count 5 must return exactly 5 entries");
}

#[test]
fn test_sample_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "3"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## case: LARGE"), "headers must be preserved");
}

#[test]
fn test_sample_count_larger_than_manifest_returns_all() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "50"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<_> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 20, "requesting more than available must return all 20 entries");
}

#[test]
fn test_sample_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    let out_path = dir.path().join("sample.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "4",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    let data_lines: Vec<_> = content.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data_lines.len(), 4);
}

#[test]
fn test_sample_entries_are_valid_manifest_lines() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "5"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#')) {
        let parts: Vec<&str> = line.splitn(3, "  ").collect();
        assert_eq!(parts.len(), 3, "sampled entry must be valid manifest line: {line}");
    }
}
