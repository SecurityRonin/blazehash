use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(
        &p,
        concat!(
            "## case: CASE-001\n",
            "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  zebra.txt\n",
            "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  alpha.txt\n",
            "blake3  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  beta.bin\n",
        ),
    )
    .unwrap();
    p
}

#[test]
fn test_sort_by_path_default() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["sort", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 3);
    let pos_alpha = data.iter().position(|l| l.contains("alpha.txt")).unwrap();
    let pos_beta = data.iter().position(|l| l.contains("beta.bin")).unwrap();
    let pos_zebra = data.iter().position(|l| l.contains("zebra.txt")).unwrap();
    assert!(pos_alpha < pos_beta, "alpha must come before beta");
    assert!(pos_beta < pos_zebra, "beta must come before zebra");
}

#[test]
fn test_sort_by_hash() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["sort", manifest.to_str().unwrap(), "--sort-by", "hash"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    let pos_a = data.iter().position(|l| l.contains("alpha.txt")).unwrap();
    let pos_b = data.iter().position(|l| l.contains("beta.bin")).unwrap();
    let pos_c = data.iter().position(|l| l.contains("zebra.txt")).unwrap();
    assert!(
        pos_a < pos_b && pos_b < pos_c,
        "entries must be sorted by hash"
    );
}

#[test]
fn test_sort_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["sort", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        first_line.starts_with("##"),
        "first line must be a header comment"
    );
}

#[test]
fn test_sort_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("sorted.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "sort",
            manifest.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("alpha.txt"));
    assert!(content.contains("beta.bin"));
}

#[test]
fn test_sort_by_algo() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["sort", manifest.to_str().unwrap(), "--sort-by", "algo"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    let pos_blake3 = data.iter().position(|l| l.contains("beta.bin")).unwrap();
    let pos_sha256_first = data.iter().position(|l| l.contains("sha256")).unwrap();
    assert!(
        pos_blake3 < pos_sha256_first,
        "blake3 must sort before sha256"
    );
}
