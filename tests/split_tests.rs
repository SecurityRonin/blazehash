use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir, n: usize) -> std::path::PathBuf {
    let p = dir.path().join("big.hash");
    let mut content = String::from("## algorithm: blake3\n");
    for i in 1..=n {
        content.push_str(&format!("blake3  {:064x}  file{i:04}.txt\n", i));
    }
    fs::write(&p, &content).unwrap();
    p
}

fn count_entries(path: &std::path::Path) -> usize {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| {
            !l.trim().is_empty() && !l.trim().starts_with('#') && !l.trim().starts_with('%')
        })
        .count()
}

#[test]
fn test_split_creates_multiple_files() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 25);
    let out_base = dir.path().join("chunk");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "split",
            m.to_str().unwrap(),
            "--chunk",
            "10",
            "-o",
            out_base.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(dir.path().join("chunk_001.hash").exists());
    assert!(dir.path().join("chunk_002.hash").exists());
    assert!(dir.path().join("chunk_003.hash").exists());
}

#[test]
fn test_split_correct_entry_counts() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 25);
    let out_base = dir.path().join("part");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "split",
            m.to_str().unwrap(),
            "--chunk",
            "10",
            "-o",
            out_base.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(count_entries(&dir.path().join("part_001.hash")), 10);
    assert_eq!(count_entries(&dir.path().join("part_002.hash")), 10);
    assert_eq!(count_entries(&dir.path().join("part_003.hash")), 5);
}

#[test]
fn test_split_chunks_preserve_headers() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out_base = dir.path().join("chunk");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "split",
            m.to_str().unwrap(),
            "--chunk",
            "3",
            "-o",
            out_base.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(dir.path().join("chunk_001.hash")).unwrap();
    assert!(content.contains("## algorithm: blake3"));
}

#[test]
fn test_split_single_chunk_when_entries_fit() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out_base = dir.path().join("chunk");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "split",
            m.to_str().unwrap(),
            "--chunk",
            "100",
            "-o",
            out_base.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(dir.path().join("chunk_001.hash").exists());
    assert!(!dir.path().join("chunk_002.hash").exists());
}
