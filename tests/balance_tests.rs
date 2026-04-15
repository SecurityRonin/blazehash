use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    let mut content = String::from("## case: test\n");
    for i in 1..=10 {
        content.push_str(&format!("sha256  {:064x}  file{i:02}.txt\n", i));
    }
    fs::write(&p, &content).unwrap();
    p
}

fn count_entries(path: &std::path::Path) -> usize {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#') && !l.trim().starts_with('%'))
        .count()
}

#[test]
fn test_balance_creates_correct_number_of_parts() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["balance", m.to_str().unwrap(), "--parts", "3", "-o", dir.path().to_str().unwrap()])
        .assert()
        .success();
    assert!(dir.path().join("test_part001.hash").exists());
    assert!(dir.path().join("test_part002.hash").exists());
    assert!(dir.path().join("test_part003.hash").exists());
    assert!(!dir.path().join("test_part004.hash").exists());
}

#[test]
fn test_balance_distributes_entries_evenly() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["balance", m.to_str().unwrap(), "--parts", "3", "-o", dir.path().to_str().unwrap()])
        .assert()
        .success();
    // 10 entries / 3 parts → 4, 3, 3
    assert_eq!(count_entries(&dir.path().join("test_part001.hash")), 4);
    assert_eq!(count_entries(&dir.path().join("test_part002.hash")), 3);
    assert_eq!(count_entries(&dir.path().join("test_part003.hash")), 3);
}

#[test]
fn test_balance_parts_cover_all_entries() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["balance", m.to_str().unwrap(), "--parts", "3", "-o", dir.path().to_str().unwrap()])
        .assert()
        .success();
    let mut all_paths: Vec<String> = Vec::new();
    for i in 1..=3 {
        let part_path = dir.path().join(format!("test_part{:03}.hash", i));
        let content = fs::read_to_string(&part_path).unwrap();
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with('%') {
                // Extract path (third field)
                let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
                if parts.len() == 3 {
                    all_paths.push(parts[2].to_string());
                }
            }
        }
    }
    assert_eq!(all_paths.len(), 10, "expected 10 total entries across all parts");
    for i in 1..=10 {
        let expected = format!("file{i:02}.txt");
        assert!(all_paths.contains(&expected), "missing entry: {expected}");
    }
}

#[test]
fn test_balance_missing_manifest_fails() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("nonexistent.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["balance", missing.to_str().unwrap(), "--parts", "2"])
        .assert()
        .failure();
}

#[test]
fn test_balance_parts_contain_headers() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["balance", m.to_str().unwrap(), "--parts", "3", "-o", dir.path().to_str().unwrap()])
        .assert()
        .success();
    for i in 1..=3 {
        let part_path = dir.path().join(format!("test_part{:03}.hash", i));
        let content = fs::read_to_string(&part_path).unwrap();
        assert!(
            content.contains("## case: test"),
            "part {i} missing header"
        );
    }
}
