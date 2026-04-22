use blazehash::algorithm::Algorithm;
use blazehash::manifest::ManifestRecord;
use blazehash::watch::{check_file_against_baseline, ChangeStatus};
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn test_check_new_file_not_in_baseline() {
    let dir = tempdir().unwrap();
    let f = dir.path().join("new.bin");
    std::fs::write(&f, b"content").unwrap();
    let baseline: HashMap<PathBuf, ManifestRecord> = HashMap::new();
    let status = check_file_against_baseline(
        &f,
        &baseline,
        &[Algorithm::Blake3],
    )
    .unwrap();
    assert_eq!(status, ChangeStatus::New);
}

#[test]
fn test_check_unchanged_file_matches_baseline() {
    let dir = tempdir().unwrap();
    let f = dir.path().join("file.bin");
    std::fs::write(&f, b"content").unwrap();
    let h = blazehash::hash::hash_file(&f, &[Algorithm::Blake3], false, false, false, blazehash::hash::YaraOpts::no_yara()).unwrap();
    let blake3_hash = h.hashes[&Algorithm::Blake3].clone();
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, blake3_hash);
    let mut baseline = HashMap::new();
    baseline.insert(
        f.clone(),
        ManifestRecord {
            path: f.clone(),
            size: 7,
            hashes,
        },
    );
    let status = check_file_against_baseline(&f, &baseline, &[Algorithm::Blake3]).unwrap();
    assert_eq!(status, ChangeStatus::Unchanged);
}

#[test]
fn test_check_modified_file_differs_from_baseline() {
    let dir = tempdir().unwrap();
    let f = dir.path().join("file.bin");
    std::fs::write(&f, b"modified").unwrap();
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "aaa".to_string());
    let mut baseline = HashMap::new();
    baseline.insert(
        f.clone(),
        ManifestRecord {
            path: f.clone(),
            size: 8,
            hashes,
        },
    );
    let status = check_file_against_baseline(&f, &baseline, &[Algorithm::Blake3]).unwrap();
    assert_eq!(status, ChangeStatus::Modified);
}
