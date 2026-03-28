use blazehash::algorithm::Algorithm;
use blazehash::walk::walk_and_hash;
use std::fs;
use tempfile::TempDir;

#[test]
fn walk_empty_directory() {
    let dir = TempDir::new().unwrap();
    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert!(results.is_empty());
}

#[test]
fn walk_flat_directory() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    fs::write(dir.path().join("b.txt"), b"bbb").unwrap();

    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(results.len(), 2);
    for r in &results {
        assert_eq!(r.size, 3);
        assert!(r.hashes.contains_key(&Algorithm::Blake3));
    }
}

#[test]
fn walk_recursive() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("root.txt"), b"root").unwrap();
    let sub = dir.path().join("subdir");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("nested.txt"), b"nested").unwrap();

    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], true).unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn walk_non_recursive_skips_subdirs() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("root.txt"), b"root").unwrap();
    let sub = dir.path().join("subdir");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("nested.txt"), b"nested").unwrap();

    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn walk_multiple_algorithms() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello world").unwrap();

    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let results = walk_and_hash(dir.path(), &algos, false).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].hashes.len(), 2);
}

#[test]
fn walk_skips_directories_and_symlinks() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("file.txt"), b"content").unwrap();
    fs::create_dir(dir.path().join("subdir")).unwrap();

    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], true).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].path.ends_with("file.txt"));
}
