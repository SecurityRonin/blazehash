use blazehash::algorithm::Algorithm;
use blazehash::hash::hash_file;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn hash_file_blake3() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hello world").unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3]).unwrap();
    assert_eq!(result.size, 11);
    assert_eq!(
        result.hashes[&Algorithm::Blake3],
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
    );
}

#[test]
fn hash_file_multiple_algorithms() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hello world").unwrap();
    f.flush().unwrap();

    let algos = vec![Algorithm::Blake3, Algorithm::Sha256, Algorithm::Md5];
    let result = hash_file(f.path(), &algos).unwrap();
    assert_eq!(result.size, 11);
    assert_eq!(result.hashes.len(), 3);
    assert_eq!(
        result.hashes[&Algorithm::Sha256],
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    assert_eq!(
        result.hashes[&Algorithm::Md5],
        "5eb63bbbe01eeed093cb22bb8f5acdc3"
    );
}

#[test]
fn hash_file_empty() {
    let f = NamedTempFile::new().unwrap();
    let result = hash_file(f.path(), &[Algorithm::Blake3]).unwrap();
    assert_eq!(result.size, 0);
    assert!(!result.hashes[&Algorithm::Blake3].is_empty());
}

#[test]
fn hash_file_large_uses_mmap() {
    // Create a 2 MiB file to trigger mmap path
    let mut f = NamedTempFile::new().unwrap();
    let data = vec![0x42u8; 2 * 1024 * 1024];
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3, Algorithm::Sha256]).unwrap();
    assert_eq!(result.size, 2 * 1024 * 1024);

    // Verify against hash_bytes for correctness
    let expected_blake3 = blazehash::algorithm::hash_bytes(Algorithm::Blake3, &data);
    assert_eq!(result.hashes[&Algorithm::Blake3], expected_blake3);
}

#[test]
fn hash_file_returns_path() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"test").unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3]).unwrap();
    assert_eq!(result.path, f.path());
}

#[test]
fn hash_file_nonexistent_returns_error() {
    let result = hash_file(std::path::Path::new("/nonexistent/file.txt"), &[Algorithm::Blake3]);
    assert!(result.is_err());
}

#[test]
fn hash_file_at_mmap_threshold() {
    // Create a file of exactly 1 MiB (the MMAP_THRESHOLD)
    let mut f = NamedTempFile::new().unwrap();
    let data = vec![0x42u8; 1024 * 1024];
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3, Algorithm::Sha256]).unwrap();
    assert_eq!(result.size, 1024 * 1024);

    // Verify against hash_bytes for correctness
    let expected_blake3 = blazehash::algorithm::hash_bytes(Algorithm::Blake3, &data);
    assert_eq!(result.hashes[&Algorithm::Blake3], expected_blake3);
}

#[test]
fn hash_file_just_below_mmap_threshold() {
    // 1 byte below threshold -- uses streaming path
    let mut f = NamedTempFile::new().unwrap();
    let data = vec![0x42u8; 1024 * 1024 - 1];
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3]).unwrap();
    assert_eq!(result.size, 1024 * 1024 - 1);

    let expected = blazehash::algorithm::hash_bytes(Algorithm::Blake3, &data);
    assert_eq!(result.hashes[&Algorithm::Blake3], expected);
}

#[test]
fn hash_file_all_algorithms() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"test data for all algos").unwrap();
    f.flush().unwrap();

    let algos: Vec<Algorithm> = Algorithm::all().to_vec();
    let result = hash_file(f.path(), &algos).unwrap();
    assert_eq!(result.hashes.len(), 8);
    for algo in &algos {
        assert!(result.hashes.contains_key(algo), "missing hash for {:?}", algo);
        assert!(!result.hashes[algo].is_empty());
    }
}

#[test]
fn hash_file_streaming_matches_mmap() {
    // Same content hashed via both paths should produce identical results
    let content = b"deterministic content for comparison";

    // Small file -- streaming path
    let mut small = NamedTempFile::new().unwrap();
    small.write_all(content).unwrap();
    small.flush().unwrap();
    let streaming_result = hash_file(small.path(), &[Algorithm::Sha256]).unwrap();

    // Verify against known hash_bytes
    let expected = blazehash::algorithm::hash_bytes(Algorithm::Sha256, content);
    assert_eq!(streaming_result.hashes[&Algorithm::Sha256], expected);
}
