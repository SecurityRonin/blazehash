use blazehash::algorithm::Algorithm;
use blazehash::piecewise::hash_file_piecewise;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn piecewise_small_file_one_chunk() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hello world").unwrap();
    f.flush().unwrap();

    let results = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 1024).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].offset, 0);
    assert_eq!(results[0].chunk_size, 11);
}

#[test]
fn piecewise_splits_file() {
    let mut f = NamedTempFile::new().unwrap();
    let data = vec![0x42u8; 1000];
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let results = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 400).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].offset, 0);
    assert_eq!(results[0].chunk_size, 400);
    assert_eq!(results[1].offset, 400);
    assert_eq!(results[1].chunk_size, 400);
    assert_eq!(results[2].offset, 800);
    assert_eq!(results[2].chunk_size, 200);
}

#[test]
fn piecewise_different_chunks_different_hashes() {
    let mut f = NamedTempFile::new().unwrap();
    let mut data = vec![0x41u8; 100];
    data.extend(vec![0x42u8; 100]);
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let results = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 100).unwrap();
    assert_eq!(results.len(), 2);
    assert_ne!(
        results[0].hashes[&Algorithm::Blake3],
        results[1].hashes[&Algorithm::Blake3]
    );
}

#[test]
fn piecewise_empty_file() {
    let f = NamedTempFile::new().unwrap();
    let results = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 1024).unwrap();
    assert!(results.is_empty());
}

#[test]
fn piecewise_exact_chunk_multiple() {
    let mut f = NamedTempFile::new().unwrap();
    let data = vec![0x42u8; 200]; // exactly 2 chunks of 100
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let results = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 100).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].chunk_size, 100);
    assert_eq!(results[1].chunk_size, 100);
    assert_eq!(results[0].offset, 0);
    assert_eq!(results[1].offset, 100);
}

#[test]
fn piecewise_multiple_algorithms() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"piecewise multi algo test").unwrap();
    f.flush().unwrap();

    let algos = vec![Algorithm::Blake3, Algorithm::Sha256, Algorithm::Md5];
    let results = hash_file_piecewise(f.path(), &algos, 1024).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].hashes.len(), 3);
    for algo in &algos {
        assert!(results[0].hashes.contains_key(algo));
    }
}

#[test]
fn piecewise_nonexistent_file_returns_error() {
    let result = hash_file_piecewise(
        std::path::Path::new("/nonexistent/file.txt"),
        &[Algorithm::Blake3],
        1024,
    );
    assert!(result.is_err());
}

#[test]
fn piecewise_single_byte_file() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"x").unwrap();
    f.flush().unwrap();

    let results = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 1024).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].chunk_size, 1);
    assert_eq!(results[0].offset, 0);
}

#[test]
fn piecewise_hashes_match_full_file_hash() {
    // For a file that fits in one chunk, piecewise hash should match hash_file
    use blazehash::hash::hash_file;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"consistency check").unwrap();
    f.flush().unwrap();

    let piecewise = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 4096).unwrap();
    let full = hash_file(f.path(), &[Algorithm::Blake3]).unwrap();

    assert_eq!(piecewise.len(), 1);
    assert_eq!(piecewise[0].hashes[&Algorithm::Blake3], full.hashes[&Algorithm::Blake3]);
}
