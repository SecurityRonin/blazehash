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
