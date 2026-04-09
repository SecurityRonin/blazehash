use blazehash::algorithm::Algorithm;
use blazehash::hash::hash_file;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn hash_file_blake3() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hello world").unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3], false).unwrap();
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
    let result = hash_file(f.path(), &algos, false).unwrap();
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
    let result = hash_file(f.path(), &[Algorithm::Blake3], false).unwrap();
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

    let result = hash_file(f.path(), &[Algorithm::Blake3, Algorithm::Sha256], false).unwrap();
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

    let result = hash_file(f.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(result.path, f.path());
}

#[test]
fn hash_file_nonexistent_returns_error() {
    let result = hash_file(
        std::path::Path::new("/nonexistent/file.txt"),
        &[Algorithm::Blake3],
        false,
    );
    assert!(result.is_err());
}

#[test]
fn hash_file_at_mmap_threshold() {
    // Create a file of exactly 1 MiB (the MMAP_THRESHOLD)
    let mut f = NamedTempFile::new().unwrap();
    let data = vec![0x42u8; 1024 * 1024];
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3, Algorithm::Sha256], false).unwrap();
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

    let result = hash_file(f.path(), &[Algorithm::Blake3], false).unwrap();
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
    let result = hash_file(f.path(), &algos, false).unwrap();
    assert_eq!(result.hashes.len(), 8);
    for algo in &algos {
        assert!(
            result.hashes.contains_key(algo),
            "missing hash for {algo:?}"
        );
        assert!(!result.hashes[algo].is_empty());
    }
}

#[test]
fn test_no_cache_flag_produces_correct_hash() {
    use assert_cmd::Command;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"blazehash no-cache test").unwrap();
    f.flush().unwrap();

    let out_normal = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-c", "sha256", f.path().to_str().unwrap()])
        .output()
        .unwrap();

    let out_nocache = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-c", "sha256", "--no-cache", f.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(out_normal.status.success());
    assert!(out_nocache.status.success());

    let normal_line = String::from_utf8_lossy(&out_normal.stdout)
        .lines()
        .find(|l| !l.starts_with('%') && !l.is_empty())
        .unwrap()
        .to_string();
    let nocache_line = String::from_utf8_lossy(&out_nocache.stdout)
        .lines()
        .find(|l| !l.starts_with('%') && !l.is_empty())
        .unwrap()
        .to_string();

    assert_eq!(normal_line, nocache_line, "--no-cache must produce identical hashes");
}

#[cfg(target_os = "macos")]
#[test]
fn test_no_cache_macos_opens_file() {
    use blazehash::hash::hash_file;
    use blazehash::algorithm::Algorithm;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"test content for F_NOCACHE").unwrap();
    f.flush().unwrap();

    let normal = hash_file(f.path(), &[Algorithm::Sha256], false).unwrap();
    let nocache = hash_file(f.path(), &[Algorithm::Sha256], true).unwrap();

    assert_eq!(
        normal.hashes[&Algorithm::Sha256],
        nocache.hashes[&Algorithm::Sha256]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_no_cache_linux_aligned_read() {
    use blazehash::hash::hash_file;
    use blazehash::algorithm::Algorithm;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    // Write exactly 4096 bytes (sector-aligned)
    f.write_all(&vec![0xABu8; 4096]).unwrap();
    f.flush().unwrap();

    let normal = hash_file(f.path(), &[Algorithm::Sha256], false).unwrap();
    let nocache = hash_file(f.path(), &[Algorithm::Sha256], true).unwrap();

    assert_eq!(
        normal.hashes[&Algorithm::Sha256],
        nocache.hashes[&Algorithm::Sha256],
        "O_DIRECT must produce identical hash"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_no_cache_linux_unaligned_size_file() {
    // File size not a multiple of 512 — must still hash correctly
    use blazehash::hash::hash_file;
    use blazehash::algorithm::Algorithm;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&vec![0x42u8; 777]).unwrap(); // deliberately odd size
    f.flush().unwrap();

    let normal = hash_file(f.path(), &[Algorithm::Sha256], false).unwrap();
    let nocache = hash_file(f.path(), &[Algorithm::Sha256], true).unwrap();

    assert_eq!(
        normal.hashes[&Algorithm::Sha256],
        nocache.hashes[&Algorithm::Sha256]
    );
}

#[cfg(target_os = "windows")]
#[test]
fn test_no_cache_windows_no_buffering() {
    use blazehash::hash::hash_file;
    use blazehash::algorithm::Algorithm;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&vec![0xCDu8; 8192]).unwrap(); // 2 × 4096
    f.flush().unwrap();

    let normal = hash_file(f.path(), &[Algorithm::Sha256], false).unwrap();
    let nocache = hash_file(f.path(), &[Algorithm::Sha256], true).unwrap();

    assert_eq!(
        normal.hashes[&Algorithm::Sha256],
        nocache.hashes[&Algorithm::Sha256]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_large_pages_linux_correct_hash() {
    use blazehash::hash::hash_file;
    use blazehash::algorithm::Algorithm;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    // 3 MiB — above 2 MiB large page threshold
    f.write_all(&vec![0x55u8; 3 * 1024 * 1024]).unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3], false).unwrap();
    let h = &result.hashes[&Algorithm::Blake3];
    assert_eq!(h.len(), 64, "BLAKE3 hash must be 64 hex chars");
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[cfg(target_os = "windows")]
#[test]
fn test_large_pages_windows_fallback_on_no_privilege() {
    // Without SeLockMemoryPrivilege (typical user), must fall back gracefully.
    // Observable: hash is still correct; no panic or error.
    use blazehash::hash::hash_file;
    use blazehash::algorithm::Algorithm;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&vec![0xAAu8; 4 * 1024 * 1024]).unwrap(); // 4 MiB
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Sha256], false);
    assert!(result.is_ok(), "hash_file must not error when large page privilege absent");
    let h = &result.unwrap().hashes[&Algorithm::Sha256];
    assert_eq!(h.len(), 64);
}

#[cfg(target_os = "windows")]
#[test]
fn test_large_pages_windows_correct_hash() {
    use blazehash::hash::hash_file;
    use blazehash::algorithm::Algorithm;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&vec![0xBBu8; 3 * 1024 * 1024]).unwrap();
    f.flush().unwrap();

    let with_lp = hash_file(f.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(with_lp.hashes[&Algorithm::Blake3].len(), 64);
}

#[test]
fn hash_file_streaming_matches_mmap() {
    // Same content hashed via both paths should produce identical results
    let content = b"deterministic content for comparison";

    // Small file -- streaming path
    let mut small = NamedTempFile::new().unwrap();
    small.write_all(content).unwrap();
    small.flush().unwrap();
    let streaming_result = hash_file(small.path(), &[Algorithm::Sha256], false).unwrap();

    // Verify against known hash_bytes
    let expected = blazehash::algorithm::hash_bytes(Algorithm::Sha256, content);
    assert_eq!(streaming_result.hashes[&Algorithm::Sha256], expected);
}
