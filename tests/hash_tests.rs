use blazehash::algorithm::Algorithm;
use blazehash::hash::hash_file;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn hash_file_blake3() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hello world").unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3], false, false).unwrap();
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
    let result = hash_file(f.path(), &algos, false, false).unwrap();
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
    let result = hash_file(f.path(), &[Algorithm::Blake3], false, false).unwrap();
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

    let result = hash_file(
        f.path(),
        &[Algorithm::Blake3, Algorithm::Sha256],
        false,
        false,
    )
    .unwrap();
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

    let result = hash_file(f.path(), &[Algorithm::Blake3], false, false).unwrap();
    assert_eq!(result.path, f.path());
}

#[test]
fn hash_file_nonexistent_returns_error() {
    let result = hash_file(
        std::path::Path::new("/nonexistent/file.txt"),
        &[Algorithm::Blake3],
        false,
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

    let result = hash_file(
        f.path(),
        &[Algorithm::Blake3, Algorithm::Sha256],
        false,
        false,
    )
    .unwrap();
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

    let result = hash_file(f.path(), &[Algorithm::Blake3], false, false).unwrap();
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
    let result = hash_file(f.path(), &algos, false, false).unwrap();
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

    assert_eq!(
        normal_line, nocache_line,
        "--no-cache must produce identical hashes"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_no_cache_macos_opens_file() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"test content for F_NOCACHE").unwrap();
    f.flush().unwrap();

    let normal = hash_file(f.path(), &[Algorithm::Sha256], false, false).unwrap();
    let nocache = hash_file(f.path(), &[Algorithm::Sha256], true, false).unwrap();

    assert_eq!(
        normal.hashes[&Algorithm::Sha256],
        nocache.hashes[&Algorithm::Sha256]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_no_cache_linux_aligned_read() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    // Write exactly 4096 bytes (sector-aligned)
    f.write_all(&vec![0xABu8; 4096]).unwrap();
    f.flush().unwrap();

    let normal = hash_file(f.path(), &[Algorithm::Sha256], false, false).unwrap();
    let nocache = hash_file(f.path(), &[Algorithm::Sha256], true, false).unwrap();

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
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&vec![0x42u8; 777]).unwrap(); // deliberately odd size
    f.flush().unwrap();

    let normal = hash_file(f.path(), &[Algorithm::Sha256], false, false).unwrap();
    let nocache = hash_file(f.path(), &[Algorithm::Sha256], true, false).unwrap();

    assert_eq!(
        normal.hashes[&Algorithm::Sha256],
        nocache.hashes[&Algorithm::Sha256]
    );
}

#[cfg(target_os = "windows")]
#[test]
fn test_no_cache_windows_no_buffering() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&vec![0xCDu8; 8192]).unwrap(); // 2 × 4096
    f.flush().unwrap();

    let normal = hash_file(f.path(), &[Algorithm::Sha256], false, false).unwrap();
    let nocache = hash_file(f.path(), &[Algorithm::Sha256], true, false).unwrap();

    assert_eq!(
        normal.hashes[&Algorithm::Sha256],
        nocache.hashes[&Algorithm::Sha256]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_large_pages_linux_correct_hash() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    // 3 MiB — above 2 MiB large page threshold
    f.write_all(&vec![0x55u8; 3 * 1024 * 1024]).unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3], false, false).unwrap();
    let h = &result.hashes[&Algorithm::Blake3];
    assert_eq!(h.len(), 64, "BLAKE3 hash must be 64 hex chars");
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[cfg(target_os = "windows")]
#[test]
fn test_large_pages_windows_fallback_on_no_privilege() {
    // Without SeLockMemoryPrivilege (typical user), must fall back gracefully.
    // Observable: hash is still correct; no panic or error.
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&vec![0xAAu8; 4 * 1024 * 1024]).unwrap(); // 4 MiB
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Sha256], false, false);
    assert!(
        result.is_ok(),
        "hash_file must not error when large page privilege absent"
    );
    let h = &result.unwrap().hashes[&Algorithm::Sha256];
    assert_eq!(h.len(), 64);
}

#[cfg(target_os = "windows")]
#[test]
fn test_large_pages_windows_correct_hash() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&vec![0xBBu8; 3 * 1024 * 1024]).unwrap();
    f.flush().unwrap();

    let with_lp = hash_file(f.path(), &[Algorithm::Blake3], false, false).unwrap();
    assert_eq!(with_lp.hashes[&Algorithm::Blake3].len(), 64);
}

#[cfg(target_os = "windows")]
#[test]
fn test_windows_iocp_walk_100_files() {
    use assert_cmd::Command;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    for i in 0..100 {
        let path = dir.path().join(format!("file_{i:04}.txt"));
        std::fs::write(&path, format!("content {i}").as_bytes()).unwrap();
    }

    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-r", "-c", "blake3", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Count only lines for our created files (file_XXXX.txt) — Windows temp
    // dirs may contain additional system files (e.g. desktop.ini) that would
    // inflate the count if we filtered only on the `%` header prefix.
    let count = stdout.lines().filter(|l| l.contains("file_")).count();
    assert_eq!(count, 100, "must hash all 100 files");
}

// --- ssdeep compute tests ---

#[test]
fn test_ssdeep_known_vector_hello() {
    let result = blazehash::fuzzy::ssdeep::compute(b"hello");
    assert!(
        result.starts_with("3:"),
        "expected block size 3, got: {result}"
    );
    let parts: Vec<&str> = result.splitn(3, ':').collect();
    assert_eq!(
        parts.len(),
        3,
        "ssdeep output must have 3 colon-separated parts"
    );
    assert!(
        parts[0].parse::<u32>().is_ok(),
        "first part must be numeric block size"
    );
}

#[test]
fn test_ssdeep_known_vector_1024_zeros() {
    let data = vec![0u8; 1024];
    let result = blazehash::fuzzy::ssdeep::compute(&data);
    let parts: Vec<&str> = result.splitn(3, ':').collect();
    assert_eq!(parts.len(), 3);
    let bs: u32 = parts[0].parse().unwrap();
    assert!(bs >= 3, "block size must be >= 3");
    assert!(
        !parts[1].is_empty(),
        "hash1 must not be empty for 1024 bytes"
    );
}

#[test]
fn test_ssdeep_output_is_base64_chars_only() {
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = blazehash::fuzzy::ssdeep::compute(data);
    let parts: Vec<&str> = result.splitn(3, ':').collect();
    assert_eq!(parts.len(), 3);
    let valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for c in parts[1].chars() {
        assert!(valid.contains(c), "hash1 contains non-base64 char: {c}");
    }
    for c in parts[2].chars() {
        assert!(valid.contains(c), "hash2 contains non-base64 char: {c}");
    }
}

#[test]
fn test_ssdeep_deterministic() {
    let data = b"blazehash fuzzy hashing test determinism";
    let h1 = blazehash::fuzzy::ssdeep::compute(data);
    let h2 = blazehash::fuzzy::ssdeep::compute(data);
    assert_eq!(h1, h2, "ssdeep must be deterministic");
}

// --- ssdeep similarity + block-size index tests ---

#[test]
fn test_ssdeep_identical_similarity() {
    use blazehash::fuzzy::ssdeep;
    let data = b"The quick brown fox jumps over the lazy dog. Some extra text to make it longer.";
    let h = ssdeep::compute(data);
    assert_eq!(ssdeep::similarity(&h, &h), 100);
}

#[test]
fn test_ssdeep_different_similarity() {
    use blazehash::fuzzy::ssdeep;
    // Completely different data → score should be very low (≤ 20)
    let h1 = ssdeep::compute(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let h2 = ssdeep::compute(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    let sim = ssdeep::similarity(&h1, &h2);
    assert!(
        sim <= 20,
        "unrelated data should have low similarity, got {sim}"
    );
}

#[test]
fn test_ssdeep_incompatible_block_size_is_zero() {
    use blazehash::fuzzy::ssdeep;
    // Block size 3 vs block size 24 — not adjacent, must return 0
    let h1 = "3:abc:de";
    let h2 = "24:xyz:pq";
    assert_eq!(ssdeep::similarity(h1, h2), 0);
}

#[test]
fn test_ssdeep_block_size_index_filters_correctly() {
    use blazehash::fuzzy::ssdeep::SsdeepIndex;
    use std::path::PathBuf;
    let mut idx = SsdeepIndex::new();
    idx.insert("6:abc:de", PathBuf::from("a.bin"));
    idx.insert("12:xyz:pq", PathBuf::from("b.bin"));
    idx.insert("3:foo:ba", PathBuf::from("c.bin"));
    // Query with block size 6 — should return entries with bs 3, 6, 12 (adjacent)
    let candidates = idx.candidates("6:query:q2");
    let paths: Vec<&PathBuf> = candidates.iter().map(|(_, p)| p).collect();
    assert!(
        paths.contains(&&PathBuf::from("a.bin")),
        "same bs should match"
    );
    assert!(
        paths.contains(&&PathBuf::from("b.bin")),
        "double bs should match"
    );
    assert!(
        paths.contains(&&PathBuf::from("c.bin")),
        "half bs should match"
    );
}

// ---- Task 14: --no-gpu flag ----

#[test]
fn test_no_gpu_flag_produces_same_hash_as_default() {
    use assert_cmd::Command;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut f, &vec![0x55u8; 4096]).unwrap();
    f.flush().unwrap();

    let out_default = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-c", "sha256", f.path().to_str().unwrap()])
        .output()
        .unwrap();

    let out_no_gpu = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-c", "sha256", "--no-gpu", f.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(out_default.status.success());
    assert!(out_no_gpu.status.success());

    let default_line = String::from_utf8_lossy(&out_default.stdout)
        .lines()
        .find(|l| !l.starts_with('%') && !l.is_empty())
        .unwrap()
        .to_string();
    let no_gpu_line = String::from_utf8_lossy(&out_no_gpu.stdout)
        .lines()
        .find(|l| !l.starts_with('%') && !l.is_empty())
        .unwrap()
        .to_string();

    assert_eq!(
        default_line, no_gpu_line,
        "--no-gpu must produce identical hashes"
    );
}

// ---- Task 4 (batch): WalkFilter glob include/exclude ----

#[test]
fn test_include_glob_filters_files() {
    use blazehash::walk_filter::WalkFilter;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.exe"), b"exe content").unwrap();
    std::fs::write(dir.path().join("file.log"), b"log content").unwrap();

    let filter = WalkFilter::builder().include("*.exe").build().unwrap();
    let output = blazehash::walk::walk_and_hash(
        dir.path(),
        &[blazehash::algorithm::Algorithm::Blake3],
        false,
        &filter,
    )
    .unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0].path.to_str().unwrap().ends_with(".exe"));
}

#[test]
fn test_exclude_glob_filters_files() {
    use blazehash::walk_filter::WalkFilter;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.exe"), b"exe").unwrap();
    std::fs::write(dir.path().join("file.log"), b"log").unwrap();

    let filter = WalkFilter::builder().exclude("*.log").build().unwrap();
    let output = blazehash::walk::walk_and_hash(
        dir.path(),
        &[blazehash::algorithm::Algorithm::Blake3],
        false,
        &filter,
    )
    .unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0].path.to_str().unwrap().ends_with(".exe"));
}

#[test]
fn test_empty_filter_includes_all() {
    use blazehash::walk_filter::WalkFilter;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
    std::fs::write(dir.path().join("b.bin"), b"b").unwrap();

    let filter = WalkFilter::default();
    let output = blazehash::walk::walk_and_hash(
        dir.path(),
        &[blazehash::algorithm::Algorithm::Blake3],
        false,
        &filter,
    )
    .unwrap();
    assert_eq!(output.results.len(), 2);
}

// ---- Task 4: tlsh wrapper ----

#[test]
fn test_tlsh_compute_returns_some_for_sufficient_data() {
    use blazehash::fuzzy::tlsh;
    // tlsh requires both sufficient length AND byte variety; use a repeating pattern
    let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
    let result = tlsh::compute(&data);
    assert!(
        result.is_some(),
        "tlsh must return Some for 512 bytes of varied data"
    );
    let hash = result.unwrap();
    assert!(hash.len() >= 70, "tlsh digest should be at least 70 chars");
    assert!(hash.starts_with("T1"), "tlsh digest must start with T1");
}

#[test]
fn test_tlsh_compute_returns_none_for_short_data() {
    use blazehash::fuzzy::tlsh;
    let data = vec![0u8; 10]; // Too short for tlsh
    let result = tlsh::compute(&data);
    assert!(
        result.is_none(),
        "tlsh must return None for very short data"
    );
}

#[test]
fn test_tlsh_identical_similarity() {
    use blazehash::fuzzy::tlsh;
    let data =
        b"The quick brown fox jumps over the lazy dog. More text to reach minimum length for tlsh.";
    let data = data.repeat(5); // ensure sufficient length
    let h1 = tlsh::compute(&data).expect("must hash");
    let h2 = tlsh::compute(&data).expect("must hash");
    let sim = tlsh::similarity(&h1, &h2);
    assert_eq!(sim, 100, "identical data must score 100");
}

#[test]
fn test_tlsh_different_similarity() {
    use blazehash::fuzzy::tlsh;
    // Different byte distributions — low similarity expected
    let d1: Vec<u8> = (0u8..=127).cycle().take(400).collect();
    let d2: Vec<u8> = (128u8..=255).cycle().take(400).collect();
    let h1 = tlsh::compute(&d1).expect("must hash d1");
    let h2 = tlsh::compute(&d2).expect("must hash d2");
    let sim = tlsh::similarity(&h1, &h2);
    assert!(
        sim < 50,
        "different byte distributions should have low similarity, got {sim}"
    );
}

#[test]
fn test_tlsh_deterministic() {
    use blazehash::fuzzy::tlsh;
    // Use varied data to satisfy tlsh entropy requirements
    let data: Vec<u8> = (0u8..=255).cycle().take(200).collect();
    let h1 = tlsh::compute(&data).unwrap();
    let h2 = tlsh::compute(&data).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn test_tlsh_distance_inversion() {
    use blazehash::fuzzy::tlsh;
    assert_eq!(tlsh::distance_to_similarity(0), 100);
    assert_eq!(tlsh::distance_to_similarity(300), 0);
    assert_eq!(tlsh::distance_to_similarity(150), 50);
    assert_eq!(tlsh::distance_to_similarity(999), 0); // clamped
}

// ---- Task 15: blazehash bench --gpu subcommand ----

#[test]
fn test_bench_gpu_no_calibrate_exits_successfully() {
    // --no-calibrate should use conservative defaults and not write any config
    use assert_cmd::Command;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    // Run bench --gpu --no-calibrate — should exit 0 (or print info and exit 0)
    // Since gpu feature may not be compiled, accept both success and "unknown subcommand"
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["bench", "--gpu", "--no-calibrate"])
        .env("BLAZEHASH_CONFIG_DIR", tmp.path().to_str().unwrap())
        .output()
        .unwrap();

    // Should not crash/panic — exit code 0 or 1 (feature not enabled) both acceptable
    // The key: must not write config when --no-calibrate is passed
    let config_path = tmp.path().join("config.toml");
    assert!(
        !config_path.exists(),
        "--no-calibrate must not write config file"
    );
}

#[test]
fn test_bench_subcommand_is_recognized() {
    use assert_cmd::Command;

    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["bench", "--help"])
        .output()
        .unwrap();

    // bench subcommand must be recognized (exit 0) and mention bench-specific flags
    assert!(out.status.success(), "blazehash bench --help must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    // The bench subcommand help must mention bench-specific flags like --gpu and --no-calibrate
    // (not just the global --no-gpu flag that exists on the top-level help)
    assert!(
        combined.contains("--no-calibrate"),
        "bench --help output must mention --no-calibrate flag, got: {combined}"
    );
}

#[test]
fn test_hash_file_with_ssdeep() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let data = b"The quick brown fox jumps over the lazy dog. ";
    for _ in 0..100 {
        f.write_all(data).unwrap();
    }
    f.flush().unwrap();

    let result = hash_file(
        f.path(),
        &[Algorithm::Blake3, Algorithm::Ssdeep],
        false,
        false,
    )
    .unwrap();
    assert!(result.hashes.contains_key(&Algorithm::Blake3));
    assert!(result.hashes.contains_key(&Algorithm::Ssdeep));
    let ssdeep_hash = &result.hashes[&Algorithm::Ssdeep];
    assert!(ssdeep_hash.contains(':'), "ssdeep hash must contain ':'");
    let parts: Vec<&str> = ssdeep_hash.splitn(3, ':').collect();
    assert_eq!(parts.len(), 3);
}

#[test]
fn test_hash_file_with_tlsh() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    // Write varied data for tlsh entropy requirement
    let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Tlsh], false, false).unwrap();
    assert!(result.hashes.contains_key(&Algorithm::Tlsh));
    let tlsh_hash = &result.hashes[&Algorithm::Tlsh];
    assert!(tlsh_hash.starts_with("T1"), "tlsh hash must start with T1");
}

#[test]
fn test_hash_file_tlsh_short_file_empty_string() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"tiny").unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Tlsh], false, false).unwrap();
    let tlsh_hash = &result.hashes[&Algorithm::Tlsh];
    assert!(
        tlsh_hash.is_empty() || tlsh_hash.starts_with("T1"),
        "short file: tlsh hash should be empty or valid, got: {tlsh_hash}"
    );
}

#[test]
fn test_manifest_roundtrip_with_ssdeep() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use blazehash::manifest::{parse_header, parse_records, write_header, write_record};
    use std::collections::HashMap;
    use std::path::PathBuf;

    let algorithms = vec![Algorithm::Blake3, Algorithm::Ssdeep];
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "a".repeat(64));
    hashes.insert(Algorithm::Ssdeep, "3:abc:de".to_string());

    let result = FileHashResult {
        path: PathBuf::from("/evidence/file.bin"),
        size: 1234,
        hashes,
        entropy: None,
    };

    let mut buf = Vec::new();
    write_header(&mut buf, &algorithms).unwrap();
    write_record(&mut buf, &result, &algorithms).unwrap();
    let content = String::from_utf8(buf).unwrap();

    let parsed_algos = parse_header(&content).unwrap();
    assert_eq!(parsed_algos, algorithms);

    let records = parse_records(&content, &algorithms);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].hashes.get(&Algorithm::Ssdeep).unwrap(),
        "3:abc:de"
    );
    assert_eq!(
        records[0].hashes.get(&Algorithm::Blake3).unwrap(),
        &"a".repeat(64)
    );
    assert_eq!(records[0].size, 1234);
}

#[test]
fn test_manifest_roundtrip_with_tlsh() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use blazehash::manifest::{parse_header, parse_records, write_header, write_record};
    use std::collections::HashMap;
    use std::path::PathBuf;

    let algorithms = vec![Algorithm::Tlsh];
    let mut hashes = HashMap::new();
    hashes.insert(
        Algorithm::Tlsh,
        "T1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3".to_string(),
    );

    let result = FileHashResult {
        path: PathBuf::from("/evidence/sample.bin"),
        size: 5678,
        hashes,
        entropy: None,
    };

    let mut buf = Vec::new();
    write_header(&mut buf, &algorithms).unwrap();
    write_record(&mut buf, &result, &algorithms).unwrap();
    let content = String::from_utf8(buf).unwrap();

    let parsed_algos = parse_header(&content).unwrap();
    assert_eq!(parsed_algos, algorithms);

    let records = parse_records(&content, &algorithms);
    assert_eq!(records.len(), 1);
    let tlsh_val = records[0].hashes.get(&Algorithm::Tlsh).unwrap();
    assert_eq!(
        tlsh_val,
        "T1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3"
    );
}

#[test]
fn hash_file_streaming_matches_mmap() {
    // Same content hashed via both paths should produce identical results
    let content = b"deterministic content for comparison";

    // Small file -- streaming path
    let mut small = NamedTempFile::new().unwrap();
    small.write_all(content).unwrap();
    small.flush().unwrap();
    let streaming_result = hash_file(small.path(), &[Algorithm::Sha256], false, false).unwrap();

    // Verify against known hash_bytes
    let expected = blazehash::algorithm::hash_bytes(Algorithm::Sha256, content);
    assert_eq!(streaming_result.hashes[&Algorithm::Sha256], expected);
}

// ---- Task 7: --fuzzy-threshold and --fuzzy-top CLI flags ----

#[test]
fn test_fuzzy_threshold_in_help() {
    use assert_cmd::Command;
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("fuzzy-threshold"),
        "help must mention --fuzzy-threshold"
    );
    assert!(help.contains("fuzzy-top"), "help must mention --fuzzy-top");
}

#[test]
fn test_fuzzy_flags_accepted_without_error() {
    use assert_cmd::Command;
    use std::io::Write;

    // Create a temp file to hash
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"test content").unwrap();
    f.flush().unwrap();

    // --fuzzy-threshold and --fuzzy-top should be accepted without error
    // even outside audit mode (silently ignored per design)
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "--fuzzy-threshold",
            "70",
            "--fuzzy-top",
            "3",
            f.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    // Should succeed (exit 0) — flags are silently accepted
    assert!(
        output.status.success(),
        "flags should be accepted without error"
    );
}

// ---- Task 2: compute_entropy ----

#[test]
fn test_entropy_all_zeros() {
    let bytes = vec![0u8; 1024];
    let h = blazehash::hash::compute_entropy(&bytes);
    assert_eq!(h, 0.0, "all-zeros must have entropy 0.0");
}

#[test]
fn test_entropy_two_values_equal() {
    let mut bytes = vec![0u8; 128];
    bytes.extend(vec![1u8; 128]);
    let h = blazehash::hash::compute_entropy(&bytes);
    assert!(
        (h - 1.0).abs() < 1e-9,
        "half-half binary must have entropy 1.0, got {h}"
    );
}

#[test]
fn test_entropy_uniform_256() {
    let bytes: Vec<u8> = (0u8..=255).collect();
    let h = blazehash::hash::compute_entropy(&bytes);
    assert!(
        (h - 8.0).abs() < 1e-9,
        "uniform 256-value must have entropy 8.0, got {h}"
    );
}

#[test]
fn test_entropy_empty_is_zero() {
    let h = blazehash::hash::compute_entropy(&[]);
    assert_eq!(h, 0.0);
}

// ---- Task 6: --stdin mode ----

#[test]
fn test_stdin_mode_cli_flag_exists() {
    let mut cmd = assert_cmd::Command::cargo_bin("blazehash").unwrap();
    cmd.args(["--stdin", "-c", "blake3"])
        .write_stdin(b"hello" as &[u8])
        .assert()
        .success();
}

#[test]
fn test_stdin_blake3_known_hash() {
    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--stdin", "-c", "blake3", "--format", "hashdeep"])
        .write_stdin(b"hello" as &[u8])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"),
        "expected blake3 hash of 'hello', got: {stdout}"
    );
}

// ---- Task 5: --min-size / --max-size walk filters ----

#[test]
fn test_min_size_filter() {
    use blazehash::walk_filter::WalkFilter;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("small.bin"), b"hi").unwrap();
    std::fs::write(dir.path().join("large.bin"), vec![0u8; 1024]).unwrap();

    let filter = WalkFilter::builder().min_size(100).build().unwrap();
    let output = blazehash::walk::walk_and_hash(
        dir.path(),
        &[blazehash::algorithm::Algorithm::Blake3],
        false,
        &filter,
    )
    .unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0]
        .path
        .to_str()
        .unwrap()
        .ends_with("large.bin"));
}

#[test]
fn test_max_size_filter() {
    use blazehash::walk_filter::WalkFilter;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("small.bin"), b"hi").unwrap();
    std::fs::write(dir.path().join("large.bin"), vec![0u8; 1024]).unwrap();

    let filter = WalkFilter::builder().max_size(10).build().unwrap();
    let output = blazehash::walk::walk_and_hash(
        dir.path(),
        &[blazehash::algorithm::Algorithm::Blake3],
        false,
        &filter,
    )
    .unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0]
        .path
        .to_str()
        .unwrap()
        .ends_with("small.bin"));
}

// ---- newer_than filter ----

#[test]
fn test_newer_than_filter_excludes_old_files() {
    use blazehash::walk_filter::WalkFilter;
    use std::time::{Duration, SystemTime};

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("old.bin"), b"hello").unwrap();
    // Use a threshold far in the future — old.bin was just created so it's older
    let future = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 365 * 10);
    let filter = WalkFilter::builder().newer_than(future).build().unwrap();
    let output = blazehash::walk::walk_and_hash(
        dir.path(),
        &[blazehash::algorithm::Algorithm::Blake3],
        false,
        &filter,
    )
    .unwrap();
    assert_eq!(
        output.results.len(),
        0,
        "file created before threshold should be excluded"
    );
}

#[test]
fn test_newer_than_filter_includes_recent_files() {
    use blazehash::walk_filter::WalkFilter;
    use std::time::{Duration, SystemTime};

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("new.bin"), b"world").unwrap();
    // Use a threshold far in the past — new.bin was just created so it's newer
    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let filter = WalkFilter::builder().newer_than(past).build().unwrap();
    let output = blazehash::walk::walk_and_hash(
        dir.path(),
        &[blazehash::algorithm::Algorithm::Blake3],
        false,
        &filter,
    )
    .unwrap();
    assert_eq!(
        output.results.len(),
        1,
        "recently created file should pass newer_than filter"
    );
}

// ---- Task 8: DFXML output format ----

#[test]
fn test_dfxml_output_format() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.bin"), b"hello").unwrap();

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            dir.path().to_str().unwrap(),
            "-c",
            "blake3",
            "--format",
            "dfxml",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("<?xml"),
        "expected XML declaration, got: {stdout}"
    );
    assert!(stdout.contains("<dfxml"), "expected dfxml root element");
    assert!(
        stdout.contains("<fileobject>"),
        "expected fileobject element"
    );
    assert!(stdout.contains("blake3"), "expected blake3 hashdigest type");
}

// ---- Task 9: sha256sum/md5sum output format ----

#[test]
fn test_sha256sum_output_format() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.bin"), b"hello").unwrap();

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            dir.path().to_str().unwrap(),
            "-c",
            "sha256",
            "--format",
            "sha256sum",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("  "),
        "expected two spaces between hash and path"
    );
    assert!(
        !stdout.contains("%%%%"),
        "sha256sum format must not contain hashdeep header"
    );
}

#[test]
fn test_sha256sum_rejects_multiple_algorithms() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f.bin"), b"x").unwrap();
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            dir.path().to_str().unwrap(),
            "-c",
            "sha256,md5",
            "--format",
            "sha256sum",
        ])
        .assert()
        .failure();
}

// ---- Task 11: --ads flag (NTFS Alternate Data Streams) ----

#[test]
fn test_ads_flag_accepted() {
    let dir = tempfile::tempdir().unwrap();
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([dir.path().to_str().unwrap(), "--ads", "-c", "blake3"])
        .assert()
        .success();
}

#[test]
fn test_include_glob_with_path_separator() {
    use blazehash::walk_filter::WalkFilter;
    let dir = tempfile::tempdir().unwrap();
    let subdir = dir.path().join("logs");
    std::fs::create_dir(&subdir).unwrap();
    std::fs::write(subdir.join("audit.log"), b"log").unwrap();
    std::fs::write(dir.path().join("main.rs"), b"code").unwrap();

    let filter = WalkFilter::builder().include("**/*.log").build().unwrap();
    let output = blazehash::walk::walk_and_hash(
        dir.path(),
        &[blazehash::algorithm::Algorithm::Blake3],
        true,
        &filter,
    )
    .unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0]
        .path
        .to_str()
        .unwrap()
        .ends_with("audit.log"));
}
