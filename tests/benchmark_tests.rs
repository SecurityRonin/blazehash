//! Performance benchmark tests: blazehash vs hashdeep.
//!
//! All tests are `#[ignore]` — run with:
//!   cargo test --release --test benchmark_tests -- --ignored --nocapture --test-threads=1
//!
//! Requires `hashdeep` to be installed (brew install md5deep / apt install hashdeep).
//! Tests skip gracefully if hashdeep is not found.
//!
//! Methodology:
//! - All benchmarks include a warmup pass to eliminate filesystem cache bias
//! - Each timed scenario runs both tools on warm cache for fair comparison
//! - Large file tests use 256 MiB to amortize process startup overhead
//! - Results report wall-clock time including process spawn

use assert_cmd::Command;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process;
use std::time::Instant;
use tempfile::TempDir;

/// Shared algorithms between blazehash and hashdeep.
const SHARED_ALGOS: &str = "md5,sha1,sha256,tiger,whirlpool";

/// Check whether hashdeep is available on PATH.
fn hashdeep_available() -> bool {
    process::Command::new("hashdeep")
        .arg("-V")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run blazehash and return (stdout, duration).
fn run_blazehash(args: &[&str]) -> (String, std::time::Duration) {
    let start = Instant::now();
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    let elapsed = start.elapsed();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "blazehash failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (stdout, elapsed)
}

/// Run hashdeep and return (stdout, duration).
fn run_hashdeep(args: &[&str]) -> (String, std::time::Duration) {
    let start = Instant::now();
    let output = process::Command::new("hashdeep")
        .args(args)
        .output()
        .expect("failed to run hashdeep");
    let elapsed = start.elapsed();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "hashdeep failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (stdout, elapsed)
}

/// Warmup: run both tools once (discard results) to populate page cache.
fn warmup(blazehash_args: &[&str], hashdeep_args: &[&str]) {
    let _ = run_hashdeep(hashdeep_args);
    let _ = run_blazehash(blazehash_args);
}

/// Warmup for blazehash-only benchmarks.
fn warmup_blazehash(args: &[&str]) {
    let _ = run_blazehash(args);
}

/// Parse a hashdeep-format manifest into (path -> {algo -> hash}) map.
/// Works for both blazehash and hashdeep output.
fn parse_manifest(content: &str) -> HashMap<String, HashMap<String, String>> {
    let mut algorithms: Vec<String> = Vec::new();
    let mut records: HashMap<String, HashMap<String, String>> = HashMap::new();

    for line in content.lines() {
        if line.starts_with("%%%% size,") {
            let cols = &line["%%%% size,".len()..];
            let parts: Vec<&str> = cols.split(',').collect();
            algorithms = parts[..parts.len() - 1]
                .iter()
                .map(|s| s.to_string())
                .collect();
            continue;
        }
        if line.starts_with("%%%%") || line.starts_with('#') || line.is_empty() {
            continue;
        }
        let expected = algorithms.len() + 2;
        let parts: Vec<&str> = line.splitn(expected, ',').collect();
        if parts.len() < expected {
            continue;
        }
        let filename = parts[algorithms.len() + 1].to_string();
        let mut hashes = HashMap::new();
        for (i, algo) in algorithms.iter().enumerate() {
            hashes.insert(algo.clone(), parts[i + 1].to_string());
        }
        records.insert(filename, hashes);
    }
    records
}

/// Print a comparison result.
fn report_timing(label: &str, blazehash_ms: f64, hashdeep_ms: f64) {
    let speedup = hashdeep_ms / blazehash_ms;
    eprintln!(
        "\n  {label}:\n    blazehash: {blazehash_ms:.1}ms\n    hashdeep:  {hashdeep_ms:.1}ms\n    speedup:   {speedup:.2}x",
    );
}

/// Create a file filled with pseudo-random data (deterministic via simple LCG).
fn create_data_file(path: &Path, size: usize) {
    let mut data = vec![0u8; size];
    let mut state: u64 = 0xDEAD_BEEF;
    for byte in data.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 33) as u8;
    }
    fs::write(path, &data).unwrap();
}

// ──────────────────────────────────────────────────────────────
// Benchmark: Single large file throughput (256 MiB)
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn bench_single_large_file() {
    if !hashdeep_available() {
        eprintln!("SKIP: hashdeep not installed");
        return;
    }

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("large.bin");
    create_data_file(&file, 256 * 1024 * 1024); // 256 MiB
    let file_str = file.to_str().unwrap();

    eprintln!("\n=== Single Large File (256 MiB) ===");

    for algo in ["md5", "sha1", "sha256", "tiger", "whirlpool"] {
        warmup(&["-c", algo, file_str], &["-c", algo, file_str]);
        let (_, bh_dur) = run_blazehash(&["-c", algo, file_str]);
        let (_, hd_dur) = run_hashdeep(&["-c", algo, file_str]);
        report_timing(
            algo,
            bh_dur.as_secs_f64() * 1000.0,
            hd_dur.as_secs_f64() * 1000.0,
        );
    }

    // All shared algorithms at once
    warmup(
        &["-c", SHARED_ALGOS, file_str],
        &["-c", SHARED_ALGOS, file_str],
    );
    let (_, bh_dur) = run_blazehash(&["-c", SHARED_ALGOS, file_str]);
    let (_, hd_dur) = run_hashdeep(&["-c", SHARED_ALGOS, file_str]);
    report_timing(
        "all 5 algos combined",
        bh_dur.as_secs_f64() * 1000.0,
        hd_dur.as_secs_f64() * 1000.0,
    );
}

// ──────────────────────────────────────────────────────────────
// Benchmark: Many small files (I/O overhead)
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn bench_many_small_files() {
    if !hashdeep_available() {
        eprintln!("SKIP: hashdeep not installed");
        return;
    }

    let dir = TempDir::new().unwrap();
    for i in 0..1000 {
        let file = dir.path().join(format!("file_{i:04}.bin"));
        create_data_file(&file, 4096);
    }
    let dir_str = dir.path().to_str().unwrap();

    eprintln!("\n=== Many Small Files (1000 x 4 KiB) ===");

    // SHA-256 only
    warmup(
        &["-r", "-c", "sha256", dir_str],
        &["-r", "-c", "sha256", dir_str],
    );
    let (_, bh_dur) = run_blazehash(&["-r", "-c", "sha256", dir_str]);
    let (_, hd_dur) = run_hashdeep(&["-r", "-c", "sha256", dir_str]);
    report_timing(
        "1000 files, SHA-256",
        bh_dur.as_secs_f64() * 1000.0,
        hd_dur.as_secs_f64() * 1000.0,
    );

    // All 5 algos
    warmup(
        &["-r", "-c", SHARED_ALGOS, dir_str],
        &["-r", "-c", SHARED_ALGOS, dir_str],
    );
    let (_, bh_dur) = run_blazehash(&["-r", "-c", SHARED_ALGOS, dir_str]);
    let (_, hd_dur) = run_hashdeep(&["-r", "-c", SHARED_ALGOS, dir_str]);
    report_timing(
        "1000 files, all 5 algos",
        bh_dur.as_secs_f64() * 1000.0,
        hd_dur.as_secs_f64() * 1000.0,
    );
}

// ──────────────────────────────────────────────────────────────
// Benchmark: Recursive directory walk
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn bench_recursive_walk() {
    if !hashdeep_available() {
        eprintln!("SKIP: hashdeep not installed");
        return;
    }

    let dir = TempDir::new().unwrap();
    // 5 x 5 x 20 = 500 files, 16 KiB each = 8 MiB total
    for i in 0..5 {
        let level1 = dir.path().join(format!("dir_{i}"));
        fs::create_dir(&level1).unwrap();
        for j in 0..5 {
            let level2 = level1.join(format!("sub_{j}"));
            fs::create_dir(&level2).unwrap();
            for k in 0..20 {
                let file = level2.join(format!("data_{k}.bin"));
                create_data_file(&file, 16384);
            }
        }
    }
    let dir_str = dir.path().to_str().unwrap();

    eprintln!("\n=== Recursive Walk (500 files, 3 levels, 8 MiB total) ===");

    warmup(
        &["-r", "-c", "sha256", dir_str],
        &["-r", "-c", "sha256", dir_str],
    );
    let (_, bh_dur) = run_blazehash(&["-r", "-c", "sha256", dir_str]);
    let (_, hd_dur) = run_hashdeep(&["-r", "-c", "sha256", dir_str]);
    report_timing(
        "recursive SHA-256",
        bh_dur.as_secs_f64() * 1000.0,
        hd_dur.as_secs_f64() * 1000.0,
    );

    warmup(
        &["-r", "-c", SHARED_ALGOS, dir_str],
        &["-r", "-c", SHARED_ALGOS, dir_str],
    );
    let (_, bh_dur) = run_blazehash(&["-r", "-c", SHARED_ALGOS, dir_str]);
    let (_, hd_dur) = run_hashdeep(&["-r", "-c", SHARED_ALGOS, dir_str]);
    report_timing(
        "recursive all 5 algos",
        bh_dur.as_secs_f64() * 1000.0,
        hd_dur.as_secs_f64() * 1000.0,
    );
}

// ──────────────────────────────────────────────────────────────
// Benchmark: Piecewise hashing
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn bench_piecewise_hashing() {
    if !hashdeep_available() {
        eprintln!("SKIP: hashdeep not installed");
        return;
    }

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("piecewise.bin");
    create_data_file(&file, 64 * 1024 * 1024); // 64 MiB
    let file_str = file.to_str().unwrap();

    eprintln!("\n=== Piecewise Hashing (64 MiB, 1M chunks) ===");

    warmup(
        &["-p", "1M", "-c", "sha256", file_str],
        &["-p", "1048576", "-c", "sha256", file_str],
    );
    let (_, bh_dur) = run_blazehash(&["-p", "1M", "-c", "sha256", file_str]);
    let (_, hd_dur) = run_hashdeep(&["-p", "1048576", "-c", "sha256", file_str]);
    report_timing(
        "piecewise SHA-256 (1M chunks)",
        bh_dur.as_secs_f64() * 1000.0,
        hd_dur.as_secs_f64() * 1000.0,
    );

    warmup(
        &["-p", "1M", "-c", SHARED_ALGOS, file_str],
        &["-p", "1048576", "-c", SHARED_ALGOS, file_str],
    );
    let (_, bh_dur) = run_blazehash(&["-p", "1M", "-c", SHARED_ALGOS, file_str]);
    let (_, hd_dur) = run_hashdeep(&["-p", "1048576", "-c", SHARED_ALGOS, file_str]);
    report_timing(
        "piecewise all 5 algos (1M chunks)",
        bh_dur.as_secs_f64() * 1000.0,
        hd_dur.as_secs_f64() * 1000.0,
    );
}

// ──────────────────────────────────────────────────────────────
// Correctness: Hash value compatibility
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn compat_hash_values_match() {
    if !hashdeep_available() {
        eprintln!("SKIP: hashdeep not installed");
        return;
    }

    let dir = TempDir::new().unwrap();

    let test_cases: &[(&str, usize)] = &[
        ("empty.bin", 0),
        ("tiny.bin", 1),
        ("small.bin", 1000),
        ("medium.bin", 100_000),
        ("boundary.bin", 1024 * 1024),
    ];

    for (name, size) in test_cases {
        let file = dir.path().join(name);
        create_data_file(&file, *size);
    }

    eprintln!("\n=== Hash Compatibility Check ===");

    for algo in ["md5", "sha1", "sha256", "tiger", "whirlpool"] {
        for (name, _) in test_cases {
            let file = dir.path().join(name);
            let file_str = file.to_str().unwrap();

            let (bh_out, _) = run_blazehash(&["-c", algo, file_str]);
            let (hd_out, _) = run_hashdeep(&["-c", algo, file_str]);

            let bh_records = parse_manifest(&bh_out);
            let hd_records = parse_manifest(&hd_out);

            assert_eq!(
                bh_records.len(),
                1,
                "blazehash: expected 1 record for {name}"
            );
            assert_eq!(
                hd_records.len(),
                1,
                "hashdeep: expected 1 record for {name}"
            );

            let bh_hashes = bh_records.values().next().unwrap();
            let hd_hashes = hd_records.values().next().unwrap();
            let bh_hash = &bh_hashes[algo];
            let hd_hash = &hd_hashes[algo];

            assert_eq!(
                bh_hash, hd_hash,
                "hash mismatch for {algo} on {name}: blazehash={bh_hash}, hashdeep={hd_hash}"
            );
            eprintln!("  {algo:>10} x {name:<16} OK");
        }
    }
}

// ──────────────────────────────────────────────────────────────
// Correctness: Multi-algorithm output compatibility
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn compat_multi_algo_values_match() {
    if !hashdeep_available() {
        eprintln!("SKIP: hashdeep not installed");
        return;
    }

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("multi.bin");
    create_data_file(&file, 50_000);
    let file_str = file.to_str().unwrap();

    eprintln!("\n=== Multi-Algorithm Compatibility ===");

    let (bh_out, _) = run_blazehash(&["-c", SHARED_ALGOS, file_str]);
    let (hd_out, _) = run_hashdeep(&["-c", SHARED_ALGOS, file_str]);

    let bh_records = parse_manifest(&bh_out);
    let hd_records = parse_manifest(&hd_out);

    let bh_hashes = bh_records.values().next().unwrap();
    let hd_hashes = hd_records.values().next().unwrap();

    for algo in ["md5", "sha1", "sha256", "tiger", "whirlpool"] {
        let bh_hash = &bh_hashes[algo];
        let hd_hash = &hd_hashes[algo];
        assert_eq!(
            bh_hash, hd_hash,
            "multi-algo mismatch for {algo}: blazehash={bh_hash}, hashdeep={hd_hash}"
        );
        eprintln!("  {algo:>10}: {bh_hash} OK");
    }
}

// ──────────────────────────────────────────────────────────────
// Correctness: Audit cross-compatibility
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn compat_audit_hashdeep_manifest() {
    if !hashdeep_available() {
        eprintln!("SKIP: hashdeep not installed");
        return;
    }

    let dir = TempDir::new().unwrap();
    for i in 0..5 {
        let file = dir.path().join(format!("file_{i}.txt"));
        fs::write(&file, format!("content of file {i}")).unwrap();
    }
    let manifest = dir.path().join("manifest_hd.hash");
    let dir_str = dir.path().to_str().unwrap();
    let manifest_str = manifest.to_str().unwrap();

    eprintln!("\n=== Cross-Tool Audit Compatibility ===");

    let (hd_out, _) = run_hashdeep(&["-r", "-c", "sha256", dir_str]);
    fs::write(&manifest, &hd_out).unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-a", "-k", manifest_str, "-r", dir_str])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    eprintln!("  blazehash audit of hashdeep manifest:\n  {stdout}");

    assert!(
        stdout.contains("Files matched: 5") || stdout.contains("Files matched: 6"),
        "expected all files to match, got: {stdout}"
    );
    assert!(
        stdout.contains("Files changed: 0"),
        "expected no changed files, got: {stdout}"
    );
}

// ──────────────────────────────────────────────────────────────
// Correctness: Piecewise hash compatibility
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn compat_piecewise_values_match() {
    if !hashdeep_available() {
        eprintln!("SKIP: hashdeep not installed");
        return;
    }

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("piecewise.bin");
    create_data_file(&file, 10_000);
    let file_str = file.to_str().unwrap();

    eprintln!("\n=== Piecewise Hash Compatibility (10 KiB, 4K chunks) ===");

    let (bh_out, _) = run_blazehash(&["-p", "4096", "-c", "sha256", file_str]);
    let (hd_out, _) = run_hashdeep(&["-p", "4096", "-c", "sha256", file_str]);

    let bh_data: Vec<&str> = bh_out
        .lines()
        .filter(|l| !l.starts_with("%%") && !l.starts_with('#') && !l.is_empty())
        .collect();
    let hd_data: Vec<&str> = hd_out
        .lines()
        .filter(|l| !l.starts_with("%%") && !l.starts_with('#') && !l.is_empty())
        .collect();

    assert_eq!(
        bh_data.len(),
        hd_data.len(),
        "piecewise chunk count mismatch: blazehash={}, hashdeep={}",
        bh_data.len(),
        hd_data.len()
    );

    for (i, (bh_line, hd_line)) in bh_data.iter().zip(hd_data.iter()).enumerate() {
        let bh_parts: Vec<&str> = bh_line.splitn(3, ',').collect();
        let hd_parts: Vec<&str> = hd_line.splitn(3, ',').collect();

        assert_eq!(
            bh_parts[0], hd_parts[0],
            "chunk {i} size mismatch: blazehash={}, hashdeep={}",
            bh_parts[0], hd_parts[0]
        );
        assert_eq!(
            bh_parts[1], hd_parts[1],
            "chunk {i} hash mismatch: blazehash={}, hashdeep={}",
            bh_parts[1], hd_parts[1]
        );
        eprintln!("  chunk {i}: size={} hash={} OK", bh_parts[0], bh_parts[1]);
    }
}

// ──────────────────────────────────────────────────────────────
// Benchmark: BLAKE3 advantage (blazehash-only, no hashdeep)
// Shows what you gain by using BLAKE3 instead of legacy algos
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn bench_blake3_advantage() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("blake3.bin");
    create_data_file(&file, 256 * 1024 * 1024); // 256 MiB
    let file_str = file.to_str().unwrap();

    eprintln!("\n=== BLAKE3 Advantage (256 MiB, blazehash only) ===");

    for algo in [
        "blake3",
        "sha256",
        "sha512",
        "sha3-256",
        "md5",
        "sha1",
        "tiger",
        "whirlpool",
    ] {
        warmup_blazehash(&["-c", algo, file_str]);
        let (_, dur) = run_blazehash(&["-c", algo, file_str]);
        eprintln!("  {algo:>10}: {:.1}ms", dur.as_secs_f64() * 1000.0);
    }

    // All 8 algorithms at once
    let all_algos = "blake3,sha256,sha512,sha3-256,md5,sha1,tiger,whirlpool";
    warmup_blazehash(&["-c", all_algos, file_str]);
    let (_, dur) = run_blazehash(&["-c", all_algos, file_str]);
    eprintln!("  {:>10}: {:.1}ms", "all 8", dur.as_secs_f64() * 1000.0);
}

// ──────────────────────────────────────────────────────────────
// Format: Manifest format interoperability
// ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn compat_manifest_format_structure() {
    if !hashdeep_available() {
        eprintln!("SKIP: hashdeep not installed");
        return;
    }

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("format.txt");
    fs::write(&file, b"format test content").unwrap();
    let file_str = file.to_str().unwrap();

    eprintln!("\n=== Manifest Format Structure ===");

    let (bh_out, _) = run_blazehash(&["-c", "sha256", file_str]);
    let (hd_out, _) = run_hashdeep(&["-c", "sha256", file_str]);

    assert!(
        bh_out.contains("HASHDEEP-1.0"),
        "blazehash missing HASHDEEP-1.0 header"
    );
    assert!(
        hd_out.contains("HASHDEEP-1.0"),
        "hashdeep missing HASHDEEP-1.0 header"
    );

    assert!(
        bh_out.contains("%%%% size,sha256,filename"),
        "blazehash missing column definition"
    );
    assert!(
        hd_out.contains("%%%% size,sha256,filename"),
        "hashdeep missing column definition"
    );

    let bh_data_count = bh_out
        .lines()
        .filter(|l| !l.starts_with("%%") && !l.starts_with('#') && !l.is_empty())
        .count();
    let hd_data_count = hd_out
        .lines()
        .filter(|l| !l.starts_with("%%") && !l.starts_with('#') && !l.is_empty())
        .count();
    assert_eq!(
        bh_data_count, hd_data_count,
        "data line count differs: blazehash={bh_data_count}, hashdeep={hd_data_count}"
    );

    eprintln!("  Both produce HASHDEEP-1.0 header: OK");
    eprintln!("  Both produce matching column definition: OK");
    eprintln!("  Both produce {bh_data_count} data line(s): OK");
}
