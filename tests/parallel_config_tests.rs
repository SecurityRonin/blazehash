/// TDD RED: parallel threshold config — calibration and runtime load/save.
///
/// Run:
///   cargo test --test parallel_config_tests
use std::path::PathBuf;

use blazehash::parallel_config::{ParallelConfig, DEFAULT_PARALLEL_THRESHOLD_BYTES};

// ── 1. Default value ──────────────────────────────────────────────────────────

#[test]
fn test_default_threshold_is_64kib() {
    let cfg = ParallelConfig::default();
    assert_eq!(cfg.parallel_threshold_bytes, DEFAULT_PARALLEL_THRESHOLD_BYTES);
    assert_eq!(DEFAULT_PARALLEL_THRESHOLD_BYTES, 64 * 1024);
}

// ── 2. should_parallelize() decision function ─────────────────────────────────

#[test]
fn test_should_parallelize_above_threshold() {
    let cfg = ParallelConfig {
        parallel_threshold_bytes: 64 * 1024,
        calibrated_at: String::new(),
        cpu_info: String::new(),
    };
    assert!(cfg.should_parallelize(64 * 1024));
    assert!(cfg.should_parallelize(1024 * 1024));
    assert!(cfg.should_parallelize(u64::MAX));
}

#[test]
fn test_should_not_parallelize_below_threshold() {
    let cfg = ParallelConfig {
        parallel_threshold_bytes: 64 * 1024,
        calibrated_at: String::new(),
        cpu_info: String::new(),
    };
    assert!(!cfg.should_parallelize(1));
    assert!(!cfg.should_parallelize(1024));
    assert!(!cfg.should_parallelize(64 * 1024 - 1));
}

// ── 3. Load returns default when config file missing ───────────────────────────

#[test]
fn test_load_or_default_returns_default_when_no_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("parallel.toml");
    let cfg = ParallelConfig::load_or_default(&path);
    assert_eq!(cfg.parallel_threshold_bytes, DEFAULT_PARALLEL_THRESHOLD_BYTES);
}

// ── 4. Save / load roundtrip ──────────────────────────────────────────────────

#[test]
fn test_save_and_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("parallel.toml");

    let original = ParallelConfig {
        parallel_threshold_bytes: 128 * 1024,
        calibrated_at: "2026-04-10".to_string(),
        cpu_info: "Apple M4 Pro".to_string(),
    };
    original.save(&path).expect("save should succeed");

    let loaded = ParallelConfig::load_or_default(&path);
    assert_eq!(loaded.parallel_threshold_bytes, 128 * 1024);
    assert_eq!(loaded.calibrated_at, "2026-04-10");
    assert_eq!(loaded.cpu_info, "Apple M4 Pro");
}

// ── 5. Config path respects BLAZEHASH_CONFIG_DIR env var ─────────────────────

#[test]
fn test_config_path_respects_env_var() {
    let dir = tempfile::tempdir().unwrap();
    // Safety: single-threaded test process for env mutation
    std::env::set_var("BLAZEHASH_CONFIG_DIR", dir.path().to_str().unwrap());
    let path = ParallelConfig::config_path();
    std::env::remove_var("BLAZEHASH_CONFIG_DIR");

    assert!(path.starts_with(dir.path()));
    assert_eq!(path.file_name().unwrap(), "config.toml");
}

// ── 6. Calibration produces a config with a sensible threshold ────────────────

#[test]
fn test_calibrate_produces_positive_threshold() {
    // calibrate() does real timing — we only assert the output is structurally valid
    let cfg = blazehash::parallel_config::calibrate();
    assert!(cfg.parallel_threshold_bytes > 0);
    assert!(!cfg.calibrated_at.is_empty());
    assert!(!cfg.cpu_info.is_empty());
}

// ── 7. bench command writes parallel.toml ────────────────────────────────────

#[test]
fn test_bench_calibrate_parallel_writes_config() {
    let dir = tempfile::tempdir().unwrap();
    let path: PathBuf = dir.path().join("parallel.toml");

    // Use calibrate_and_save_to to avoid env-var races between parallel tests
    blazehash::parallel_config::calibrate_and_save_to(&path)
        .expect("calibrate_and_save_to should succeed");

    assert!(path.exists(), "parallel.toml should have been written");

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("parallel_threshold_bytes"));
}
