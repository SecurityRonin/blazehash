#![cfg(feature = "gpu")]

use blazehash::gpu::config::{GpuConfig, GpuConfigState};
use tempfile::TempDir;

fn temp_config_path() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");
    (dir, path)
}

#[test]
fn test_config_no_file_returns_none() {
    let (_dir, path) = temp_config_path();
    let config = GpuConfig::load(&path);
    assert!(config.is_none(), "no config file → no config");
}

#[test]
fn test_config_write_and_load_roundtrip() {
    let (_dir, path) = temp_config_path();
    let cfg = GpuConfig {
        device: "NVIDIA RTX 3090".to_string(),
        calibrated: "2026-04-09".to_string(),
        threshold_single_mb: 48,
        threshold_multi_mb: 3,
        gpu_enabled: true,
    };
    cfg.save(&path).unwrap();
    let loaded = GpuConfig::load(&path).unwrap();
    assert_eq!(loaded.device, "NVIDIA RTX 3090");
    assert_eq!(loaded.threshold_single_mb, 48);
    assert!(loaded.gpu_enabled);
}

#[test]
fn test_config_corrupted_returns_none() {
    let (_dir, path) = temp_config_path();
    std::fs::write(&path, b"not valid toml {{{{").unwrap();
    let config = GpuConfig::load(&path);
    assert!(config.is_none(), "corrupted config → treat as missing");
}

#[test]
fn test_state_no_config_triggers_calibration() {
    let (_dir, path) = temp_config_path();
    let state = GpuConfigState::resolve(None, Some("NVIDIA RTX 3090"), &path);
    assert_eq!(state, GpuConfigState::NeedsCalibration);
}

#[test]
fn test_state_same_device_enabled_returns_use_thresholds() {
    let (_dir, path) = temp_config_path();
    let cfg = GpuConfig {
        device: "NVIDIA RTX 3090".to_string(),
        calibrated: "2026-04-09".to_string(),
        threshold_single_mb: 48,
        threshold_multi_mb: 3,
        gpu_enabled: true,
    };
    cfg.save(&path).unwrap();
    let state = GpuConfigState::resolve(GpuConfig::load(&path), Some("NVIDIA RTX 3090"), &path);
    assert_eq!(state, GpuConfigState::UseThresholds { single_mb: 48, multi_mb: 3 });
}

#[test]
fn test_state_same_device_disabled_returns_skip() {
    let (_dir, path) = temp_config_path();
    let cfg = GpuConfig {
        device: "Intel UHD 630".to_string(),
        calibrated: "2026-04-09".to_string(),
        threshold_single_mb: 999,
        threshold_multi_mb: 999,
        gpu_enabled: false,
    };
    cfg.save(&path).unwrap();
    let state = GpuConfigState::resolve(GpuConfig::load(&path), Some("Intel UHD 630"), &path);
    assert_eq!(state, GpuConfigState::Skip);
}

#[test]
fn test_state_different_device_triggers_calibration() {
    let (_dir, path) = temp_config_path();
    let cfg = GpuConfig {
        device: "Old GPU".to_string(),
        calibrated: "2026-04-09".to_string(),
        threshold_single_mb: 48,
        threshold_multi_mb: 3,
        gpu_enabled: true,
    };
    cfg.save(&path).unwrap();
    let state = GpuConfigState::resolve(GpuConfig::load(&path), Some("New GPU"), &path);
    assert_eq!(state, GpuConfigState::NeedsCalibration);
}

#[test]
fn test_state_no_gpu_adapter_returns_skip_leaves_config() {
    let (_dir, path) = temp_config_path();
    let cfg = GpuConfig {
        device: "NVIDIA RTX 3090".to_string(),
        calibrated: "2026-04-09".to_string(),
        threshold_single_mb: 48,
        threshold_multi_mb: 3,
        gpu_enabled: true,
    };
    cfg.save(&path).unwrap();
    // GPU absent (adapter = None) — config should be untouched
    let state = GpuConfigState::resolve(GpuConfig::load(&path), None, &path);
    assert_eq!(state, GpuConfigState::Skip);
    // Config still on disk, unmodified
    let reloaded = GpuConfig::load(&path).unwrap();
    assert_eq!(reloaded.device, "NVIDIA RTX 3090");
}

#[test]
fn test_no_calibrate_flag_returns_conservative_defaults() {
    let state = GpuConfigState::resolve_no_calibrate(Some("NVIDIA RTX 3090"));
    assert_eq!(state, GpuConfigState::UseThresholds {
        single_mb: blazehash::gpu::config::DEFAULT_THRESHOLD_SINGLE_MB,
        multi_mb: blazehash::gpu::config::DEFAULT_THRESHOLD_MULTI_MB,
    });
}

#[test]
fn test_backend_detect_returns_option() {
    // On headless CI with no GPU, returns None gracefully.
    // On a machine with a GPU, returns Some.
    // Either way: must not panic.
    let backend = blazehash::gpu::backend::GpuBackend::detect();
    if let Some(b) = backend {
        assert!(!b.adapter_name().is_empty());
    }
}

#[test]
fn test_backend_skips_software_renderers() {
    // If detect() returns Some, the adapter must not be a known SW renderer.
    let backend = blazehash::gpu::backend::GpuBackend::detect();
    if let Some(b) = backend {
        let name = b.adapter_name().to_lowercase();
        assert!(!name.contains("warp"), "WARP is a software renderer");
        assert!(!name.contains("llvmpipe"), "llvmpipe is a software renderer");
        assert!(!name.contains("software"), "software renderer must be skipped");
    }
}

#[test]
fn test_gpu_sha256_empty_input() {
    let Some(backend) = blazehash::gpu::backend::GpuBackend::detect() else {
        eprintln!("No GPU — skipping GPU sha256 test");
        return;
    };
    let hasher = blazehash::gpu::sha256::GpuSha256::new(&backend);
    let result = hasher.hash(b"");
    assert_eq!(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn test_gpu_sha256_abc() {
    let Some(backend) = blazehash::gpu::backend::GpuBackend::detect() else { return; };
    let hasher = blazehash::gpu::sha256::GpuSha256::new(&backend);
    let result = hasher.hash(b"abc");
    assert_eq!(result, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn test_gpu_sha256_matches_cpu_for_various_sizes() {
    use sha2::{Sha256, Digest};

    let Some(backend) = blazehash::gpu::backend::GpuBackend::detect() else { return; };
    let hasher = blazehash::gpu::sha256::GpuSha256::new(&backend);

    for size in [0usize, 1, 55, 56, 63, 64, 128, 1023, 4096] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let gpu_result = hasher.hash(&data);
        let cpu_result = hex::encode(Sha256::digest(&data));
        assert_eq!(gpu_result, cpu_result, "mismatch at size={size}");
    }
}

#[test]
fn test_gpu_sha256_large_file_matches_cpu() {
    use sha2::{Sha256, Digest};

    let Some(backend) = blazehash::gpu::backend::GpuBackend::detect() else { return; };
    let hasher = blazehash::gpu::sha256::GpuSha256::new(&backend);

    let data = vec![0x42u8; 1024 * 1024]; // 1 MiB
    let gpu_result = hasher.hash(&data);
    let cpu_result = hex::encode(Sha256::digest(&data));
    assert_eq!(gpu_result, cpu_result);
}
