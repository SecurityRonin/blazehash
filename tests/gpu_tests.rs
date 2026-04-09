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
