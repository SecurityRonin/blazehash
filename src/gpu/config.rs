use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Conservative defaults calibrated on Paperspace RTX A5000 (PCIe 4.0 discrete).
/// Users should run `blazehash bench --gpu` for their hardware.
pub const DEFAULT_THRESHOLD_SINGLE_MB: u32 = 256;
pub const DEFAULT_THRESHOLD_MULTI_MB: u32 = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GpuConfig {
    pub device: String,
    pub calibrated: String,
    pub threshold_single_mb: u32,
    pub threshold_multi_mb: u32,
    pub gpu_enabled: bool,
}

impl GpuConfig {
    pub fn load(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        toml::from_str(&content).ok()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum GpuConfigState {
    /// No real GPU found or GPU absent this run — use CPU. Config untouched.
    Skip,
    /// GPU present, calibration data valid for this device.
    UseThresholds { single_mb: u32, multi_mb: u32 },
    /// GPU present but no valid config for this device — must calibrate.
    NeedsCalibration,
}

impl GpuConfigState {
    /// Resolve GPU state given loaded config and current detected adapter name.
    ///
    /// `adapter_name`: None means no real GPU detected (absent, or software renderer).
    pub fn resolve(
        config: Option<GpuConfig>,
        adapter_name: Option<&str>,
        _config_path: &Path,
    ) -> Self {
        let Some(name) = adapter_name else {
            return GpuConfigState::Skip;
        };

        match config {
            None => GpuConfigState::NeedsCalibration,
            Some(cfg) if cfg.device != name => GpuConfigState::NeedsCalibration,
            Some(cfg) if !cfg.gpu_enabled => GpuConfigState::Skip,
            Some(cfg) => GpuConfigState::UseThresholds {
                single_mb: cfg.threshold_single_mb,
                multi_mb: cfg.threshold_multi_mb,
            },
        }
    }

    /// Used with --no-calibrate: return conservative defaults, write no config.
    pub fn resolve_no_calibrate(adapter_name: Option<&str>) -> Self {
        if adapter_name.is_none() {
            return GpuConfigState::Skip;
        }
        GpuConfigState::UseThresholds {
            single_mb: DEFAULT_THRESHOLD_SINGLE_MB,
            multi_mb: DEFAULT_THRESHOLD_MULTI_MB,
        }
    }
}
