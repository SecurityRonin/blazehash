//! Unified configuration file — `~/.config/blazehash/config.toml`
//!
//! All subsystem configs live under named TOML tables:
//!
//! ```toml
//! [parallel]
//! parallel_threshold_bytes = 4096
//! calibrated_at = "2026-04-10"
//! cpu_info = "Apple M4 Pro"
//!
//! [gpu]
//! device = "Apple M4 Pro GPU"
//! calibrated = "2026-04-10"
//! threshold_single_mb = 256
//! threshold_multi_mb = 32
//! gpu_enabled = true
//! ```

use crate::parallel_config::ParallelConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[cfg(feature = "gpu")]
use crate::gpu::config::GpuConfig;

/// Top-level config written to / read from `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlazeConfig {
    /// Parallel threshold calibration — written by `blazehash bench`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel: Option<ParallelConfig>,

    /// GPU calibration — written by `blazehash bench --gpu`.
    #[cfg(feature = "gpu")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuConfig>,
}

impl BlazeConfig {
    /// Load from `path`. Returns `Default` if file is absent or unparseable.
    pub fn load(path: &Path) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        toml::from_str(&content).unwrap_or_default()
    }

    /// Load from the canonical config path (`$BLAZEHASH_CONFIG_DIR/config.toml`).
    pub fn load_default() -> Self {
        Self::load(&config_path())
    }

    /// Write to `path`, creating parent directories as needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Save to the canonical config path.
    pub fn save_default(&self) -> Result<()> {
        self.save(&config_path())
    }
}

/// Canonical path for the unified config file.
///
/// Respects `$BLAZEHASH_CONFIG_DIR`; falls back to `~/.config/blazehash/`.
pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// Directory that holds blazehash config files.
pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("BLAZEHASH_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(cfg) = dirs::config_dir() {
        cfg.join("blazehash")
    } else {
        PathBuf::from(".")
    }
}
