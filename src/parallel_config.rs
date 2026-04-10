//! Platform-adaptive parallel hashing threshold.
//!
//! Rayon's per-task dispatch costs ~20–40 µs. For files below the threshold,
//! sequential iteration is faster. The threshold is either:
//!  - loaded from `~/.config/blazehash/parallel.toml` (written by `blazehash bench`)
//!  - or the hardcoded default of 64 KiB (safe for all platforms)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Hardcoded conservative default: ~6× above the break-even point on Apple M4 Pro
/// (SHA-256 computation at ~533 MB/s takes ~120 µs for 64 KiB vs ~30 µs dispatch cost).
pub const DEFAULT_PARALLEL_THRESHOLD_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParallelConfig {
    /// Mean file size (bytes) at or above which `par_iter` is used. Below this,
    /// sequential `iter` avoids Rayon dispatch overhead.
    pub parallel_threshold_bytes: u64,
    /// ISO-8601 date when calibration was last run (empty for defaults).
    pub calibrated_at: String,
    /// CPU description string for cache invalidation when hardware changes.
    pub cpu_info: String,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            parallel_threshold_bytes: DEFAULT_PARALLEL_THRESHOLD_BYTES,
            calibrated_at: String::new(),
            cpu_info: String::new(),
        }
    }
}

impl ParallelConfig {
    /// Returns `true` if files with this mean size should be hashed in parallel.
    pub fn should_parallelize(&self, mean_file_bytes: u64) -> bool {
        mean_file_bytes >= self.parallel_threshold_bytes
    }

    /// Path to the parallel config TOML file.
    /// Respects `$BLAZEHASH_CONFIG_DIR`; falls back to `~/.config/blazehash/`.
    pub fn config_path() -> PathBuf {
        config_dir().join("parallel.toml")
    }

    /// Load from `path`, returning `Default` if the file is absent or unparseable.
    pub fn load_or_default(path: &Path) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        toml::from_str(&content).unwrap_or_default()
    }

    /// Write this config to `path`, creating parent directories as needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("BLAZEHASH_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(cfg) = dirs::config_dir() {
        cfg.join("blazehash")
    } else {
        PathBuf::from(".")
    }
}

/// Measure the sequential↔parallel crossover for SHA-256 on this machine.
///
/// Tries files of increasing size; returns the first size where parallel is
/// at least 10% faster than sequential (to avoid false positives from noise).
/// Falls back to `DEFAULT_PARALLEL_THRESHOLD_BYTES` if no crossover is found
/// within the tested range.
pub fn calibrate() -> ParallelConfig {
    use crate::algorithm::{hash_bytes, Algorithm};
    use rayon::prelude::*;

    // Test sizes: 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB, 4 MiB
    let test_sizes: &[u64] = &[
        4 * 1024,
        16 * 1024,
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
    ];
    // Number of synthetic files per size class
    let n_files = 64usize;
    // Warm-up runs discarded before timing
    let warmup = 2usize;
    let timed = 5usize;

    let mut threshold = DEFAULT_PARALLEL_THRESHOLD_BYTES;

    eprintln!("[*] Calibrating parallel threshold ({n_files} files × each size, {timed} runs)...");

    for &size in test_sizes {
        let data: Vec<u8> = (0..size as usize).map(|i| i as u8).collect();
        let files: Vec<&[u8]> = vec![&data; n_files];

        // Warm up
        for _ in 0..warmup {
            files
                .iter()
                .for_each(|f| drop(hash_bytes(Algorithm::Sha256, f)));
            files
                .par_iter()
                .for_each(|f| drop(hash_bytes(Algorithm::Sha256, f)));
        }

        // Time sequential
        let t0 = Instant::now();
        for _ in 0..timed {
            files
                .iter()
                .for_each(|f| drop(hash_bytes(Algorithm::Sha256, f)));
        }
        let seq_us = t0.elapsed().as_micros() / timed as u128;

        // Time parallel
        let t0 = Instant::now();
        for _ in 0..timed {
            files
                .par_iter()
                .for_each(|f| drop(hash_bytes(Algorithm::Sha256, f)));
        }
        let par_us = t0.elapsed().as_micros() / timed as u128;

        let size_kib = size / 1024;
        eprintln!(
            "    {size_kib} KiB × {n_files}: seq={seq_us}µs  par={par_us}µs{}",
            if par_us < seq_us { "  ← parallel wins" } else { "" }
        );

        // Parallel wins by at least 10% → this is our threshold
        if par_us > 0 && par_us * 10 < seq_us * 9 {
            threshold = size;
            break;
        }
    }

    eprintln!("[+] Threshold set to {} KiB/file", threshold / 1024);

    ParallelConfig {
        parallel_threshold_bytes: threshold,
        calibrated_at: today_iso8601(),
        cpu_info: cpu_info_string(),
    }
}

/// Run calibration and write the result to `ParallelConfig::config_path()`.
pub fn calibrate_and_save() -> Result<()> {
    calibrate_and_save_to(&ParallelConfig::config_path())
}

/// Run calibration and write the result to an explicit path.
/// Useful for testing without relying on env-var manipulation.
pub fn calibrate_and_save_to(path: &Path) -> Result<()> {
    let cfg = calibrate();
    cfg.save(path)?;
    eprintln!("[+] Parallel config written to {}", path.display());
    Ok(())
}

fn today_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    // Gregorian approximation — accurate enough for cache-invalidation metadata
    let year = 1970 + days / 365;
    let doy = days % 365;
    let month = (doy / 30) + 1;
    let day = (doy % 30) + 1;
    format!("{year:04}-{month:02}-{day:02}")
}

fn cpu_info_string() -> String {
    // On Apple Silicon, sysctl returns the chip name; on Linux, /proc/cpuinfo.
    // We keep this best-effort: a blank string is fine if detection fails.
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in content.lines() {
                if line.starts_with("model name") {
                    if let Some(val) = line.splitn(2, ':').nth(1) {
                        return val.trim().to_string();
                    }
                }
            }
        }
    }
    std::env::consts::ARCH.to_string()
}
