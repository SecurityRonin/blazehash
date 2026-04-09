use anyhow::Result;

pub fn run(gpu: bool, no_calibrate: bool) -> Result<()> {
    if !gpu {
        eprintln!("Usage: blazehash bench --gpu [--no-calibrate]");
        return Ok(());
    }

    #[cfg(feature = "gpu")]
    {
        use blazehash::gpu::config::{
            GpuConfig, DEFAULT_THRESHOLD_MULTI_MB, DEFAULT_THRESHOLD_SINGLE_MB,
        };

        if no_calibrate {
            println!("[*] --no-calibrate: using conservative defaults (no config written)");
            println!("    threshold_single_mb = {DEFAULT_THRESHOLD_SINGLE_MB}");
            println!("    threshold_multi_mb  = {DEFAULT_THRESHOLD_MULTI_MB}");
            return Ok(());
        }

        let config_dir = get_config_dir();
        let config_path = config_dir.join("config.toml");

        let backend = match blazehash::gpu::backend::GpuBackend::detect() {
            Some(b) => b,
            None => {
                println!("[*] No GPU detected — calibration skipped");
                return Ok(());
            }
        };

        println!(
            "[*] Calibrating GPU vs CPU crossover on {}...",
            backend.adapter_name()
        );

        let (single_mb, multi_mb, gpu_enabled) = calibrate(&backend);

        let cfg = GpuConfig {
            device: backend.adapter_name().to_string(),
            calibrated: {
                use std::time::{SystemTime, UNIX_EPOCH};
                let secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                // Compute date components from Unix timestamp
                let days = secs / 86400;
                let year = 1970 + days / 365; // approximate — sufficient for config metadata
                let day_of_year = days % 365;
                let month = (day_of_year / 30) + 1;
                let day = (day_of_year % 30) + 1;
                format!("{year:04}-{month:02}-{day:02}")
            },
            threshold_single_mb: single_mb,
            threshold_multi_mb: multi_mb,
            gpu_enabled,
        };

        if !gpu_enabled {
            println!("[*] GPU was slower than CPU at all tested sizes — writing gpu_enabled=false");
        }

        std::fs::create_dir_all(&config_dir)?;
        cfg.save(&config_path)?;

        println!(
            "[+] Calibration complete. Written to {}",
            config_path.display()
        );
        println!("    threshold_single_mb = {single_mb}");
        println!("    threshold_multi_mb  = {multi_mb}");
    }

    #[cfg(not(feature = "gpu"))]
    {
        let _ = no_calibrate; // suppress unused warning
        eprintln!(
            "[!] GPU feature not compiled. Rebuild with --features gpu to enable GPU benchmarking."
        );
    }

    Ok(())
}

#[cfg(feature = "gpu")]
fn get_config_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("BLAZEHASH_CONFIG_DIR") {
        return std::path::PathBuf::from(dir);
    }
    if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("blazehash")
    } else {
        std::path::PathBuf::from(".")
    }
}

#[cfg(feature = "gpu")]
fn calibrate(backend: &blazehash::gpu::backend::GpuBackend) -> (u32, u32, bool) {
    use blazehash::gpu::config::{DEFAULT_THRESHOLD_MULTI_MB, DEFAULT_THRESHOLD_SINGLE_MB};
    use blazehash::gpu::sha256::GpuSha256;
    use std::time::Instant;

    let hasher = GpuSha256::new(backend);

    let test_sizes_mb: &[u32] = &[1, 2, 4, 8, 16, 32, 64, 128];
    let mut gpu_ever_won = false;
    let mut single_threshold = DEFAULT_THRESHOLD_SINGLE_MB;

    for &size_mb in test_sizes_mb {
        let data = vec![0x42u8; (size_mb as usize) * 1024 * 1024];

        // CPU timing
        let t0 = Instant::now();
        for _ in 0..3 {
            let _ = blazehash::algorithm::hash_bytes(blazehash::algorithm::Algorithm::Sha256, &data);
        }
        let cpu_ms = t0.elapsed().as_millis() / 3;

        // GPU timing
        let t0 = Instant::now();
        for _ in 0..3 {
            let _ = hasher.hash(&data);
        }
        let gpu_ms = t0.elapsed().as_millis() / 3;

        println!("    SHA-256 {size_mb} MB: CPU={cpu_ms}ms  GPU={gpu_ms}ms");

        if gpu_ms < cpu_ms {
            single_threshold = size_mb;
            gpu_ever_won = true;
            break;
        }
    }

    if !gpu_ever_won {
        return (DEFAULT_THRESHOLD_SINGLE_MB, DEFAULT_THRESHOLD_MULTI_MB, false);
    }

    let multi_threshold = (single_threshold / 4).max(1);
    (single_threshold, multi_threshold, true)
}
