use anyhow::{Context, Result};
use blazehash::output::make_writer;
use blazehash::walk::walk_paths;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::report_walk_errors;

/// Conservative BLAKE3 throughput baseline used for time estimates (bytes/sec).
/// BLAKE3 typically achieves 3–6 GiB/s on modern hardware; 3 GiB/s is a safe lower bound.
const BLAKE3_BYTES_PER_SEC: u64 = 3 * 1024 * 1024 * 1024;

pub fn run(
    paths: &[PathBuf],
    recursive: bool,
    output: Option<&PathBuf>,
    #[cfg_attr(not(target_os = "windows"), allow(unused_variables))] mft: bool,
) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    let mut total_bytes = 0u64;
    let mut total_files = 0usize;

    for path in paths {
        // ── Windows MFT fast path ─────────────────────────────────────────────
        #[cfg(target_os = "windows")]
        if mft && path.is_dir() {
            let entries = run_mft_for_path(path, recursive)?;
            for e in &entries {
                writeln!(writer, "{}\t{}", e.size, e.path.display())?;
                total_bytes += e.size;
                total_files += 1;
            }
            continue;
        }

        // ── Standard path (all platforms) ────────────────────────────────────
        if path.is_file() {
            let meta = fs::metadata(path)
                .with_context(|| format!("failed to read metadata for {}", path.display()))?;
            let size = meta.len();
            writeln!(writer, "{}\t{}", size, path.display())?;
            total_bytes += size;
            total_files += 1;
        } else if path.is_dir() {
            let (file_paths, errors) = walk_paths(path, recursive);
            report_walk_errors(&errors);
            for file_path in &file_paths {
                let meta = fs::metadata(file_path).with_context(|| {
                    format!("failed to read metadata for {}", file_path.display())
                })?;
                let size = meta.len();
                writeln!(writer, "{}\t{}", size, file_path.display())?;
                total_bytes += size;
                total_files += 1;
            }
        }
    }

    writer.flush()?;

    // ─── Windows MFT helper ───────────────────────────────────────────────────

    /// Enumerate file sizes for `root` via the NTFS $MFT, with UAC elevation
    /// fallback when the process is not already running as Administrator.
    #[cfg(target_os = "windows")]
    fn run_mft_for_path(
        root: &std::path::Path,
        recursive: bool,
    ) -> Result<Vec<blazehash::walk_windows_mft::MftEntry>> {
        use blazehash::walk_windows_mft::{
            enumerate_mft_sizes, is_elevated, read_mft_results, spawn_elevated_mft_worker,
        };

        if is_elevated() {
            return enumerate_mft_sizes(root, recursive);
        }

        // Not elevated — spawn an elevated subprocess via UAC and collect its output.
        eprintln!("[*] --mft: not running as Administrator.");
        eprintln!("[*] A UAC elevation prompt will appear. Approve it to use MFT direct access.");

        let tmp = tempfile::NamedTempFile::new()
            .context("failed to create temp file for MFT worker output")?;
        let tmp_path = tmp.path().to_path_buf();
        // Keep the file alive until we've read it
        let _tmp = tmp;

        spawn_elevated_mft_worker(root, recursive, &tmp_path)?;
        read_mft_results(&tmp_path)
    }

    let file_word = if total_files == 1 { "file" } else { "files" };
    let mib = total_bytes as f64 / (1024.0 * 1024.0);
    let est_secs = total_bytes as f64 / BLAKE3_BYTES_PER_SEC as f64;
    let (size_str, unit) = if mib >= 1024.0 {
        (mib / 1024.0, "GiB")
    } else {
        (mib, "MiB")
    };
    eprintln!(
        "[+] {total_files} {file_word} — {size_str:.1} {unit} (est. {est_secs:.1}s to hash @ BLAKE3 ~3 GiB/s)"
    );

    Ok(())
}
