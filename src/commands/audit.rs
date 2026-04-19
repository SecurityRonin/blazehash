use anyhow::{Context, Result};
use blazehash::audit;
use blazehash::manifest_loader::find_manifest;
use blazehash::output::make_writer;
use blazehash::walk::walk_paths;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::report_walk_errors;

#[allow(clippy::too_many_arguments)]
pub fn run(
    paths: &[PathBuf],
    known: &[PathBuf],
    recursive: bool,
    output: Option<&PathBuf>,
    fuzzy_threshold: u32,
    fuzzy_top: usize,
    ignore_sig: bool,
    expected_pubkey: Option<String>,
    fail_on_unknown: bool,
) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    // If no -k paths provided, auto-locate a manifest by scanning the target paths.
    let auto_known: Vec<PathBuf>;
    let effective_known: &[PathBuf] = if known.is_empty() {
        // Collect search dirs: directories from paths, plus cwd as fallback.
        let search_dirs: Vec<&std::path::Path> = {
            let mut dirs: Vec<&std::path::Path> = paths
                .iter()
                .filter(|p| p.is_dir())
                .map(|p| p.as_path())
                .collect();
            // Include cwd if no directory paths given
            if dirs.is_empty() {
                static CWD_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
                let cwd = CWD_PATH
                    .get_or_init(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
                dirs.push(cwd.as_path());
            }
            dirs
        };
        let found = find_manifest(&search_dirs)?;
        auto_known = vec![found];
        &auto_known
    } else {
        known
    };

    // Resolve each manifest path — fetch remote URLs into temp files first.
    // The `_remote_tmps` vec keeps the NamedTempFile values alive for the full audit run.
    let mut _remote_tmps: Vec<tempfile::NamedTempFile> = Vec::new();
    let resolved_known: Vec<PathBuf> = effective_known
        .iter()
        .map(|p| {
            let s = p.to_string_lossy();
            if blazehash::manifest_loader::is_remote_url(&s) {
                let tmp = blazehash::manifest_loader::fetch_remote_manifest(&s)?;
                let resolved = tmp.path().to_path_buf();
                _remote_tmps.push(tmp);
                Ok(resolved)
            } else {
                Ok(p.clone())
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let effective_known: &[PathBuf] = &resolved_known;

    if !ignore_sig {
        for known in effective_known {
            let _ = blazehash::signing::auto_verify_sidecar(known, expected_pubkey.as_deref())?;
        }
    }

    for known_path in effective_known {
        let known_content = fs::read_to_string(known_path)
            .with_context(|| format!("failed to read known file {}", known_path.display()))?;

        let mut all_paths = Vec::new();
        for path in paths {
            if path.is_file() {
                all_paths.push(path.clone());
            } else if path.is_dir() {
                let (file_paths, errors) = walk_paths(path, recursive);
                report_walk_errors(&errors);
                all_paths.extend(file_paths);
            }
        }

        let result = audit::audit(&all_paths, &known_content, fuzzy_threshold, fuzzy_top)?;
        writeln!(writer, "blazehash audit summary:")?;
        writeln!(writer, "  Files matched: {}", result.matched)?;
        writeln!(writer, "  Files changed: {}", result.changed)?;
        writeln!(writer, "  Files new: {}", result.new_files)?;
        writeln!(writer, "  Files moved: {}", result.moved)?;
        writeln!(writer, "  Files missing: {}", result.missing)?;
        writeln!(writer, "  Files fuzzy matched: {}", result.fuzzy_matched)?;

        // Print per-file details
        for status in &result.details {
            match status {
                blazehash::audit::AuditStatus::Matched(_) => {
                    // Matched: don't print (too noisy for large audits)
                }
                blazehash::audit::AuditStatus::Changed(p) => {
                    writeln!(writer, "[!] {} CHANGED", p.display())?;
                }
                blazehash::audit::AuditStatus::New(p) => {
                    writeln!(writer, "[?] {} UNKNOWN", p.display())?;
                }
                blazehash::audit::AuditStatus::Moved { path, original } => {
                    writeln!(
                        writer,
                        "[*] {} MOVED from {}",
                        path.display(),
                        original.display()
                    )?;
                }
                blazehash::audit::AuditStatus::Missing(p) => {
                    writeln!(writer, "[-] {} MISSING", p.display())?;
                }
                blazehash::audit::AuditStatus::FuzzyMatch {
                    path,
                    original,
                    similarity,
                } => {
                    writeln!(
                        writer,
                        "[~] {} FUZZY MATCH sim={}% <- {}",
                        path.display(),
                        similarity,
                        original.display()
                    )?;
                }
            }
        }

        // --fail-on-unknown: exit non-zero if any file was not found in the manifest
        if fail_on_unknown && result.new_files > 0 {
            writer.flush()?;
            std::process::exit(1);
        }
    }

    writer.flush()?;
    Ok(())
}
