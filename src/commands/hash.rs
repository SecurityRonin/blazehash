use anyhow::{Context, Result};
use blazehash::ads::enumerate_ads;
use blazehash::algorithm::Algorithm;
use blazehash::format::{write_csv, write_dfxml, write_json, write_jsonl, write_sumfile};
use blazehash::hash::{hash_file, FileHashResult};
use blazehash::manifest::{write_header_with_metadata, write_record};
use blazehash::output::make_writer;
use blazehash::progress::walk_and_hash_with_progress;
use blazehash::resume::ResumeState;
use blazehash::walk::walk_and_hash_with_options;
use blazehash::walk_filter::WalkFilter;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::report_walk_errors;

pub struct HashOptions<'a> {
    pub paths: &'a [PathBuf],
    pub algorithms: &'a [Algorithm],
    pub recursive: bool,
    pub format: &'a str,
    pub bare: bool,
    pub resume: bool,
    pub output: Option<&'a PathBuf>,
    pub no_cache: bool,
    pub no_gpu: bool,
    pub filter: &'a WalkFilter,
    pub nsrl: Option<&'a PathBuf>,
    pub nsrl_exclude: bool,
    #[cfg(feature = "hashdb")]
    pub nsrl_hsh: Option<&'a std::path::PathBuf>,
    pub sign: bool,
    pub ads: bool,
    pub entropy: bool,
    pub case_id: Option<&'a str>,
    pub examiner: Option<&'a str>,
    pub progress: bool,
}

pub fn run(opts: HashOptions<'_>) -> Result<()> {
    let HashOptions {
        paths,
        algorithms,
        recursive,
        format,
        bare,
        resume,
        output,
        no_cache,
        no_gpu,
        filter,
        nsrl,
        nsrl_exclude,
        sign,
        ads,
        entropy,
        case_id,
        examiner,
        progress,
        #[cfg(feature = "hashdb")]
        nsrl_hsh,
    } = opts;
    let mut resume_state = load_resume_state(resume, output)?;
    let append = resume && output.is_some_and(|p| p.exists());
    let mut writer = make_writer(output.map(|p| p.as_path()), append)?;

    #[allow(unused_mut)] // `mut` is only needed when the `nsrl` feature is enabled
    let mut all_results = collect_results(
        paths,
        algorithms,
        recursive,
        &mut resume_state,
        no_cache,
        no_gpu,
        filter,
        ads,
        entropy,
        progress,
    )?;

    #[cfg(feature = "hashdb")]
    {
        // Build a combined known-good set from .hsh flat file (SHA-1 hashes).
        let mut hsh_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        if let Some(hsh_path) = nsrl_hsh {
            hsh_set = blazehash::nsrl::load_hsh(hsh_path)?;
        }

        if let Some(nsrl_path) = nsrl {
            let lookup = blazehash::nsrl::NsrlLookup::open(nsrl_path)?;
            let mut known_count = 0usize;
            all_results.retain(|r| {
                let hash_val = r
                    .hashes
                    .get(&Algorithm::Sha256)
                    .or_else(|| r.hashes.get(&Algorithm::Md5))
                    .map(|s| s.as_str())
                    .unwrap_or("");
                let sha1_val = r
                    .hashes
                    .get(&Algorithm::Sha1)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                let in_sqlite = lookup.lookup(hash_val) == blazehash::nsrl::NsrlResult::KnownGood;
                let in_hsh = !hsh_set.is_empty() && hsh_set.contains(sha1_val);
                if in_sqlite || in_hsh {
                    eprintln!("[K] {}  (NSRL known-good)", r.path.display());
                    known_count += 1;
                    !nsrl_exclude
                } else {
                    true
                }
            });
            if known_count > 0 {
                eprintln!("[K] {known_count} file(s) matched NSRL");
            }
        } else if !hsh_set.is_empty() {
            // .hsh only (no SQLite), filter by SHA-1
            let mut known_count = 0usize;
            all_results.retain(|r| {
                let sha1_val = r
                    .hashes
                    .get(&Algorithm::Sha1)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                if hsh_set.contains(sha1_val) {
                    eprintln!("[K] {}  (NSRL known-good)", r.path.display());
                    known_count += 1;
                    !nsrl_exclude
                } else {
                    true
                }
            });
            if known_count > 0 {
                eprintln!("[K] {known_count} file(s) matched NSRL");
            }
        }
    }
    #[cfg(not(feature = "hashdb"))]
    let _ = (nsrl, nsrl_exclude);

    #[cfg(feature = "parquet-output")]
    if format == "parquet" {
        blazehash::format::write_parquet(
            output.ok_or_else(|| anyhow::anyhow!("--format parquet requires -o <output>"))?,
            &all_results,
            algorithms,
        )?;
        return Ok(());
    }

    #[cfg(feature = "duckdb-output")]
    if format == "duckdb" {
        blazehash::format::write_duckdb(
            output.ok_or_else(|| anyhow::anyhow!("--format duckdb requires -o <file>"))?,
            &all_results,
            algorithms,
        )?;
        return Ok(());
    }

    let needs_header = !(bare || append);
    write_output(
        &mut writer,
        &all_results,
        algorithms,
        format,
        needs_header,
        case_id,
        examiner,
    )?;

    writer.flush()?;

    if sign {
        let output_path = output.ok_or_else(|| anyhow::anyhow!("--sign requires --output"))?;
        blazehash::signing::sign(output_path)?;
    }

    Ok(())
}

fn load_resume_state(resume: bool, output: Option<&PathBuf>) -> Result<ResumeState> {
    if !resume {
        return Ok(ResumeState::new());
    }
    match output {
        Some(p) if p.exists() => {
            let content = fs::read_to_string(p)
                .with_context(|| format!("failed to read manifest for resume: {}", p.display()))?;
            ResumeState::from_manifest(&content)
        }
        _ => Ok(ResumeState::new()),
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_results(
    paths: &[PathBuf],
    algorithms: &[Algorithm],
    recursive: bool,
    resume_state: &mut ResumeState,
    no_cache: bool,
    no_gpu: bool,
    filter: &WalkFilter,
    ads: bool,
    entropy: bool,
    progress: bool,
) -> Result<Vec<FileHashResult>> {
    let mut all_results = Vec::new();

    #[cfg(feature = "docker")]
    let (oci_paths, local_paths): (Vec<PathBuf>, Vec<PathBuf>) = paths
        .iter()
        .cloned()
        .partition(|p| blazehash::image::is_oci_uri(&p.to_string_lossy()));

    #[cfg(feature = "docker")]
    {
        for oci_uri in &oci_paths {
            let uri_str = oci_uri.to_string_lossy();
            let layers = super::image::oci_results(&uri_str, algorithms)?;
            all_results.extend(layers);
        }
    }

    #[cfg(feature = "docker")]
    let paths = local_paths.as_slice();

    for path in paths {
        if path.is_file() {
            if resume_state.is_done(path) {
                continue;
            }
            let result = hash_file(path, algorithms, no_cache, no_gpu, entropy)
                .with_context(|| format!("failed to hash {}", path.display()))?;
            resume_state.mark_done(path.clone());
            if ads {
                hash_ads_streams(path, algorithms, no_cache, no_gpu, &mut all_results);
            }
            all_results.push(result);
        } else if path.is_dir() {
            let output = if progress {
                walk_and_hash_with_progress(path, algorithms, recursive, filter, entropy)?
            } else {
                walk_and_hash_with_options(path, algorithms, recursive, filter, entropy)?
            };
            report_walk_errors(&output.errors);
            for r in output.results {
                if resume_state.is_done(&r.path) {
                    continue;
                }
                if ads {
                    hash_ads_streams(&r.path, algorithms, no_cache, no_gpu, &mut all_results);
                }
                resume_state.mark_done(r.path.clone());
                all_results.push(r);
            }
        }
    }

    Ok(all_results)
}

/// Hash any NTFS Alternate Data Streams attached to `path` and append results.
/// No-op on non-Windows or when the file has no named ADS.
fn hash_ads_streams(
    path: &std::path::Path,
    algorithms: &[Algorithm],
    no_cache: bool,
    no_gpu: bool,
    results: &mut Vec<FileHashResult>,
) {
    for stream_path in enumerate_ads(path) {
        match hash_file(&stream_path, algorithms, no_cache, no_gpu, false) {
            Ok(r) => results.push(r),
            Err(e) => eprintln!("[!] Failed to hash ADS {}: {e}", stream_path.display()),
        }
    }
}

fn write_output<W: Write>(
    writer: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
    format: &str,
    needs_header: bool,
    case_id: Option<&str>,
    examiner: Option<&str>,
) -> Result<()> {
    match format {
        "csv" => write_csv(writer, results, algorithms)?,
        "dfxml" => write_dfxml(writer, results, algorithms)?,
        "json" => write_json(writer, results, algorithms)?,
        "jsonl" => write_jsonl(writer, results, algorithms)?,
        "sha256sum" | "md5sum" => write_sumfile(writer, results, algorithms)?,
        _ => {
            if needs_header {
                write_header_with_metadata(writer, algorithms, case_id, examiner)?;
            }
            for result in results {
                write_record(writer, result, algorithms)?;
            }
        }
    }
    Ok(())
}
