use anyhow::{Context, Result};
use blazehash::algorithm::Algorithm;
use blazehash::format::{write_csv, write_json, write_jsonl};
use blazehash::hash::{hash_file, FileHashResult};
use blazehash::manifest::{write_header, write_record};
use blazehash::output::make_writer;
use blazehash::resume::ResumeState;
use blazehash::walk::walk_and_hash;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::report_walk_errors;

pub fn run(
    paths: &[PathBuf],
    algorithms: &[Algorithm],
    recursive: bool,
    format: &str,
    bare: bool,
    resume: bool,
    output: Option<&PathBuf>,
) -> Result<()> {
    let mut resume_state = load_resume_state(resume, output)?;
    let append = resume && output.is_some_and(|p| p.exists());
    let mut writer = make_writer(output.map(|p| p.as_path()), append)?;

    let all_results = collect_results(paths, algorithms, recursive, &mut resume_state)?;

    let needs_header = !(bare || append);
    write_output(&mut writer, &all_results, algorithms, format, needs_header)?;

    writer.flush()?;
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

fn collect_results(
    paths: &[PathBuf],
    algorithms: &[Algorithm],
    recursive: bool,
    resume_state: &mut ResumeState,
) -> Result<Vec<FileHashResult>> {
    let mut all_results = Vec::new();

    for path in paths {
        if path.is_file() {
            if resume_state.is_done(path) {
                continue;
            }
            let result = hash_file(path, algorithms)
                .with_context(|| format!("failed to hash {}", path.display()))?;
            resume_state.mark_done(path.clone());
            all_results.push(result);
        } else if path.is_dir() {
            let output = walk_and_hash(path, algorithms, recursive)?;
            report_walk_errors(&output.errors);
            for r in output.results {
                if resume_state.is_done(&r.path) {
                    continue;
                }
                resume_state.mark_done(r.path.clone());
                all_results.push(r);
            }
        }
    }

    Ok(all_results)
}

fn write_output<W: Write>(
    writer: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
    format: &str,
    needs_header: bool,
) -> Result<()> {
    match format {
        "csv" => write_csv(writer, results, algorithms)?,
        "json" => write_json(writer, results, algorithms)?,
        "jsonl" => write_jsonl(writer, results, algorithms)?,
        _ => {
            if needs_header {
                write_header(writer, algorithms)?;
            }
            for result in results {
                write_record(writer, result, algorithms)?;
            }
        }
    }
    Ok(())
}
