mod cli;

use anyhow::Result;
use blazehash::audit;
use blazehash::format::{write_csv, write_json, write_jsonl};
use blazehash::hash::hash_file;
use blazehash::manifest::{write_header, write_record};
use blazehash::piecewise::hash_file_piecewise;
use blazehash::resume::ResumeState;
use blazehash::walk::{walk_and_hash, WalkOutput};
use clap::Parser;
use cli::Cli;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};

fn report_walk_errors(output: &WalkOutput) {
    for err in &output.errors {
        eprintln!("blazehash: warning: {}: {}", err.path.display(), err.error);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let algorithms = cli.flat_algorithms();

    // Size-only mode
    if cli.size_only {
        let mut writer: Box<dyn Write> = match &cli.output {
            Some(path) => Box::new(BufWriter::new(File::create(path)?)),
            None => Box::new(BufWriter::new(io::stdout().lock())),
        };
        for path in &cli.paths {
            if path.is_file() {
                let meta = fs::metadata(path)?;
                writeln!(writer, "{}\t{}", meta.len(), path.display())?;
            } else if path.is_dir() {
                let output = walk_and_hash(path, &algorithms, cli.recursive)?;
                report_walk_errors(&output);
                for r in &output.results {
                    writeln!(writer, "{}\t{}", r.size, r.path.display())?;
                }
            }
        }
        return Ok(());
    }

    // Audit mode
    if cli.audit {
        let mut writer: Box<dyn Write> = match &cli.output {
            Some(path) => Box::new(BufWriter::new(File::create(path)?)),
            None => Box::new(BufWriter::new(io::stdout().lock())),
        };
        for known_path in &cli.known {
            let known_content = fs::read_to_string(known_path)?;
            let mut all_paths = Vec::new();
            for path in &cli.paths {
                if path.is_file() {
                    all_paths.push(path.clone());
                } else if path.is_dir() {
                    let output = walk_and_hash(path, &algorithms, cli.recursive)?;
                    report_walk_errors(&output);
                    for r in output.results {
                        all_paths.push(r.path);
                    }
                }
            }
            let result = audit::audit(&all_paths, &known_content)?;
            writeln!(writer, "blazehash audit summary:")?;
            writeln!(writer, "  Files matched: {}", result.matched)?;
            writeln!(writer, "  Files changed: {}", result.changed)?;
            writeln!(writer, "  Files new: {}", result.new_files)?;
            writeln!(writer, "  Files moved: {}", result.moved)?;
            writeln!(writer, "  Files missing: {}", result.missing)?;
        }
        writer.flush()?;
        return Ok(());
    }

    // Resume state
    let mut resume_state = if cli.resume {
        if let Some(ref output_path) = cli.output {
            if output_path.exists() {
                let content = fs::read_to_string(output_path)?;
                ResumeState::from_manifest(&content)?
            } else {
                ResumeState::new()
            }
        } else {
            ResumeState::new()
        }
    } else {
        ResumeState::new()
    };

    // Writer: append mode for resume with existing file, create mode otherwise
    let mut writer: Box<dyn Write> = match &cli.output {
        Some(path) if cli.resume && path.exists() => {
            Box::new(BufWriter::new(OpenOptions::new().append(true).open(path)?))
        }
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };

    // Piecewise mode
    if let Some(ref chunk_str) = cli.piecewise {
        let chunk_size = cli::parse_chunk_size(chunk_str)
            .map_err(|e| anyhow::anyhow!("invalid chunk size: {}", e))?;

        if !cli.bare {
            write_header(&mut writer, &algorithms)?;
        }

        for path in &cli.paths {
            if path.is_file() {
                let chunks = hash_file_piecewise(path, &algorithms, chunk_size)?;
                for chunk in &chunks {
                    write!(writer, "{}", chunk.chunk_size)?;
                    for algo in &algorithms {
                        let hash = chunk.hashes.get(algo)
                            .ok_or_else(|| anyhow::anyhow!("missing hash"))?;
                        write!(writer, ",{}", hash)?;
                    }
                    writeln!(writer, ",{}:{}-{}",
                        path.display(),
                        chunk.offset,
                        chunk.offset + chunk.chunk_size
                    )?;
                }
            }
        }
        writer.flush()?;
        return Ok(());
    }

    // Normal hashing mode (with resume support)
    let mut all_results = Vec::new();
    for path in &cli.paths {
        if path.is_file() {
            if resume_state.is_done(path) {
                continue;
            }
            let result = hash_file(path, &algorithms)?;
            resume_state.mark_done(path.clone());
            all_results.push(result);
        } else if path.is_dir() {
            let output = walk_and_hash(path, &algorithms, cli.recursive)?;
            report_walk_errors(&output);
            for r in output.results {
                if resume_state.is_done(&r.path) {
                    continue;
                }
                resume_state.mark_done(r.path.clone());
                all_results.push(r);
            }
        }
    }

    // Write header (only if not resuming an existing file)
    let needs_header = !cli.bare && !(cli.resume && cli.output.as_ref().map_or(false, |p| p.exists()));

    // Write output in requested format
    match cli.format.as_str() {
        "csv" => write_csv(&mut writer, &all_results, &algorithms)?,
        "json" => write_json(&mut writer, &all_results, &algorithms)?,
        "jsonl" => write_jsonl(&mut writer, &all_results, &algorithms)?,
        _ => {
            // hashdeep format (default)
            if needs_header {
                write_header(&mut writer, &algorithms)?;
            }
            for result in &all_results {
                write_record(&mut writer, result, &algorithms)?;
            }
        }
    };

    writer.flush()?;
    Ok(())
}
