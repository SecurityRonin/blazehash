use anyhow::{Context, Result};
use blazehash::audit;
use blazehash::output::make_writer;
use blazehash::walk::walk_paths;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::report_walk_errors;

pub fn run(
    paths: &[PathBuf],
    known: &[PathBuf],
    recursive: bool,
    output: Option<&PathBuf>,
) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    for known_path in known {
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

        let result = audit::audit(&all_paths, &known_content)?;
        writeln!(writer, "blazehash audit summary:")?;
        writeln!(writer, "  Files matched: {}", result.matched)?;
        writeln!(writer, "  Files changed: {}", result.changed)?;
        writeln!(writer, "  Files new: {}", result.new_files)?;
        writeln!(writer, "  Files moved: {}", result.moved)?;
        writeln!(writer, "  Files missing: {}", result.missing)?;
    }

    writer.flush()?;
    Ok(())
}
