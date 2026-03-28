use anyhow::{Context, Result};
use blazehash::output::make_writer;
use blazehash::walk::walk_paths;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::report_walk_errors;

pub fn run(paths: &[PathBuf], recursive: bool, output: Option<&PathBuf>) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    for path in paths {
        if path.is_file() {
            let meta = fs::metadata(path)
                .with_context(|| format!("failed to read metadata for {}", path.display()))?;
            writeln!(writer, "{}\t{}", meta.len(), path.display())?;
        } else if path.is_dir() {
            let (file_paths, errors) = walk_paths(path, recursive);
            report_walk_errors(&errors);
            for file_path in &file_paths {
                let meta = fs::metadata(file_path).with_context(|| {
                    format!("failed to read metadata for {}", file_path.display())
                })?;
                writeln!(writer, "{}\t{}", meta.len(), file_path.display())?;
            }
        }
    }

    writer.flush()?;
    Ok(())
}
