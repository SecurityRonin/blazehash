use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// Create a buffered writer targeting either a file or stdout.
///
/// - `path = None` → stdout
/// - `path = Some(p)` with `append = true` and file exists → append mode
/// - `path = Some(p)` otherwise → create/truncate
pub fn make_writer(path: Option<&Path>, append: bool) -> Result<Box<dyn Write>> {
    match path {
        Some(p) if append && p.exists() => {
            let file = OpenOptions::new()
                .append(true)
                .open(p)
                .with_context(|| format!("failed to open {} for appending", p.display()))?;
            Ok(Box::new(BufWriter::new(file)))
        }
        Some(p) => {
            let file = File::create(p)
                .with_context(|| format!("failed to create output file {}", p.display()))?;
            Ok(Box::new(BufWriter::new(file)))
        }
        None => Ok(Box::new(BufWriter::new(io::stdout().lock()))),
    }
}
