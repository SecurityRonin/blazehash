use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// Return a writer for `path` (creates/truncates the file) or stdout when `path` is `None`.
///
/// When the `remote` feature is enabled and `path` looks like a remote URI
/// (e.g. `s3://`, `mem://`), an in-memory buffer is returned that flushes
/// atomically to the remote backend on drop.
pub fn output_writer(path: Option<&Path>) -> Result<Box<dyn Write>> {
    match path {
        None => Ok(Box::new(io::stdout())),
        Some(p) => {
            let s = p.to_string_lossy();
            if crate::remote::is_remote_uri(&s) {
                #[cfg(feature = "remote")]
                {
                    use crate::remote::operator::operator_for_uri;
                    use crate::remote::writer::RemoteWriter;
                    let (op, rel) = operator_for_uri(&s)?;
                    // blocking::Operator::new requires an active tokio runtime handle.
                    let blocking_op = opendal::blocking::Operator::new(op)?;
                    return Ok(Box::new(RemoteWriter::new(blocking_op, rel)));
                }
                #[cfg(not(feature = "remote"))]
                anyhow::bail!(
                    "remote URIs require the `remote` feature: recompile with --features remote"
                );
            }
            Ok(Box::new(File::create(p)?))
        }
    }
}

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
