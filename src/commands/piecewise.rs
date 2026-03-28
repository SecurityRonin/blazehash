use anyhow::{Context, Result};
use blazehash::algorithm::Algorithm;
use blazehash::manifest::write_header;
use blazehash::output::make_writer;
use blazehash::piecewise::hash_file_piecewise;
use std::io::Write;
use std::path::PathBuf;

pub fn run(
    paths: &[PathBuf],
    algorithms: &[Algorithm],
    chunk_str: &str,
    bare: bool,
    output: Option<&PathBuf>,
) -> Result<()> {
    let chunk_size = crate::cli::parse_chunk_size(chunk_str)
        .map_err(|e| anyhow::anyhow!("invalid chunk size: {e}"))?;

    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    if !bare {
        write_header(&mut writer, algorithms)?;
    }

    for path in paths {
        if path.is_file() {
            let chunks = hash_file_piecewise(path, algorithms, chunk_size)
                .with_context(|| format!("failed to hash {}", path.display()))?;
            for chunk in &chunks {
                write!(writer, "{}", chunk.chunk_size)?;
                for algo in algorithms {
                    let hash = chunk
                        .hashes
                        .get(algo)
                        .ok_or_else(|| anyhow::anyhow!("missing hash for {algo}"))?;
                    write!(writer, ",{hash}")?;
                }
                writeln!(
                    writer,
                    ",{}:{}-{}",
                    path.display(),
                    chunk.offset,
                    chunk.offset + chunk.chunk_size
                )?;
            }
        }
    }

    writer.flush()?;
    Ok(())
}
