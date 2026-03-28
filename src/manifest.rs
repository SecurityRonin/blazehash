use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::{bail, Result};
use std::io::Write;
use std::str::FromStr;

/// Write the hashdeep-format header.
pub fn write_header<W: Write>(w: &mut W, algorithms: &[Algorithm]) -> Result<()> {
    writeln!(w, "%%%% HASHDEEP-1.0")?;
    write!(w, "%%%% size")?;
    for algo in algorithms {
        write!(w, ",{}", algo.hashdeep_name())?;
    }
    writeln!(w, ",filename")?;
    writeln!(w, "## Invoked from: blazehash v{}", env!("CARGO_PKG_VERSION"))?;
    writeln!(w, "##")?;
    Ok(())
}

/// Write a single hashdeep-format record.
pub fn write_record<W: Write>(
    w: &mut W,
    result: &FileHashResult,
    algorithms: &[Algorithm],
) -> Result<()> {
    write!(w, "{}", result.size)?;
    for algo in algorithms {
        write!(w, ",{}", result.hashes[algo])?;
    }
    writeln!(w, ",{}", result.path.display())?;
    Ok(())
}

/// Parse a hashdeep-format header, returning the algorithms in column order.
pub fn parse_header(input: &str) -> Result<Vec<Algorithm>> {
    let mut lines = input.lines();

    // First line: %%%% HASHDEEP-1.0
    let first = lines.next().unwrap_or("");
    if !first.starts_with("%%%% HASHDEEP") {
        bail!("not a hashdeep file: missing header");
    }

    // Second line: %%%% size,algo1,algo2,...,filename
    let second = lines.next().unwrap_or("");
    if !second.starts_with("%%%% size,") {
        bail!("not a hashdeep file: missing column line");
    }

    let cols = &second["%%%% size,".len()..];
    let parts: Vec<&str> = cols.split(',').collect();

    // Last part is "filename", skip it
    if parts.is_empty() || parts.last() != Some(&"filename") {
        bail!("not a hashdeep file: missing filename column");
    }

    let algo_names = &parts[..parts.len() - 1];
    let mut algorithms = Vec::new();
    for name in algo_names {
        algorithms.push(Algorithm::from_str(name)?);
    }

    Ok(algorithms)
}
