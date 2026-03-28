use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
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
        let hash = result.hashes.get(algo)
            .ok_or_else(|| anyhow::anyhow!("missing hash for algorithm {algo}"))?;
        write!(w, ",{hash}")?;
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
        bail!("not a hashdeep file: missing header (got {:?})", first.chars().take(40).collect::<String>());
    }

    // Second line: %%%% size,algo1,algo2,...,filename
    let second = lines.next().unwrap_or("");
    if !second.starts_with("%%%% size,") {
        bail!("not a hashdeep file: missing column line (got {:?})", second.chars().take(40).collect::<String>());
    }

    let cols = &second["%%%% size,".len()..];
    let parts: Vec<&str> = cols.split(',').collect();

    // Last part is "filename", skip it
    if parts.is_empty() || parts.last() != Some(&"filename") {
        bail!("not a hashdeep file: missing filename column (got {:?})", second.chars().take(60).collect::<String>());
    }

    let algo_names = &parts[..parts.len() - 1];
    let mut algorithms = Vec::new();
    for name in algo_names {
        algorithms.push(Algorithm::from_str(name)?);
    }

    Ok(algorithms)
}

/// A single parsed record from a hashdeep manifest.
#[derive(Debug, Clone)]
pub struct ManifestRecord {
    pub size: u64,
    pub hashes: HashMap<Algorithm, String>,
    pub path: PathBuf,
}

/// Parse all data records from a hashdeep manifest.
/// Skips headers (%%%%), comments (#), empty lines, and malformed entries.
pub fn parse_records(content: &str, algorithms: &[Algorithm]) -> Vec<ManifestRecord> {
    let expected_fields = algorithms.len() + 2; // size + N hashes + filename

    content
        .lines()
        .filter(|line| !line.starts_with("%%%%") && !line.starts_with('#') && !line.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(expected_fields, ',').collect();
            if parts.len() < expected_fields {
                return None;
            }

            let size: u64 = parts[0].parse().ok()?;
            let mut hashes = HashMap::new();
            for (i, algo) in algorithms.iter().enumerate() {
                hashes.insert(*algo, parts[i + 1].to_string());
            }
            let path = PathBuf::from(parts[algorithms.len() + 1]);

            Some(ManifestRecord { size, hashes, path })
        })
        .collect()
}
