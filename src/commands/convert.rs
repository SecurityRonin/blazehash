//! Convert legacy hash manifest formats (md5sum, sha256sum, hashdeep, sfv)
//! into the blazehash two-space format: `algo  hash  path`.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn convert_manifest(
    input_path: &Path,
    format: &str,
    out: &mut impl Write,
) -> Result<()> {
    let content = std::fs::read_to_string(input_path)?;
    writeln!(out, "## converted-from: {format}")?;
    match format.to_ascii_lowercase().as_str() {
        "sha256sum" => convert_sumfile(&content, "sha256", out),
        "sha1sum"   => convert_sumfile(&content, "sha1", out),
        "md5sum"    => convert_sumfile(&content, "md5", out),
        "hashdeep"  => convert_hashdeep(&content, out),
        "sfv"       => convert_sfv(&content, out),
        other       => bail!("unknown format '{other}'; supported: sha256sum, sha1sum, md5sum, hashdeep, sfv"),
    }
}

/// Parse `sha256sum`-style lines: `<hash>  <path>` or `<hash> *<path>`.
fn convert_sumfile(content: &str, algo: &str, out: &mut impl Write) -> Result<()> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((hash, rest)) = line.split_once(|c: char| c.is_ascii_whitespace()) {
            let path = rest.trim_start_matches(|c: char| c.is_ascii_whitespace())
                          .trim_start_matches('*');
            let hash = hash.trim();
            if !path.is_empty() && !hash.is_empty() {
                writeln!(out, "{algo}  {hash}  {path}")?;
            }
        }
    }
    Ok(())
}

/// Parse hashdeep CSV format.
fn convert_hashdeep(content: &str, out: &mut impl Write) -> Result<()> {
    let mut algos: Vec<String> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("%%%%") {
            if let Some(rest) = line.strip_prefix("%%%%") {
                let rest = rest.trim();
                if rest.starts_with("size,") || rest.contains(',') {
                    let fields: Vec<&str> = rest.split(',').collect();
                    for f in fields.iter().skip(1) {
                        if *f != "filename" {
                            algos.push(f.to_ascii_lowercase());
                        }
                    }
                }
            }
            continue;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if algos.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(algos.len() + 2, ',').collect();
        if parts.len() < algos.len() + 2 {
            continue;
        }
        let filename = parts[algos.len() + 1];
        for (i, algo) in algos.iter().enumerate() {
            let hash = parts[i + 1];
            writeln!(out, "{algo}  {hash}  {filename}")?;
        }
    }
    Ok(())
}

/// Parse SFV: `; comment` lines, `<filename> <CRC32>` (reversed!).
fn convert_sfv(content: &str, out: &mut impl Write) -> Result<()> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some((filename, hash)) = line.rsplit_once(|c: char| c.is_ascii_whitespace()) {
            let filename = filename.trim_end();
            let hash = hash.trim();
            if !filename.is_empty() && !hash.is_empty() {
                writeln!(out, "crc32  {hash}  {filename}")?;
            }
        }
    }
    Ok(())
}
