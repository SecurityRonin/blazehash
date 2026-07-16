//! Sort manifest entries by a chosen field (path, hash, algo, or ext).
//! Header/comment lines are emitted first in original order, then sorted data lines.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn sort_manifest(manifest_path: &Path, by: &str, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

    let mut headers: Vec<&str> = Vec::new();
    let mut entries: Vec<&str> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }

    entries.sort_by(|a, b| {
        let key_a = sort_key(a, by);
        let key_b = sort_key(b, by);
        key_a.cmp(key_b)
    });

    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for e in &entries {
        writeln!(out, "{e}")?;
    }
    Ok(())
}

fn sort_key<'a>(line: &'a str, by: &str) -> &'a str {
    let parts: Vec<&str> = line.splitn(3, "  ").collect();
    if parts.len() != 3 {
        return line;
    }
    match by {
        "hash" => parts[1].trim(),
        "algo" => parts[0].trim(),
        "ext" => {
            let path = parts[2].trim();
            match path.rfind('.') {
                Some(i) => &path[i..],
                None => path,
            }
        }
        _ => parts[2].trim(), // default: sort by path
    }
}

pub fn validate_sort_by(by: &str) -> Result<()> {
    match by {
        "path" | "hash" | "algo" | "ext" => Ok(()),
        other => bail!("unknown sort field '{other}'; supported: path, hash, algo, ext"),
    }
}
