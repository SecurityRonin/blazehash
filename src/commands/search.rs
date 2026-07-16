//! Search manifest entries by path substring or hash prefix/substring.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub struct SearchOpts<'a> {
    pub path_query: Option<&'a str>,
    pub hash_query: Option<&'a str>,
    pub ignore_case: bool,
}

pub fn search_manifest(
    manifest_path: &Path,
    opts: &SearchOpts<'_>,
    out: &mut impl Write,
) -> Result<usize> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut matched = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }
        let hash = parts[1].trim();
        let path = parts[2].trim();

        let path_ok = match opts.path_query {
            None => true,
            Some(q) => {
                if opts.ignore_case {
                    path.to_ascii_lowercase().contains(&q.to_ascii_lowercase())
                } else {
                    path.contains(q)
                }
            }
        };
        let hash_ok = match opts.hash_query {
            None => true,
            Some(q) => {
                if opts.ignore_case {
                    hash.to_ascii_lowercase()
                        .starts_with(&q.to_ascii_lowercase())
                } else {
                    hash.starts_with(q)
                }
            }
        };

        if path_ok && hash_ok {
            writeln!(out, "{line}")?;
            matched += 1;
        }
    }
    Ok(matched)
}
