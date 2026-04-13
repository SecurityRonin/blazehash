use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub struct FilterOpts<'a> {
    pub include: Option<&'a [String]>,
    pub algo: Option<&'a str>,
}

pub fn filter_manifest<W: Write>(
    manifest_path: &Path,
    opts: &FilterOpts<'_>,
    out: &mut W,
) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

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
        let algo = parts[0].trim();
        let path = parts[2].trim();

        if let Some(required_algo) = opts.algo {
            if !algo.eq_ignore_ascii_case(required_algo) {
                continue;
            }
        }
        if let Some(patterns) = opts.include {
            let matched = patterns.iter().any(|pat| glob_match(pat, path));
            if !matched {
                continue;
            }
        }
        writeln!(out, "{line}")?;
    }
    Ok(())
}

fn glob_match(pattern: &str, path: &str) -> bool {
    let path = path.replace('\\', "/");
    let pattern = pattern.replace('\\', "/");
    glob_match_inner(&pattern, &path)
}

fn glob_match_inner(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern == "**" {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix("**/") {
        if glob_match_inner(rest, text) {
            return true;
        }
        if let Some(slash) = text.find('/') {
            return glob_match_inner(pattern, &text[slash + 1..]);
        }
        return false;
    }
    let (pat_seg, pat_rest) = match pattern.find('/') {
        Some(i) => (&pattern[..i], Some(&pattern[i + 1..])),
        None => (pattern, None),
    };
    let (txt_seg, txt_rest) = match text.find('/') {
        Some(i) => (&text[..i], Some(&text[i + 1..])),
        None => (text, None),
    };
    if !segment_match(pat_seg, txt_seg) {
        return false;
    }
    match (pat_rest, txt_rest) {
        (None, None) => true,
        (Some(p), Some(t)) => glob_match_inner(p, t),
        _ => false,
    }
}

fn segment_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            return text[pos..].ends_with(part);
        } else if let Some(found) = text[pos..].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}
