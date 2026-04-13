use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn cat_manifests(paths: &[&Path], out: &mut impl Write) -> Result<()> {
    if paths.len() < 2 {
        anyhow::bail!("cat: requires at least two manifest paths");
    }
    let first = std::fs::read_to_string(paths[0])?;
    for line in first.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.starts_with('%') {
            writeln!(out, "{line}")?;
        }
    }
    for path in paths {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') && !t.starts_with('%') {
                writeln!(out, "{line}")?;
            }
        }
    }
    Ok(())
}
