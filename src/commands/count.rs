use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn count_entries(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let n = content
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with('%')
        })
        .count();
    writeln!(out, "{n}")?;
    Ok(())
}
