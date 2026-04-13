use anyhow::Result;
use std::path::Path;

pub fn split_manifest(manifest_path: &Path, chunk_size: usize, out_base: &Path) -> Result<usize> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<&str> = Vec::new();
    let mut entries: Vec<&str> = Vec::new();

    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('#') || t.starts_with('%') {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }

    let stem = out_base.to_string_lossy();
    let mut chunk_num = 0usize;
    for chunk in entries.chunks(chunk_size) {
        chunk_num += 1;
        let filename = format!("{stem}_{chunk_num:03}.hash");
        let mut buf = String::new();
        for h in &headers {
            buf.push_str(h);
            buf.push('\n');
        }
        for e in chunk {
            buf.push_str(e);
            buf.push('\n');
        }
        std::fs::write(&filename, &buf)?;
    }

    Ok(chunk_num)
}
