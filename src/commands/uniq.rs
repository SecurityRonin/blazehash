use anyhow::Result;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

pub fn uniq_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<&str> = Vec::new();
    let mut order: Vec<String> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();

    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('#') || t.starts_with('%') {
            headers.push(line);
            continue;
        }
        let parts: Vec<&str> = t.splitn(3, "  ").collect();
        let path_key = if parts.len() == 3 {
            parts[2].trim().to_string()
        } else {
            line.to_string()
        };
        if let Some(&idx) = seen.get(&path_key) {
            order[idx] = line.to_string();
        } else {
            seen.insert(path_key, order.len());
            order.push(line.to_string());
        }
    }

    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for entry in &order {
        writeln!(out, "{entry}")?;
    }
    Ok(())
}
