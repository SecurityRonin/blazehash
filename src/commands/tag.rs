use anyhow::Result;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

pub fn tag_manifest(
    manifest_path: &Path,
    set_pairs: &[String],
    unset_keys: &[String],
    out: &mut impl Write,
) -> Result<()> {
    let mut updates: HashMap<String, String> = HashMap::new();
    for pair in set_pairs {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--set requires key=value format, got: {pair}"))?;
        updates.insert(k.trim().to_string(), v.trim().to_string());
    }
    let remove: std::collections::HashSet<String> =
        unset_keys.iter().map(|k| k.trim().to_string()).collect();

    let content = std::fs::read_to_string(manifest_path)?;
    let mut seen_keys: std::collections::HashSet<String> = Default::default();

    // Emit existing header lines (updated/filtered)
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("##") {
            let rest = rest.trim();
            if let Some((k, _)) = rest.split_once(':') {
                let key = k.trim().to_string();
                if remove.contains(&key) {
                    continue;
                }
                if let Some(new_val) = updates.get(&key) {
                    writeln!(out, "## {key}: {new_val}")?;
                    seen_keys.insert(key);
                    continue;
                }
                seen_keys.insert(key);
            }
            writeln!(out, "{line}")?;
        }
    }

    // Emit new headers not already in manifest
    let mut new_keys: Vec<_> = updates
        .keys()
        .filter(|k| !seen_keys.contains(*k) && !remove.contains(*k))
        .collect();
    new_keys.sort();
    for k in new_keys {
        writeln!(out, "## {k}: {}", updates[k])?;
    }

    // Emit data lines
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        writeln!(out, "{line}")?;
    }

    Ok(())
}
