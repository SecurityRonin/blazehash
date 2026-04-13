use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn stamp_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let ts = now_iso8601();
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<String> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    let mut has_stamp = false;

    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("##") || trimmed.starts_with("%%") {
            if trimmed.starts_with("## stamped:") || trimmed.starts_with("##stamped:") {
                headers.push(format!("## stamped: {ts}"));
                has_stamp = true;
            } else {
                headers.push(line.to_string());
            }
        } else if line.trim().is_empty() {
            // skip blank lines between headers; they'll be naturally absent
        } else {
            entries.push(line.to_string());
        }
    }

    if !has_stamp {
        headers.push(format!("## stamped: {ts}"));
    }

    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for e in &entries {
        writeln!(out, "{e}")?;
    }
    Ok(())
}

fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d)
}
