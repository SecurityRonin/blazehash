use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimelineEventKind {
    Acquired,
    Signed { pubkey: String },
    Cosigned { pubkey: String },
    Timestamped,
    PqSigned { pubkey_prefix: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub kind: TimelineEventKind,
    pub timestamp: Option<String>,
    pub description: String,
}

fn file_mtime_iso(path: &Path) -> Option<String> {
    let secs = std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let dt = chrono::DateTime::from_timestamp(secs as i64, 0)?;
    Some(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn read_sidecar_meta(path: &Path, key: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let prefix = format!("# {key}: ");
    for line in content.lines().take(10) {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn sidecar_path(manifest_path: &Path, ext: &str) -> anyhow::Result<std::path::PathBuf> {
    let base = manifest_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("manifest path has no file name"))?
        .to_string_lossy();
    let name = format!("{base}.{ext}");
    Ok(manifest_path.parent().unwrap_or(Path::new(".")).join(name))
}

pub fn build_timeline(manifest_path: &Path) -> Result<Vec<TimelineEvent>> {
    let mut events: Vec<TimelineEvent> = Vec::new();

    // 1. Acquired event from manifest mtime
    events.push(TimelineEvent {
        kind: TimelineEventKind::Acquired,
        timestamp: file_mtime_iso(manifest_path),
        description: format!(
            "Manifest acquired: {}",
            manifest_path.file_name().unwrap_or_default().to_string_lossy()
        ),
    });

    // 2. .sig sidecar
    let sig_path = sidecar_path(manifest_path, "sig")?;
    if sig_path.exists() {
        let signed_at = read_sidecar_meta(&sig_path, "signed_at");
        let pubkey = read_sidecar_meta(&sig_path, "pubkey").unwrap_or_default();
        events.push(TimelineEvent {
            kind: TimelineEventKind::Signed { pubkey: pubkey.clone() },
            timestamp: signed_at,
            description: format!("Ed25519 signature by pubkey {pubkey}"),
        });
    }

    // 3. .msig sidecar
    let msig_path = sidecar_path(manifest_path, "msig")?;
    if msig_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&msig_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(sigs) = val.get("signatures").and_then(|s| s.as_array()) {
                    for sig in sigs {
                        let pubkey = sig
                            .get("pubkey")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let signed_at = sig
                            .get("signed_at")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        events.push(TimelineEvent {
                            kind: TimelineEventKind::Cosigned { pubkey: pubkey.clone() },
                            timestamp: signed_at,
                            description: format!("Co-signed by pubkey {pubkey}"),
                        });
                    }
                }
            }
        }
    }

    // 4. .ots sidecar
    let ots_path = sidecar_path(manifest_path, "ots")?;
    if ots_path.exists() {
        events.push(TimelineEvent {
            kind: TimelineEventKind::Timestamped,
            timestamp: file_mtime_iso(&ots_path),
            description: "OpenTimestamps proof present".to_string(),
        });
    }

    // 5. .pqsig sidecar
    let pqsig_path = sidecar_path(manifest_path, "pqsig")?;
    if pqsig_path.exists() {
        let signed_at = read_sidecar_meta(&pqsig_path, "signed_at");
        let pubkey = read_sidecar_meta(&pqsig_path, "pubkey").unwrap_or_default();
        let pubkey_prefix = pubkey.chars().take(16).collect::<String>();
        events.push(TimelineEvent {
            kind: TimelineEventKind::PqSigned { pubkey_prefix: pubkey_prefix.clone() },
            timestamp: signed_at,
            description: format!("ML-DSA post-quantum signature by pubkey prefix {pubkey_prefix}"),
        });
    }

    // Sort by timestamp (None sorts last)
    events.sort_by(|a, b| match (&a.timestamp, &b.timestamp) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(x), Some(y)) => x.cmp(y),
    });

    Ok(events)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#39;")
}

pub fn render_timeline_html(events: &[TimelineEvent], manifest_path: &Path) -> Result<String> {
    let manifest = manifest_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    let mut rows = String::new();
    for event in events {
        let ts = event.timestamp.as_deref().unwrap_or("—");
        let kind = match &event.kind {
            TimelineEventKind::Acquired => "Acquired".to_string(),
            TimelineEventKind::Signed { pubkey } => format!("Signed ({pubkey})"),
            TimelineEventKind::Cosigned { pubkey } => format!("Cosigned ({pubkey})"),
            TimelineEventKind::Timestamped => "Timestamped".to_string(),
            TimelineEventKind::PqSigned { pubkey_prefix } => {
                format!("PQ-Signed ({pubkey_prefix}…)")
            }
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            html_escape(ts), html_escape(&kind), html_escape(&event.description)
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Chain-of-Custody Timeline: {manifest}</title>
<style>
  body {{ font-family: sans-serif; margin: 2em; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: 0.5em 1em; text-align: left; }}
  th {{ background: #f0f0f0; }}
</style>
</head>
<body>
<h1>Chain-of-Custody Timeline</h1>
<p>Manifest: <code>{manifest}</code></p>
<table>
<thead><tr><th>Timestamp</th><th>Event</th><th>Description</th></tr></thead>
<tbody>
{rows}</tbody>
</table>
</body>
</html>
"#,
    );

    Ok(html)
}
