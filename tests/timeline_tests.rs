// tests/timeline_tests.rs
use blazehash::timeline::{build_timeline, TimelineEvent, TimelineEventKind};
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, "sha256  aaa  file.bin\n").unwrap();
    p
}

fn write_sidecar(dir: &TempDir, name: &str, content: &str) {
    fs::write(dir.path().join(name), content).unwrap();
}

#[test]
fn test_timeline_has_acquired_event() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let events = build_timeline(&manifest).unwrap();
    assert!(!events.is_empty());
    assert!(events.iter().any(|e| matches!(e.kind, TimelineEventKind::Acquired)));
}

#[test]
fn test_timeline_includes_sig_event() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    write_sidecar(&dir, "case.hash.sig",
        "# signed_at: 2026-04-13T00:00:00Z\n# pubkey: abcd1234\naabbccdd");
    let events = build_timeline(&manifest).unwrap();
    assert!(events.iter().any(|e| matches!(e.kind, TimelineEventKind::Signed { .. })));
}

#[test]
fn test_timeline_includes_msig_events() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let msig = r#"{"manifest_sha256":"aaa","signatures":[
        {"pubkey":"aa","sig":"bb","signed_at":"2026-04-13T01:00:00Z"},
        {"pubkey":"cc","sig":"dd","signed_at":"2026-04-13T02:00:00Z"}
    ]}"#;
    write_sidecar(&dir, "case.hash.msig", msig);
    let events = build_timeline(&manifest).unwrap();
    let count = events.iter().filter(|e| matches!(e.kind, TimelineEventKind::Cosigned { .. })).count();
    assert_eq!(count, 2);
}

#[test]
fn test_timeline_includes_ots_event() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    write_sidecar(&dir, "case.hash.ots", "dummy ots");
    let events = build_timeline(&manifest).unwrap();
    assert!(events.iter().any(|e| matches!(e.kind, TimelineEventKind::Timestamped)));
}

#[test]
fn test_timeline_events_sorted_by_time() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    write_sidecar(&dir, "case.hash.sig",
        "# signed_at: 2026-04-14T00:00:00Z\naabbccdd");
    let events = build_timeline(&manifest).unwrap();
    let timestamps: Vec<_> = events.iter()
        .filter_map(|e| e.timestamp.as_deref())
        .collect();
    let mut sorted = timestamps.clone();
    sorted.sort();
    assert_eq!(timestamps, sorted);
}

#[test]
fn test_timeline_json_roundtrip() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let events = build_timeline(&manifest).unwrap();
    let json = serde_json::to_string(&events).unwrap();
    let parsed: Vec<TimelineEvent> = serde_json::from_str(&json).unwrap();
    assert_eq!(events.len(), parsed.len());
}

#[test]
fn test_render_timeline_html_contains_table() {
    use blazehash::timeline::render_timeline_html;
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let events = build_timeline(&manifest).unwrap();
    let html = render_timeline_html(&events, &manifest).unwrap();
    assert!(html.contains("<html"));
    assert!(html.contains("<table"));
    assert!(html.contains("<tr"));
}
