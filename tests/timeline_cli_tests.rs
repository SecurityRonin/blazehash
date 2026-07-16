use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, "sha256  aaa  file.bin\n").unwrap();
    p
}

#[test]
fn test_cli_timeline_json_stdout() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["timeline", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    assert!(json.is_array(), "output must be a JSON array");
    // Must have at least the Acquired event
    assert!(!json.as_array().unwrap().is_empty());
}

#[test]
fn test_cli_timeline_html_output() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let html_out = dir.path().join("timeline.html");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "timeline",
            manifest.to_str().unwrap(),
            "-o",
            html_out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let html = fs::read_to_string(&html_out).unwrap();
    assert!(html.contains("<html"), "must be valid HTML");
    assert!(html.contains("<table"), "must contain a table");
}

#[test]
fn test_cli_timeline_json_file_output() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let json_out = dir.path().join("timeline.json");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "timeline",
            manifest.to_str().unwrap(),
            "-o",
            json_out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&json_out).unwrap())
        .expect("output file must be valid JSON");
    assert!(json.is_array());
}

#[test]
fn test_cli_timeline_missing_manifest_fails() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["timeline", "/nonexistent/path/case.hash"])
        .assert()
        .failure();
}
