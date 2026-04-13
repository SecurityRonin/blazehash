use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("evidence.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "## examiner: Jane Smith\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  secret/docs/contract.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  secret/logs/activity.log\n",
    )).unwrap();
    p
}

#[test]
fn test_redact_removes_paths() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    assert!(!content.contains("contract.pdf"), "path must be removed");
    assert!(!content.contains("activity.log"), "path must be removed");
    assert!(!content.contains("secret/"), "directory must be removed");
}

#[test]
fn test_redact_preserves_hashes() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    assert!(content.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(content.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
}

#[test]
fn test_redact_replaces_with_uuids() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    // UUID pattern: 8-4-4-4-12 hex chars
    let re = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
    let hash_lines: Vec<_> = content.lines().filter(|l| l.starts_with("sha256")).collect();
    assert_eq!(hash_lines.len(), 2);
    for line in &hash_lines {
        assert!(re.is_match(line), "UUID not found in line: {line}");
    }
}

#[test]
fn test_redact_is_deterministic() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out1 = dir.path().join("r1.hash");
    let out2 = dir.path().join("r2.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out1.to_str().unwrap()])
        .assert().success();
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out2.to_str().unwrap()])
        .assert().success();
    assert_eq!(fs::read_to_string(&out1).unwrap(), fs::read_to_string(&out2).unwrap());
}

#[test]
fn test_redact_preserves_case_and_examiner_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    assert!(content.contains("## case: CASE-001"));
    assert!(content.contains("## examiner: Jane Smith"));
}

#[test]
fn test_redact_includes_merkle_root_comment() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("redacted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    assert!(content.contains("## merkle_root:"), "must include merkle root comment");
}

#[test]
fn test_redact_requires_output_flag() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    Command::cargo_bin("blazehash").unwrap()
        .args(["redact", manifest.to_str().unwrap()])
        .assert().failure();
}
