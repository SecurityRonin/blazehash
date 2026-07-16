use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_clean_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("clean.hash");
    fs::write(
        &p,
        concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/a.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  docs/b.pdf\n",
    ),
    )
    .unwrap();
    p
}

#[test]
fn test_lint_clean_manifest_exits_zero() {
    let dir = TempDir::new().unwrap();
    let manifest = write_clean_manifest(&dir);
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["lint", manifest.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn test_lint_duplicate_path_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("dup.hash");
    fs::write(
        &p,
        concat!(
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/a.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  docs/a.pdf\n",
    ),
    )
    .unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["lint", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "duplicate path should cause lint failure"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("duplicate") || combined.contains("dup"),
        "should mention duplicate, got:\n{combined}"
    );
}

#[test]
fn test_lint_duplicate_hash_warns() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("dup_hash.hash");
    fs::write(
        &p,
        concat!(
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/a.pdf\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/b.pdf\n",
    ),
    )
    .unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["lint", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "duplicate hash is a warning, not error"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.to_lowercase().contains("warn")
            || combined.contains("duplicate hash")
            || combined.contains("hardlink"),
        "should warn about duplicate hash, got:\n{combined}"
    );
}

#[test]
fn test_lint_malformed_line_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("malformed.hash");
    fs::write(&p, "this line has no double-space separator at all\n").unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["lint", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "malformed line should cause lint failure"
    );
}

#[test]
fn test_lint_json_output() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("dup.hash");
    fs::write(
        &p,
        concat!(
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/a.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  docs/a.pdf\n",
    ),
    )
    .unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["lint", p.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.trim().is_empty() {
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("--json must produce valid JSON even on failure");
        assert!(
            json["errors"].is_array() || json["warnings"].is_array(),
            "JSON should have errors or warnings array"
        );
    }
}
