use assert_cmd::Command;

#[test]
fn test_selfcheck_prints_hash() {
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("selfcheck")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let has_blake3_hash = stdout
        .split_whitespace()
        .any(|tok| tok.len() == 64 && tok.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        has_blake3_hash,
        "expected 64-char hex hash in output, got:\n{stdout}"
    );
}

#[test]
fn test_selfcheck_json_output() {
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["selfcheck", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("selfcheck --json must produce valid JSON");
    assert!(
        json["blake3"]
            .as_str()
            .map(|h| h.len() == 64)
            .unwrap_or(false),
        "JSON should have blake3 field with 64-char hash"
    );
    assert!(json["path"].is_string(), "JSON should include binary path");
}

#[test]
fn test_selfcheck_includes_size() {
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("selfcheck")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("size") || stdout.contains("bytes") || stdout.contains("MB"),
        "selfcheck should report binary size, got:\n{stdout}"
    );
}

#[test]
fn test_selfcheck_deterministic() {
    let out1 = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["selfcheck", "--json"])
        .output()
        .unwrap();
    let out2 = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["selfcheck", "--json"])
        .output()
        .unwrap();
    assert_eq!(out1.stdout, out2.stdout, "selfcheck must be deterministic");
}
