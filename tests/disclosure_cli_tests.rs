// tests/disclosure_cli_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    fs::write(&p, concat!(
        "# blazehash manifest\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  evidence/a.bin\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  evidence/b.bin\n",
    )).unwrap();
    p
}

#[test]
fn test_cli_disclose_produces_json() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("proof.json");
    Command::cargo_bin("blazehash").unwrap()
        .args(["disclose", manifest.to_str().unwrap(),
               "--paths", "evidence/a.bin",
               "-o", out.to_str().unwrap()])
        .assert().success();
    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(json["disclosed"][0]["path"], "evidence/a.bin");
    assert_eq!(json["root"].as_str().unwrap().len(), 64);
}

#[test]
fn test_cli_disclose_stdout_when_no_output_flag() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["disclose", manifest.to_str().unwrap(),
               "--paths", "evidence/a.bin"])
        .output().unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["root"].as_str().is_some());
}

#[test]
fn test_cli_prove_membership_produces_json() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = dir.path().join("membership.json");
    Command::cargo_bin("blazehash").unwrap()
        .args(["prove-membership", manifest.to_str().unwrap(),
               "--sha256", &"a".repeat(64),
               "-o", out.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(json["root"].as_str().is_some());
    // Path must NOT appear in output
    assert!(!content.contains("evidence/a.bin"), "file path must not appear in membership proof");
}

#[test]
fn test_cli_disclose_unknown_path_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    Command::cargo_bin("blazehash").unwrap()
        .args(["disclose", manifest.to_str().unwrap(),
               "--paths", "no_such_file.bin"])
        .assert().failure();
}

#[test]
fn test_cli_disclose_multiple_paths_comma_separated() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["disclose", manifest.to_str().unwrap(),
               "--paths", "evidence/a.bin,evidence/b.bin"])
        .output().unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["disclosed"].as_array().unwrap().len(), 2);
}

#[test]
fn test_cli_prove_membership_stdout_when_no_output_flag() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["prove-membership", manifest.to_str().unwrap(),
               "--sha256", &"a".repeat(64)])
        .output().unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["root"].as_str().is_some());
}
