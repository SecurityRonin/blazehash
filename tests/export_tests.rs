use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/contract.pdf\n",
        "blake3  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  images/photo.jpg\n",
    )).unwrap();
    p
}

#[test]
fn test_export_csv_has_header_row() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--export-format", "csv"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(first_line.to_ascii_lowercase().contains("algo") ||
            first_line.to_ascii_lowercase().contains("algorithm"),
        "CSV first line must be a header with algo column, got: {first_line}");
}

#[test]
fn test_export_csv_has_data_rows() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--export-format", "csv"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("contract.pdf"), "CSV must contain path");
    assert!(stdout.contains("sha256"), "CSV must contain algo");
}

#[test]
fn test_export_jsonl_one_json_object_per_line() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--export-format", "jsonl"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let obj: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("JSONL line is not valid JSON: {line}\n{e}"));
        assert!(obj["path"].is_string(), "JSON line must have path field");
        assert!(obj["hash"].is_string(), "JSON line must have hash field");
        assert!(obj["algo"].is_string(), "JSON line must have algo field");
    }
}

#[test]
fn test_export_tsv_tab_separated() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--export-format", "tsv"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let has_tab = stdout.lines()
        .filter(|l| !l.trim().is_empty())
        .any(|l| l.contains('\t'));
    assert!(has_tab, "TSV output must contain tab characters");
}

#[test]
fn test_export_unknown_format_fails() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--export-format", "xls"])
        .assert().failure();
}

#[test]
fn test_export_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("out.csv");
    Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--export-format", "csv",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("contract.pdf"));
}
