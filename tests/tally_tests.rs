use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const MANIFEST: &str = "\
## case: TALLY-TEST
sha256  aaaa1111111111111111111111111111111111111111111111111111111111111111  /evidence/file1.exe
sha256  bbbb2222222222222222222222222222222222222222222222222222222222222222  /evidence/file2.exe
blake3  cccc3333333333333333333333333333333333333333333333333333333333333333  /docs/readme.txt
sha256  dddd4444444444444444444444444444444444444444444444444444444444444444  /docs/notes.pdf
blake3  eeee5555555555555555555555555555555555555555555555555555555555555555  /no_extension_file
";

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    fs::write(&p, MANIFEST).unwrap();
    p
}

#[test]
fn test_tally_by_ext_default() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tally", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "tally should succeed");
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    // First line must be "2\t.exe"
    assert_eq!(
        lines.first().copied(),
        Some("2\t.exe"),
        "first line should be 2\\t.exe, got: {:?}",
        lines
    );
    assert!(text.contains(".txt"), "output should contain .txt\n{text}");
    assert!(text.contains(".pdf"), "output should contain .pdf\n{text}");
    assert!(text.contains("(none)"), "output should contain (none)\n{text}");
}

#[test]
fn test_tally_by_algo() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tally", manifest.to_str().unwrap(), "--tally-by", "algo"])
        .output()
        .unwrap();
    assert!(output.status.success(), "tally --tally-by algo should succeed");
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() >= 2, "expected at least 2 lines, got: {:?}", lines);
    assert_eq!(
        lines.first().copied(),
        Some("3\tsha256"),
        "first line should be 3\\tsha256, got: {:?}",
        lines
    );
    assert_eq!(
        lines.get(1).copied(),
        Some("2\tblake3"),
        "second line should be 2\\tblake3, got: {:?}",
        lines
    );
}

#[test]
fn test_tally_by_dir() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tally", manifest.to_str().unwrap(), "--tally-by", "dir"])
        .output()
        .unwrap();
    assert!(output.status.success(), "tally --tally-by dir should succeed");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("/evidence"), "output should contain /evidence\n{text}");
    assert!(text.contains("/docs"), "output should contain /docs\n{text}");
}

#[test]
fn test_tally_missing_manifest_fails() {
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tally", "/nonexistent/path/manifest.hash"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "tally should fail on missing manifest"
    );
}

#[test]
fn test_tally_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("tally_out.txt");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "tally",
            manifest.to_str().unwrap(),
            "--tally-by",
            "algo",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let text = fs::read_to_string(&out_path).unwrap();
    assert!(text.contains("sha256"), "output file should contain sha256\n{text}");
    assert!(text.contains("blake3"), "output file should contain blake3\n{text}");
}
