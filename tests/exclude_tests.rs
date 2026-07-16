use assert_cmd::Command;
use std::io::Write;
use tempfile::NamedTempFile;

const MANIFEST: &str = "\
## case: EXCLUDE-TEST
sha256  aaaa1111111111111111111111111111111111111111111111111111111111111111  /evidence/file1.exe
sha256  bbbb2222222222222222222222222222222222222222222222222222222222222222  /docs/readme.txt
blake3  cccc3333333333333333333333333333333333333333333333333333333333333333  /tmp/scratch.tmp
sha256  dddd4444444444444444444444444444444444444444444444444444444444444444  /evidence/report.pdf
";

fn write_manifest() -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(MANIFEST.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn test_exclude_drops_matching_entries() {
    let manifest = write_manifest();
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "exclude",
            manifest.path().to_str().unwrap(),
            "--exclude-pattern",
            "*.tmp",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("scratch.tmp"),
        "scratch.tmp should be excluded"
    );
    assert!(stdout.contains("file1.exe"), "file1.exe should be kept");
    assert!(stdout.contains("readme.txt"), "readme.txt should be kept");
}

#[test]
fn test_exclude_preserves_headers() {
    let manifest = write_manifest();
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "exclude",
            manifest.path().to_str().unwrap(),
            "--exclude-pattern",
            "*.tmp",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("## case:"),
        "header should be preserved in output"
    );
}

#[test]
fn test_exclude_glob_with_directory_prefix() {
    let manifest = write_manifest();
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "exclude",
            manifest.path().to_str().unwrap(),
            "--exclude-pattern",
            "/evidence/*",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("file1.exe"),
        "file1.exe should be excluded"
    );
    assert!(
        !stdout.contains("report.pdf"),
        "report.pdf should be excluded"
    );
    assert!(stdout.contains("readme.txt"), "readme.txt should be kept");
}

#[test]
fn test_exclude_no_matches_passes_all_through() {
    let manifest = write_manifest();
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "exclude",
            manifest.path().to_str().unwrap(),
            "--exclude-pattern",
            "*.xyz",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("file1.exe"), "file1.exe should be kept");
    assert!(stdout.contains("readme.txt"), "readme.txt should be kept");
    assert!(stdout.contains("scratch.tmp"), "scratch.tmp should be kept");
    assert!(stdout.contains("report.pdf"), "report.pdf should be kept");
}

#[test]
fn test_exclude_output_to_file() {
    let manifest = write_manifest();
    let out_file = NamedTempFile::new().unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "exclude",
            manifest.path().to_str().unwrap(),
            "--exclude-pattern",
            "*.tmp",
            "-o",
            out_file.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    let contents = std::fs::read_to_string(out_file.path()).unwrap();
    assert!(
        !contents.contains("scratch.tmp"),
        "excluded entry should not be in output file"
    );
    assert!(
        contents.contains("file1.exe"),
        "kept entry should be in output file"
    );
}
