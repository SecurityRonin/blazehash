use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_slice_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    let mut content = String::from("## case: TEST-SLICE\n");
    for i in 1..=10 {
        content.push_str(&format!(
            "sha256  aaaa{:02}11111111111111111111111111111111111111111111111111111111111  file{:03}.bin\n",
            i, i
        ));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_slice_default_count() {
    let dir = TempDir::new().unwrap();
    let manifest = write_slice_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["slice", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "slice should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for i in 1..=10 {
        assert!(
            stdout.contains(&format!("file{:03}.bin", i)),
            "file{:03}.bin should be present in default output",
            i
        );
    }
}

#[test]
fn test_slice_offset_skips_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_slice_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["slice", manifest.to_str().unwrap(), "--offset", "3"])
        .output()
        .unwrap();
    assert!(out.status.success(), "slice with --offset should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // With offset 3 and default count 10, first data entry should be file004.bin
    let data_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with('%')
        })
        .collect();
    assert!(
        !data_lines.is_empty(),
        "should have data entries after offset 3"
    );
    assert!(
        data_lines[0].contains("file004.bin"),
        "first data entry after offset 3 should be file004.bin, got: {}",
        data_lines[0]
    );
}

#[test]
fn test_slice_offset_and_count() {
    let dir = TempDir::new().unwrap();
    let manifest = write_slice_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "slice",
            manifest.to_str().unwrap(),
            "--offset",
            "2",
            "--count",
            "3",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "slice with --offset and --count should succeed"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with('%')
        })
        .collect();
    assert_eq!(data_lines.len(), 3, "should have exactly 3 data entries");
    assert!(
        data_lines[0].contains("file003.bin"),
        "first entry should be file003.bin"
    );
    assert!(
        data_lines[1].contains("file004.bin"),
        "second entry should be file004.bin"
    );
    assert!(
        data_lines[2].contains("file005.bin"),
        "third entry should be file005.bin"
    );
}

#[test]
fn test_slice_offset_beyond_end() {
    let dir = TempDir::new().unwrap();
    let manifest = write_slice_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["slice", manifest.to_str().unwrap(), "--offset", "100"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "slice with offset beyond end should succeed"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Header should be present
    assert!(
        stdout.contains("## case: TEST-SLICE"),
        "header should be present even when offset exceeds entries"
    );
    // No data entries
    let data_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with('%')
        })
        .collect();
    assert!(
        data_lines.is_empty(),
        "offset beyond end should produce no data entries, got: {:?}",
        data_lines
    );
}

#[test]
fn test_slice_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_slice_manifest(&dir);
    let out_path = dir.path().join("sliced.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "slice",
            manifest.to_str().unwrap(),
            "--offset",
            "0",
            "--count",
            "2",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("file001.bin"),
        "output file should contain file001.bin"
    );
    assert!(
        content.contains("file002.bin"),
        "output file should contain file002.bin"
    );
    assert!(
        !content.contains("file003.bin"),
        "output file should NOT contain file003.bin (count=2)"
    );
}
