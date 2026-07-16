use std::fs;
use std::io::Write;
use std::process::Command;

fn blazehash_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps/
    p.pop(); // debug/
    p.push("blazehash");
    p
}

fn write_manifest(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "{content}").unwrap();
    f.flush().unwrap();
    f
}

/// Test 1: stamp adds a ## stamped: header when none exists
#[test]
fn test_stamp_adds_stamped_header() {
    let manifest = write_manifest(
        "## case: TEST-STAMP\nsha256  abc123def456789012345678901234567890123456789012345678901234567890  /evidence/file.bin\n"
    );
    let out = Command::new(blazehash_bin())
        .args(["stamp", manifest.path().to_str().unwrap()])
        .output()
        .expect("failed to run blazehash stamp");

    assert!(
        out.status.success(),
        "blazehash stamp failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("## stamped:"),
        "output does not contain '## stamped:' header: {stdout}"
    );
}

/// Test 2: timestamp format matches YYYY-MM-DDTHH:MM:SSZ
#[test]
fn test_stamp_timestamp_format() {
    let manifest = write_manifest(
        "## case: FMT-TEST\nsha256  abc123def456789012345678901234567890123456789012345678901234567890  /evidence/file.bin\n"
    );
    let out = Command::new(blazehash_bin())
        .args(["stamp", manifest.path().to_str().unwrap()])
        .output()
        .expect("failed to run blazehash stamp");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Find the stamped line
    let stamped_line = stdout
        .lines()
        .find(|l| l.starts_with("## stamped:"))
        .expect("no '## stamped:' line found in output");

    // Extract the timestamp portion
    let ts = stamped_line.trim_start_matches("## stamped:").trim();

    // Check basic format: YYYY-MM-DDTHH:MM:SSZ
    assert!(
        ts.len() == 20,
        "timestamp length should be 20, got {} for {:?}",
        ts.len(),
        ts
    );
    assert!(ts.ends_with('Z'), "timestamp should end with Z: {ts}");
    assert_eq!(&ts[4..5], "-", "char 4 should be '-': {ts}");
    assert_eq!(&ts[7..8], "-", "char 7 should be '-': {ts}");
    assert_eq!(&ts[10..11], "T", "char 10 should be 'T': {ts}");
    assert_eq!(&ts[13..14], ":", "char 13 should be ':': {ts}");
    assert_eq!(&ts[16..17], ":", "char 16 should be ':': {ts}");
    // All digit positions should actually be digits
    for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 19] {
        // skip Z at 19 (end)
        if i == 19 {
            break;
        }
        let c = ts.chars().nth(i).unwrap();
        assert!(
            c.is_ascii_digit(),
            "char at {i} should be a digit, got {c}: {ts}"
        );
    }
}

/// Test 3: stamp replaces an existing ## stamped: header
#[test]
fn test_stamp_replaces_existing_stamp() {
    let manifest = write_manifest(
        "## case: REPLACE-TEST\n## stamped: 2020-01-01T00:00:00Z\nsha256  abc123def456789012345678901234567890123456789012345678901234567890  /evidence/file.bin\n"
    );
    let out = Command::new(blazehash_bin())
        .args(["stamp", manifest.path().to_str().unwrap()])
        .output()
        .expect("failed to run blazehash stamp");

    assert!(
        out.status.success(),
        "blazehash stamp failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Should contain exactly one ## stamped: line
    let stamped_count = stdout
        .lines()
        .filter(|l| l.starts_with("## stamped:"))
        .count();
    assert_eq!(
        stamped_count, 1,
        "expected exactly 1 '## stamped:' line, got {stamped_count}: {stdout}"
    );

    // Old timestamp should be gone
    assert!(
        !stdout.contains("2020-01-01T00:00:00Z"),
        "old timestamp should have been replaced: {stdout}"
    );
}

/// Test 4: stamp preserves other ## headers
#[test]
fn test_stamp_preserves_other_headers() {
    let manifest = write_manifest(
        "## case: MYCASE\n## examiner: Alice\nsha256  abc123def456789012345678901234567890123456789012345678901234567890  /evidence/file.bin\n"
    );
    let out = Command::new(blazehash_bin())
        .args(["stamp", manifest.path().to_str().unwrap()])
        .output()
        .expect("failed to run blazehash stamp");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("## case: MYCASE"),
        "output missing '## case: MYCASE' header: {stdout}"
    );
    assert!(
        stdout.contains("## examiner: Alice"),
        "output missing '## examiner: Alice' header: {stdout}"
    );
}

/// Test 5: stamp -o writes stamped manifest to file
#[test]
fn test_stamp_output_to_file() {
    let manifest = write_manifest(
        "## case: OUTPUT-TEST\nsha256  abc123def456789012345678901234567890123456789012345678901234567890  /evidence/file.bin\n"
    );
    let out_file = tempfile::NamedTempFile::new().unwrap();
    let out_path = out_file.path().to_str().unwrap().to_string();
    // Drop NamedTempFile so we can write to path without conflict
    drop(out_file);

    let status = Command::new(blazehash_bin())
        .args(["stamp", manifest.path().to_str().unwrap(), "-o", &out_path])
        .status()
        .expect("failed to run blazehash stamp");

    assert!(status.success(), "blazehash stamp -o failed");

    let content = fs::read_to_string(&out_path).expect("failed to read output file");
    assert!(
        content.contains("## stamped:"),
        "output file does not contain '## stamped:': {content}"
    );
}
