use std::io::Write;
use tempfile::NamedTempFile;

const MANIFEST: &str = "\
## case: TALLY-TEST
sha256  aaaa1111111111111111111111111111111111111111111111111111111111111111  /evidence/file1.exe
sha256  bbbb2222222222222222222222222222222222222222222222222222222222222222  /evidence/file2.exe
blake3  cccc3333333333333333333333333333333333333333333333333333333333333333  /docs/readme.txt
sha256  dddd4444444444444444444444444444444444444444444444444444444444444444  /docs/notes.pdf
blake3  eeee5555555555555555555555555555555555555555555555555555555555555555  /no_extension_file
";

fn write_manifest() -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(MANIFEST.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn test_tally_by_ext_default() {
    let manifest = write_manifest();
    let mut out = Vec::new();
    blazehash::commands::tally::tally_manifest(manifest.path(), "ext", &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    // First line must be "2\t.exe"
    assert_eq!(lines[0], "2\t.exe", "first line should be 2\t.exe, got: {:?}", lines);
    // Output must contain .txt, .pdf, (none)
    assert!(text.contains(".txt"), "output should contain .txt\n{text}");
    assert!(text.contains(".pdf"), "output should contain .pdf\n{text}");
    assert!(text.contains("(none)"), "output should contain (none)\n{text}");
}

#[test]
fn test_tally_by_algo() {
    let manifest = write_manifest();
    let mut out = Vec::new();
    blazehash::commands::tally::tally_manifest(manifest.path(), "algo", &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() >= 2, "expected at least 2 lines, got: {:?}", lines);
    assert_eq!(lines[0], "3\tsha256", "first line should be 3\tsha256, got: {:?}", lines[0]);
    assert_eq!(lines[1], "2\tblake3", "second line should be 2\tblake3, got: {:?}", lines[1]);
}

#[test]
fn test_tally_by_dir() {
    let manifest = write_manifest();
    let mut out = Vec::new();
    blazehash::commands::tally::tally_manifest(manifest.path(), "dir", &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("/evidence"), "output should contain /evidence\n{text}");
    assert!(text.contains("/docs"), "output should contain /docs\n{text}");
}

#[test]
fn test_tally_missing_manifest_fails() {
    let mut out = Vec::new();
    let result = blazehash::commands::tally::tally_manifest(
        std::path::Path::new("/nonexistent/path/manifest.hash"),
        "ext",
        &mut out,
    );
    assert!(result.is_err(), "should fail on missing manifest");
}

#[test]
fn test_tally_output_to_file() {
    let manifest = write_manifest();
    let out_file = NamedTempFile::new().unwrap();
    let mut out = std::fs::File::create(out_file.path()).unwrap();
    blazehash::commands::tally::tally_manifest(manifest.path(), "algo", &mut out).unwrap();
    drop(out);
    let text = std::fs::read_to_string(out_file.path()).unwrap();
    assert!(text.contains("sha256"), "output file should contain sha256\n{text}");
    assert!(text.contains("blake3"), "output file should contain blake3\n{text}");
}
