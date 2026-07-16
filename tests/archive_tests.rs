use assert_cmd::Command;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

fn create_zip(dir: &TempDir) -> std::path::PathBuf {
    let zip_path = dir.path().join("evidence.zip");
    let file = fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("docs/contract.pdf", options).unwrap();
    zip.write_all(b"fake pdf content").unwrap();
    zip.start_file("images/photo.jpg", options).unwrap();
    zip.write_all(b"fake jpg content").unwrap();
    zip.finish().unwrap();
    zip_path
}

#[test]
fn test_archive_zip_lists_entries() {
    let dir = TempDir::new().unwrap();
    let zip_path = create_zip(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["archive", zip_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "archive command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("contract.pdf"),
        "expected contract.pdf in output"
    );
    assert!(stdout.contains("photo.jpg"), "expected photo.jpg in output");
}

#[test]
fn test_archive_zip_produces_hashes() {
    let dir = TempDir::new().unwrap();
    let zip_path = create_zip(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["archive", zip_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let has_hash = stdout
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('%') && !l.is_empty())
        .any(|l| {
            l.split_whitespace()
                .any(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
        });
    assert!(
        has_hash,
        "expected blake3 hashes in archive output:\n{stdout}"
    );
}

#[test]
fn test_archive_zip_deterministic() {
    let dir = TempDir::new().unwrap();
    let zip_path = create_zip(&dir);
    let out1 = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["archive", zip_path.to_str().unwrap()])
        .output()
        .unwrap()
        .stdout;
    let out2 = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["archive", zip_path.to_str().unwrap()])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(out1, out2, "archive output must be deterministic");
}

#[test]
fn test_archive_unsupported_format_fails() {
    let dir = TempDir::new().unwrap();
    let bad = dir.path().join("notanarchive.xyz");
    fs::write(&bad, b"not an archive").unwrap();
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["archive", bad.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn test_archive_output_to_file() {
    let dir = TempDir::new().unwrap();
    let zip_path = create_zip(&dir);
    let out_path = dir.path().join("archive.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "archive",
            zip_path.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("contract.pdf"));
}
