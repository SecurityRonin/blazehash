use assert_cmd::Command;
use std::io::Write;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("manifest.txt");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "## case: reverse-test").unwrap();
    writeln!(f, "blake3  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  file1.txt").unwrap();
    writeln!(f, "blake3  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  file2.txt").unwrap();
    writeln!(f, "blake3  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  file3.txt").unwrap();
    path
}

#[test]
fn test_reverse_reverses_entry_order() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["reverse", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pos_file3 = stdout.find("file3.txt").expect("file3.txt not found");
    let pos_file1 = stdout.find("file1.txt").expect("file1.txt not found");
    assert!(pos_file3 < pos_file1, "file3.txt should appear before file1.txt in reversed output");
}

#[test]
fn test_reverse_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["reverse", manifest.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("## case: reverse-test"), "header should be preserved in output");
}

#[test]
fn test_reverse_double_reverse_is_identity() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);

    let temp2 = dir.path().join("reversed.txt");

    // First reverse: manifest -> temp2
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "reverse",
            manifest.to_str().unwrap(),
            "-o",
            temp2.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Second reverse: temp2 -> stdout
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["reverse", temp2.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pos_file1 = stdout.find("file1.txt").expect("file1.txt not found");
    let pos_file3 = stdout.find("file3.txt").expect("file3.txt not found");
    assert!(pos_file1 < pos_file3, "double reverse should restore original order: file1 before file3");
}

#[test]
fn test_reverse_missing_manifest_fails() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["reverse", "/nonexistent/path/to/manifest.txt"])
        .assert()
        .failure();
}

#[test]
fn test_reverse_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = make_manifest(&dir);
    let out_file = dir.path().join("out.txt");

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "reverse",
            manifest.to_str().unwrap(),
            "-o",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&out_file).unwrap();
    let pos_file3 = content.find("file3.txt").expect("file3.txt not in output file");
    let pos_file1 = content.find("file1.txt").expect("file1.txt not in output file");
    assert!(pos_file3 < pos_file1, "output file should have file3 before file1");
}
