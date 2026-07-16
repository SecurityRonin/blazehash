use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest_a(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("a.hash");
    fs::write(&p, concat!(
        "## manifest: A\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  shared.txt\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  only_in_a.txt\n",
        "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  also_shared.pdf\n",
    )).unwrap();
    p
}

fn write_manifest_b(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("b.hash");
    fs::write(&p, concat!(
        "## manifest: B\n",
        "sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  shared.txt\n",
        "sha256  eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  only_in_b.txt\n",
        "sha256  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  also_shared.pdf\n",
    )).unwrap();
    p
}

#[test]
fn test_subtract_returns_a_minus_b() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["subtract", a.to_str().unwrap(), b.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("only_in_a.txt"), "a-only path must appear");
    assert!(
        !stdout.contains("shared.txt"),
        "shared path must be subtracted"
    );
    assert!(
        !stdout.contains("also_shared.pdf"),
        "also-shared must be subtracted"
    );
    assert!(
        !stdout.contains("only_in_b.txt"),
        "b-only path must never appear"
    );
}

#[test]
fn test_subtract_empty_result_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.hash");
    let b = dir.path().join("b.hash");
    fs::write(&a, "sha256  aaaa  shared.txt\n").unwrap();
    fs::write(
        &b,
        concat!("sha256  aaaa  shared.txt\n", "sha256  bbbb  extra.txt\n"),
    )
    .unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["subtract", a.to_str().unwrap(), b.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "empty result must exit nonzero");
}

#[test]
fn test_subtract_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["subtract", a.to_str().unwrap(), b.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("## manifest: A"),
        "headers from A must be preserved"
    );
}

#[test]
fn test_subtract_output_to_file() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out_path = dir.path().join("diff.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "subtract",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("only_in_a.txt"));
}

#[test]
fn test_subtract_missing_second_arg_fails() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.hash");
    fs::write(&a, "sha256  aaaa  f.txt\n").unwrap();
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["subtract", a.to_str().unwrap()])
        .assert()
        .failure();
}
