use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn cli_version() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("blazehash"));
}

#[test]
fn cli_hash_single_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("HASHDEEP-1.0"))
        .stdout(predicate::str::contains("blake3"))
        .stdout(predicate::str::contains("test.txt"));
}

#[test]
fn cli_hash_directory_recursive() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("b.txt"), b"bbb").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("a.txt"))
        .stdout(predicate::str::contains("b.txt"));
}

#[test]
fn cli_multiple_algorithms() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-c")
        .arg("blake3,sha256")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("size,blake3,sha256,filename"));
}

#[test]
fn cli_output_to_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();
    let output = dir.path().join("output.hash");

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-o")
        .arg(output.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&output).unwrap();
    assert!(contents.contains("HASHDEEP-1.0"));
    assert!(contents.contains("test.txt"));
}

#[test]
fn cli_size_only_mode() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-s")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("11"));
}
