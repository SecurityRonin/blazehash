use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_update_appends_new_file() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    let existing = dir.path().join("existing.bin");
    let new_file = dir.path().join("new.bin");

    fs::write(&existing, b"hello").unwrap();
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-o", manifest.to_str().unwrap(), existing.to_str().unwrap()])
        .assert()
        .success();

    fs::write(&new_file, b"world").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "update",
            manifest.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(&manifest).unwrap();
    assert!(contents.contains("new.bin"), "update should append new.bin");
    assert!(
        contents.contains("existing.bin"),
        "update should keep existing.bin"
    );
}

#[test]
fn test_update_removes_deleted_file() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    let f1 = dir.path().join("f1.bin");
    let f2 = dir.path().join("f2.bin");

    fs::write(&f1, b"aaa").unwrap();
    fs::write(&f2, b"bbb").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "-r",
            "-o",
            manifest.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    fs::remove_file(&f2).unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "update",
            manifest.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(&manifest).unwrap();
    assert!(
        !contents.contains("f2.bin"),
        "deleted file should be removed from manifest"
    );
}

#[test]
fn test_update_rehashes_changed_file() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    let f = dir.path().join("data.bin");

    fs::write(&f, b"original").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-o", manifest.to_str().unwrap(), f.to_str().unwrap()])
        .assert()
        .success();

    let before = fs::read_to_string(&manifest).unwrap();

    fs::write(&f, b"changed content here").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "update",
            manifest.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let after = fs::read_to_string(&manifest).unwrap();
    assert_ne!(
        before, after,
        "manifest should change after file content change"
    );
    assert!(
        after.contains("20,") || after.contains(",20,") || after.contains(" 20 "),
        "updated manifest should reflect new size"
    );
}
