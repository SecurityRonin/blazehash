use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_merge_two_non_overlapping_manifests() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.hash");
    let b = dir.path().join("b.hash");
    let out = dir.path().join("merged.hash");

    fs::write(
        &a,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,aaa,/a.bin\n",
    )
    .unwrap();
    fs::write(
        &b,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n6,bbb,/b.bin\n",
    )
    .unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "merge",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let merged = fs::read_to_string(&out).unwrap();
    assert!(merged.contains("/a.bin"), "merged should contain /a.bin");
    assert!(merged.contains("/b.bin"), "merged should contain /b.bin");
}

#[test]
fn test_merge_last_write_wins_on_duplicate_path() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.hash");
    let b = dir.path().join("b.hash");
    let out = dir.path().join("merged.hash");

    fs::write(
        &a,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,oldold,/dup.bin\n",
    )
    .unwrap();
    fs::write(
        &b,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,newnew,/dup.bin\n",
    )
    .unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "merge",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let merged = fs::read_to_string(&out).unwrap();
    assert!(merged.contains("newnew"), "last manifest's hash should win");
    assert!(
        !merged.contains("oldold"),
        "earlier hash should be overwritten"
    );
}

#[test]
fn test_merge_requires_at_least_two_inputs_and_output() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.hash");
    fs::write(
        &a,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,aaa,/a.bin\n",
    )
    .unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["merge", a.to_str().unwrap()])
        .assert()
        .failure();
}
