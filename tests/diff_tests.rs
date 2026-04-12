use std::fs;
use tempfile::tempdir;

fn write_hashdeep(path: &std::path::Path, entries: &[(&str, &str)]) {
    use std::io::Write;
    let mut f = fs::File::create(path).unwrap();
    writeln!(f, "%%%% HASHDEEP-1.0").unwrap();
    writeln!(f, "%%%% size,blake3,filename").unwrap();
    writeln!(f, "##").unwrap();
    for (hash, name) in entries {
        writeln!(f, "5,{hash},{name}").unwrap();
    }
}

#[test]
fn test_diff_detects_added_file() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("aaaa", "/file1.bin"), ("bbbb", "/file2.bin")]);

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("ADDED") || stdout.contains("[+]"),
        "expected ADDED: {stdout}"
    );
}

#[test]
fn test_diff_detects_removed_file() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin"), ("bbbb", "/file2.bin")]);
    write_hashdeep(&after, &[("aaaa", "/file1.bin")]);

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("REMOVED") || stdout.contains("[-]"),
        "expected REMOVED: {stdout}"
    );
}

#[test]
fn test_diff_detects_modified_file() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("zzzz", "/file1.bin")]);

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("MODIFIED") || stdout.contains("[!]"),
        "expected MODIFIED: {stdout}"
    );
}

#[test]
fn test_diff_exits_zero_when_identical() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("aaaa", "/file1.bin")]);

    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .assert()
        .code(0);
}

#[test]
fn test_diff_exits_one_when_differences() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("bbbb", "/file1.bin")]);

    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .assert()
        .code(1);
}

#[test]
fn test_diff_patch_format_shows_unified_diff() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("aaaa", "/file1.bin"), ("bbbb", "/file2.bin")]);

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "diff",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--patch",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("--- ") && stdout.contains("+++ "),
        "patch output must have unified diff headers, got:\n{stdout}"
    );
    assert!(
        stdout.contains("+5,bbbb,/file2.bin") || stdout.contains("+4,bbbb,/file2.bin"),
        "added entries must be prefixed with +, got:\n{stdout}"
    );
}

#[test]
fn test_diff_patch_format_shows_removed() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin"), ("bbbb", "/file2.bin")]);
    write_hashdeep(&after, &[("aaaa", "/file1.bin")]);

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "diff",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--patch",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("-5,bbbb,/file2.bin") || stdout.contains("-4,bbbb,/file2.bin"),
        "removed entries must be prefixed with -, got:\n{stdout}"
    );
}

#[test]
fn test_diff_patch_format_shows_modified() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("zzzz", "/file1.bin")]);

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "diff",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--patch",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("-")
            && stdout.contains("aaaa")
            && stdout.contains("+")
            && stdout.contains("zzzz"),
        "modified entries must show old (-) and new (+), got:\n{stdout}"
    );
}
