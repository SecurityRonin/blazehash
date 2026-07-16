use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_convert_sha256sum_format() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("sums.txt");
    fs::write(
        &input,
        concat!(
            "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd  docs/a.pdf\n",
            "1122334411223344112233441122334411223344112233441122334411223344 *images/b.jpg\n",
        ),
    )
    .unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "sha256sum"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "convert failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sha256"), "output must declare sha256 algo");
    assert!(stdout.contains("docs/a.pdf"), "path must be present");
    assert!(
        stdout.contains("images/b.jpg"),
        "binary-mode asterisk path must be stripped"
    );
}

#[test]
fn test_convert_md5sum_format() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("md5s.txt");
    fs::write(&input, "aabbccddaabbccddaabbccddaabbccdd  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "md5sum"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("md5"), "output must declare md5 algo");
    assert!(stdout.contains("file.txt"));
}

#[test]
fn test_convert_hashdeep_format() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("hashdeep.txt");
    fs::write(
        &input,
        concat!(
            "%%%% HASHDEEP-1.0\n",
            "%%%% size,md5,sha256,filename\n",
            "## Invoked from: /evidence\n",
            "## $ hashdeep -r /evidence\n",
            "## \n",
            "1024,aabbccddaabbccddaabbccddaabbccdd,",
            "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd,",
            "/evidence/file.bin\n",
        ),
    )
    .unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "hashdeep"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "convert hashdeep failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("sha256") || stdout.contains("md5"),
        "must have algo"
    );
    assert!(stdout.contains("file.bin"), "path must appear");
}

#[test]
fn test_convert_sfv_format() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("sums.sfv");
    fs::write(
        &input,
        concat!(
            "; SFV created by WinCRC32\n",
            "movie.mkv DEADBEEF\n",
            "subs.srt  CAFEBABE\n",
        ),
    )
    .unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "sfv"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("crc32") || stdout.contains("CRC"),
        "sfv is CRC32"
    );
    assert!(stdout.contains("movie.mkv"));
}

#[test]
fn test_convert_output_to_file() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("sums.txt");
    fs::write(
        &input,
        "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd  a.txt\n",
    )
    .unwrap();
    let out_path = dir.path().join("converted.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "convert",
            input.to_str().unwrap(),
            "--from",
            "sha256sum",
            "-o",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("sha256"));
    assert!(content.contains("a.txt"));
}

#[test]
fn test_convert_unknown_format_fails() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("x.txt");
    fs::write(&input, "data\n").unwrap();
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "foobar"])
        .assert()
        .failure();
}
