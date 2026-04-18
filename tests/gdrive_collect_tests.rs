// Tests for the `blazehash gdrive-collect <url>` CLI subcommand.
//
// Unit tests run offline (no network). Network integration test is #[ignore]
// and must be run explicitly:
//   cargo test --all-features --test gdrive_collect_tests -- --ignored

// ── Library-level parse_file_id tests (offline) ──────────────────────────────

#[test]
fn test_gdrive_collect_parses_full_url() {
    let url = "https://drive.google.com/file/d/1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0/view";
    let id = blazehash::remote::gdrive::parse_file_id(url).unwrap();
    assert_eq!(id, "1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0");
}

#[test]
fn test_gdrive_collect_parses_bare_id() {
    let id =
        blazehash::remote::gdrive::parse_file_id("1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0").unwrap();
    assert_eq!(id, "1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0");
}

#[test]
fn test_gdrive_collect_parses_gdrive_uri() {
    let id = blazehash::remote::gdrive::parse_file_id(
        "gdrive://1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0",
    )
    .unwrap();
    assert_eq!(id, "1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0");
}

// ── CLI subcommand dispatch tests ─────────────────────────────────────────────

/// Verifies that `blazehash gdrive-collect` (no URL arg) is recognised as a
/// subcommand and fails with a meaningful error — not with
/// "No such file or directory" (which would happen if it fell through to Hash).
#[test]
fn test_gdrive_collect_subcommand_exists() {
    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["gdrive-collect"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should NOT say "No such file or directory" (that's the Hash fallthrough)
    assert!(
        !stderr.contains("No such file"),
        "gdrive-collect not recognised as subcommand — stderr: {stderr}"
    );
}

/// Passing an unrecognisable string (no scheme, not a valid bare ID format
/// for Drive, e.g. contains characters Drive IDs don't have) should exit
/// non-zero.
#[test]
fn test_gdrive_collect_bad_url_exits_nonzero() {
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["gdrive-collect", "https://example.com/not-a-drive-url"])
        .assert()
        .failure();
}

// ── Network integration test (ignored by default) ────────────────────────────

#[test]
#[ignore = "requires network — run with: cargo test --all-features --test gdrive_collect_tests -- --ignored test_gdrive_collect_live"]
fn test_gdrive_collect_live() {
    let url = "https://drive.google.com/file/d/1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0/view";
    let out = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["gdrive-collect", url])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).unwrap();
    // manifest line format: "<hash>  gdrive://<id>"
    assert!(
        stdout.contains("gdrive://1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0"),
        "expected manifest line in stdout, got: {stdout}"
    );
}
