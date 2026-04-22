// Tests for blazehash Google Drive file hashing (URI-based interface).
//
// Usage:
//   blazehash gdrive://<file-id>
//   blazehash https://drive.google.com/file/d/<id>/view
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

// ── CLI URI dispatch tests ────────────────────────────────────────────────────

/// Verifies that `blazehash gdrive://` (no file ID) is recognised as a
/// gdrive URI and fails with a meaningful error — not silently with
/// "No such file or directory" (hash-mode fallthrough).
#[test]
fn test_gdrive_scheme_is_recognised() {
    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["gdrive://"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "gdrive:// with empty ID should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("No such file"),
        "gdrive:// fell through to hash mode — stderr: {stderr}"
    );
}

/// An empty gdrive:// URI (no file ID) must exit non-zero.
#[test]
fn test_gdrive_empty_id_exits_nonzero() {
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["gdrive://"])
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
        .args([url])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).unwrap();
    assert!(
        stdout.contains("gdrive://1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0"),
        "expected manifest line in stdout, got: {stdout}"
    );
}
