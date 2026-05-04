// Integration tests asserting the forensicnomicon integration is removed.
// These FAIL before the removal (--nomicon is a valid flag) and PASS after.

use assert_cmd::Command;

/// After removal, `--nomicon` must be an unknown flag (exit non-zero).
#[test]
fn nomicon_flag_is_removed() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--nomicon", "/tmp"])
        .assert()
        .failure();
}

/// After removal, `--catalog-yara` must also be gone.
#[test]
fn catalog_yara_flag_is_removed() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--catalog-yara", "/tmp"])
        .assert()
        .failure();
}
