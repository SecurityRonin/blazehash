#[cfg(feature = "forensic-image")]
mod tests {
    use assert_cmd::Command;
    use blazehash::forensic_image::{verify_image, ImageFormat, ImageVerification};
    use predicates::prelude::*;
    use std::path::Path;

    const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

    #[test]
    fn detect_ewf_format() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let format = ImageFormat::detect(Path::new(&path)).unwrap();
        assert!(matches!(format, ImageFormat::Ewf));
    }

    #[test]
    fn detect_unknown_format_for_non_image() {
        let result = ImageFormat::detect(Path::new("Cargo.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn verify_ewf_image_passes() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let result = verify_image(Path::new(&path)).unwrap();

        assert!(matches!(result.format, ImageFormat::Ewf));
        assert!(result.media_size > 0);
        assert!(result.computed_md5.is_some());
        assert!(result.md5_match == Some(true));
    }

    #[test]
    fn verify_ewf_image_returns_stored_hashes() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let result = verify_image(Path::new(&path)).unwrap();

        assert!(result.stored_md5.is_some());
        // Verify hash strings are valid hex
        let md5 = result.stored_md5.as_ref().unwrap();
        assert_eq!(md5.len(), 32); // 16 bytes = 32 hex chars
        assert!(md5.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_ewf_image_returns_metadata() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let result = verify_image(Path::new(&path)).unwrap();

        // nps-2010-emails has acquisition software metadata
        assert!(result.metadata.is_some());
    }

    #[test]
    fn verify_nonexistent_file_returns_error() {
        let result = verify_image(Path::new("/nonexistent/image.E01"));
        assert!(result.is_err());
    }

    #[test]
    fn image_verification_display_shows_pass() {
        let v = ImageVerification {
            format: ImageFormat::Ewf,
            path: "/test/image.E01".into(),
            media_size: 1024 * 1024,
            stored_md5: Some("abcdef0123456789abcdef0123456789".to_string()),
            stored_sha1: None,
            computed_md5: Some("abcdef0123456789abcdef0123456789".to_string()),
            computed_sha1: None,
            md5_match: Some(true),
            sha1_match: None,
            metadata: None,
        };
        let display = format!("{v}");
        assert!(display.contains("PASS"));
        assert!(display.contains("abcdef0123456789abcdef0123456789"));
    }

    #[test]
    fn image_verification_display_shows_fail() {
        let v = ImageVerification {
            format: ImageFormat::Ewf,
            path: "/test/image.E01".into(),
            media_size: 1024,
            stored_md5: Some("aaaa".to_string()),
            stored_sha1: None,
            computed_md5: Some("bbbb".to_string()),
            computed_sha1: None,
            md5_match: Some(false),
            sha1_match: None,
            metadata: None,
        };
        let display = format!("{v}");
        assert!(display.contains("FAIL"));
    }

    // --- CLI e2e tests ---

    #[test]
    fn cli_verify_image_e01() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        Command::cargo_bin("blazehash")
            .unwrap()
            .args(["--verify-image", &path])
            .assert()
            .success()
            .stdout(predicate::str::contains("MD5 match:     PASS"))
            .stdout(predicate::str::contains("EWF (E01)"))
            .stdout(predicate::str::contains("7dae50cec8163697415e69fd72387c01"));
    }

    #[test]
    fn cli_verify_image_nonexistent() {
        Command::cargo_bin("blazehash")
            .unwrap()
            .args(["--verify-image", "/nonexistent/image.E01"])
            .assert()
            .failure();
    }

    #[test]
    fn cli_verify_image_unsupported_format() {
        Command::cargo_bin("blazehash")
            .unwrap()
            .args(["--verify-image", "Cargo.toml"])
            .assert()
            .failure();
    }

    #[test]
    fn cli_verify_image_shows_in_help() {
        Command::cargo_bin("blazehash")
            .unwrap()
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("--verify-image"));
    }
}
