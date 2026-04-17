// Tests for Google Drive support in blazehash.
//
// Unit tests run offline. Network integration tests are #[ignore] and
// require real internet access:
//   cargo test --features remote -p blazehash --test gdrive_tests -- --ignored
//
// ## Google Drive file ID formats
//
//   "0B" prefix — legacy format, pre-~2017 uploads. Longer base64-encoded IDs.
//                 Large files routed through a virus-scan confirmation redirect.
//
//   "1Y" prefix — modern format, post-~2017 uploads. Shorter opaque IDs.
//                 Served via a simpler direct-download redirect.
//
// We test one fixture of each format to exercise both download paths.
//
// Fixture A (legacy "0B"): "Reflected File Download" whitepaper (Ryan Barnett, 2014)
//   File ID : 0B0KLoHg_gR_XQnV4RVhlNl96MHM
//   Size    : 1,629,784 bytes (~1.6 MB)
//   SHA-256 : b417b7e59c9e8c78dc2c520993d4ed9d6c191508f9151fe3464db7b93bd4f575
//
// Fixture B (modern "1Y"): XML test file
//   Share URL: https://drive.google.com/file/d/1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0/view
//   File ID : 1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0
//   Size    : 9,666 bytes (~9.4 KB)
//   SHA-256 : 71162d394f9e03d7371e0f3731ec00cc22aaa3b118ddaa90ef378e94bdd866e6

// ── Unit tests (no network) ──────────────────────────────────────────────────

#[test]
fn gdrive_scheme_detected_by_is_remote_uri() {
    assert!(blazehash::remote::is_remote_uri("gdrive://1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0"));
}

#[test]
fn gdrive_legacy_0b_scheme_detected_by_is_remote_uri() {
    assert!(blazehash::remote::is_remote_uri("gdrive://0B0KLoHg_gR_XQnV4RVhlNl96MHM"));
}

#[test]
fn gdrive_scheme_detected_by_uri_scheme_detect() {
    use blazehash::remote::UriScheme;
    assert_eq!(
        UriScheme::detect("gdrive://1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0"),
        Some(UriScheme::GDrive)
    );
}

// ── parse_file_id unit tests ─────────────────────────────────────────────────

#[test]
fn parse_file_id_from_view_url_1y_format() {
    use blazehash::remote::gdrive::parse_file_id;
    let url = "https://drive.google.com/file/d/1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0/view";
    assert_eq!(
        parse_file_id(url),
        Some("1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0".to_string())
    );
}

#[test]
fn parse_file_id_from_view_url_0b_legacy_format() {
    use blazehash::remote::gdrive::parse_file_id;
    // Legacy "0B" IDs appear in /file/d/<id>/view share URLs too
    let url = "https://drive.google.com/file/d/0B0KLoHg_gR_XQnV4RVhlNl96MHM/view";
    assert_eq!(
        parse_file_id(url),
        Some("0B0KLoHg_gR_XQnV4RVhlNl96MHM".to_string())
    );
}

#[test]
fn parse_file_id_from_open_url() {
    use blazehash::remote::gdrive::parse_file_id;
    let url = "https://drive.google.com/open?id=1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0";
    assert_eq!(
        parse_file_id(url),
        Some("1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0".to_string())
    );
}

#[test]
fn parse_file_id_from_gdrive_scheme_uri() {
    use blazehash::remote::gdrive::parse_file_id;
    // gdrive://<id> — bare ID after scheme
    let uri = "gdrive://1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0";
    assert_eq!(
        parse_file_id(uri),
        Some("1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0".to_string())
    );
}

#[test]
fn parse_file_id_from_bare_id() {
    use blazehash::remote::gdrive::parse_file_id;
    // Bare ID with no scheme or URL — returned as-is
    assert_eq!(
        parse_file_id("1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0"),
        Some("1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0".to_string())
    );
}

#[test]
fn parse_file_id_returns_none_for_empty_string() {
    use blazehash::remote::gdrive::parse_file_id;
    assert_eq!(parse_file_id(""), None);
}

#[test]
fn parse_file_id_returns_none_for_unrecognised_url() {
    use blazehash::remote::gdrive::parse_file_id;
    assert_eq!(parse_file_id("https://example.com/not/a/drive/url"), None);
}

// ── Network integration tests ────────────────────────────────────────────────

#[cfg(feature = "remote")]
mod gdrive_integration {
    use blazehash::algorithm::Algorithm;
    use blazehash::remote::gdrive::hash_gdrive_file;

    // Fixture A — legacy "0B" format, ~1.6 MB PDF (exercises virus-scan bypass path)
    const FIXTURE_A_ID: &str = "0B0KLoHg_gR_XQnV4RVhlNl96MHM";
    const FIXTURE_A_SHA256: &str =
        "b417b7e59c9e8c78dc2c520993d4ed9d6c191508f9151fe3464db7b93bd4f575";
    const FIXTURE_A_SIZE: u64 = 1_629_784;

    // Fixture B — modern "1Y" format, ~9.4 KB XML (exercises direct-download path)
    const FIXTURE_B_URL: &str =
        "https://drive.google.com/file/d/1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0/view";
    const FIXTURE_B_ID: &str = "1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0";
    const FIXTURE_B_SHA256: &str =
        "71162d394f9e03d7371e0f3731ec00cc22aaa3b118ddaa90ef378e94bdd866e6";
    const FIXTURE_B_SIZE: u64 = 9_666;

    #[test]
    #[ignore = "requires network; run with: cargo test --features remote --test gdrive_tests -- --ignored"]
    fn fixture_a_0b_legacy_sha256_matches() {
        let mut out = Vec::new();
        let result = hash_gdrive_file(FIXTURE_A_ID, &[Algorithm::Sha256], &mut out)
            .expect("download should succeed for public file");
        assert_eq!(
            result.sha256.as_deref(),
            Some(FIXTURE_A_SHA256),
            "SHA-256 mismatch — file may have changed or is no longer public"
        );
    }

    #[test]
    #[ignore = "requires network; run with: cargo test --features remote --test gdrive_tests -- --ignored"]
    fn fixture_a_0b_legacy_size_matches() {
        let mut out = Vec::new();
        let result = hash_gdrive_file(FIXTURE_A_ID, &[Algorithm::Sha256], &mut out)
            .expect("download should succeed for public file");
        assert_eq!(result.bytes_read, FIXTURE_A_SIZE);
    }

    #[test]
    #[ignore = "requires network; run with: cargo test --features remote --test gdrive_tests -- --ignored"]
    fn fixture_b_1y_modern_sha256_matches() {
        let mut out = Vec::new();
        let result = hash_gdrive_file(FIXTURE_B_ID, &[Algorithm::Sha256], &mut out)
            .expect("download should succeed for public file");
        assert_eq!(
            result.sha256.as_deref(),
            Some(FIXTURE_B_SHA256),
            "SHA-256 mismatch — file may have changed or is no longer public"
        );
    }

    #[test]
    #[ignore = "requires network; run with: cargo test --features remote --test gdrive_tests -- --ignored"]
    fn fixture_b_1y_modern_size_matches() {
        let mut out = Vec::new();
        let result = hash_gdrive_file(FIXTURE_B_ID, &[Algorithm::Sha256], &mut out)
            .expect("download should succeed for public file");
        assert_eq!(result.bytes_read, FIXTURE_B_SIZE);
    }

    #[test]
    #[ignore = "requires network; run with: cargo test --features remote --test gdrive_tests -- --ignored"]
    fn fixture_b_parsed_from_share_url_matches() {
        // Verify parse_file_id + hash_gdrive_file round-trip with a full share URL
        use blazehash::remote::gdrive::parse_file_id;
        let id = parse_file_id(FIXTURE_B_URL).expect("parse share URL");
        assert_eq!(id, FIXTURE_B_ID);

        let mut out = Vec::new();
        let result =
            hash_gdrive_file(&id, &[Algorithm::Sha256], &mut out).expect("download");
        assert_eq!(result.sha256.as_deref(), Some(FIXTURE_B_SHA256));
    }

    #[test]
    #[ignore = "requires network; run with: cargo test --features remote --test gdrive_tests -- --ignored"]
    fn nonexistent_file_id_returns_error() {
        let mut out = Vec::new();
        let result = hash_gdrive_file("0Bnonexistentfileid00000", &[Algorithm::Sha256], &mut out);
        assert!(result.is_err(), "expected error for non-existent file ID");
    }
}
