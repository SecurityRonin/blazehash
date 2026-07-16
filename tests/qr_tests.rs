#[cfg(feature = "qr")]
mod qr_tests {
    use blazehash::qr_label::{build_qr_content, generate_qr_png};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_manifest(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_build_qr_content_minimal() {
        let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc,/foo\n");
        let content = build_qr_content(manifest.path(), None, None).unwrap();
        assert!(
            content.starts_with("BLAZEHASH:sha256="),
            "must start with BLAZEHASH:sha256="
        );
        assert!(
            content.len() < 300,
            "minimal content must fit in QR: len={}",
            content.len()
        );
    }

    #[test]
    fn test_build_qr_content_with_case() {
        let manifest = write_temp_manifest("%%blazehash-1.0\n## case: CASE-2026-001\n## examiner: Jane Smith\nsha256,path\nabc,/foo\n");
        let content = build_qr_content(manifest.path(), None, None).unwrap();
        assert!(
            content.contains("case=CASE-2026-001"),
            "must include case id: {content}"
        );
        assert!(
            content.contains("examiner=Jane+Smith")
                || content.contains("examiner=Jane%20Smith")
                || content.contains("examiner=Jane Smith"),
            "must include examiner: {content}"
        );
    }

    #[test]
    fn test_generate_qr_png_creates_file() {
        let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc,/foo\n");
        let out_dir = tempfile::tempdir().unwrap();
        let out_path = out_dir.path().join("label.png");
        generate_qr_png(manifest.path(), &out_path, None).unwrap();
        assert!(out_path.exists(), "PNG file must be created");
        // Check it's actually a PNG (magic bytes)
        let bytes = std::fs::read(&out_path).unwrap();
        assert_eq!(
            &bytes[..8],
            b"\x89PNG\r\n\x1a\n",
            "output must be valid PNG"
        );
    }

    #[test]
    fn test_generate_qr_png_with_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("evidence.hash");
        std::fs::write(&manifest_path, "%%blazehash-1.0\nsha256,path\nabc,/foo\n").unwrap();
        // Write a fake .pub file (64 hex chars = 32 bytes = Ed25519 pubkey)
        let pub_path = dir.path().join("evidence.hash.pub");
        let fake_pubkey = "a3f8e2c1d4b7".repeat(5) + "a3f8e2"; // 64 hex chars
        std::fs::write(&pub_path, &fake_pubkey).unwrap();

        let out_path = dir.path().join("label.png");
        generate_qr_png(&manifest_path, &out_path, None).unwrap();
        assert!(out_path.exists(), "PNG must be created with pubkey");
    }
}

#[cfg(feature = "qr")]
mod qr_cli_tests {
    use assert_cmd::Command;
    use tempfile::tempdir;

    #[test]
    fn test_cli_qr_creates_png() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("evidence.hash");
        std::fs::write(&manifest, "%%blazehash-1.0\nsha256,path\nabc,/foo\n").unwrap();
        let out = dir.path().join("label.png");

        Command::cargo_bin("blazehash")
            .unwrap()
            .arg("qr")
            .arg(&manifest)
            .arg("-o")
            .arg(&out)
            .assert()
            .success();

        assert!(out.exists(), "PNG must be created by CLI");
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "must be valid PNG");
    }
}

#[cfg(feature = "qr")]
mod qr_text_tests {
    use blazehash::qr_label::generate_qr_text;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_manifest(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_generate_qr_text_is_non_empty() {
        let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc,/foo\n");
        let text = generate_qr_text(manifest.path(), None).unwrap();
        assert!(!text.is_empty(), "text QR must be non-empty");
        assert!(
            text.contains('\u{2584}') || text.contains('\u{2580}') || text.contains('\u{2588}'),
            "text QR must contain Unicode block chars"
        );
    }

    #[test]
    fn test_generate_qr_text_has_multiple_lines() {
        let manifest = write_temp_manifest("%%blazehash-1.0\nsha256,path\nabc,/foo\n");
        let text = generate_qr_text(manifest.path(), None).unwrap();
        assert!(text.lines().count() > 5, "QR code must span multiple lines");
    }

    #[test]
    fn test_cli_qr_text_stdout_no_output_flag() {
        use assert_cmd::Command;
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("evidence.hash");
        std::fs::write(&manifest, "%%blazehash-1.0\nsha256,path\nabc,/foo\n").unwrap();

        let out = Command::cargo_bin("blazehash")
            .unwrap()
            .arg("qr")
            .arg(&manifest)
            .assert()
            .success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        assert!(
            stdout.contains('\u{2584}')
                || stdout.contains('\u{2580}')
                || stdout.contains('\u{2588}'),
            "no -o flag: stdout must contain Unicode QR"
        );
    }
}
