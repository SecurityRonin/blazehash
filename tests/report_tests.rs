#[cfg(feature = "report")]
mod report_tests {
    use assert_cmd::Command;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_report_generates_html_file() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("manifest.hash");
        let report = dir.path().join("report.html");
        fs::write(
            &manifest,
            "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
        )
        .unwrap();

        Command::cargo_bin("blazehash")
            .unwrap()
            .args([
                "report",
                manifest.to_str().unwrap(),
                "--examiner",
                "Jane Smith",
                "--case",
                "Case-2026-001",
                "-o",
                report.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert!(report.exists(), "report.html should be created");
        let html = fs::read_to_string(&report).unwrap();
        assert!(html.contains("<html"), "output should be valid HTML");
        assert!(html.contains("Jane Smith"), "examiner name should appear");
        assert!(html.contains("Case-2026-001"), "case number should appear");
        assert!(html.contains("/f.bin"), "manifest entry should appear");
    }

    #[test]
    fn test_report_includes_manifest_hash() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("manifest.hash");
        let report = dir.path().join("report.html");
        fs::write(
            &manifest,
            "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
        )
        .unwrap();

        Command::cargo_bin("blazehash")
            .unwrap()
            .args([
                "report",
                manifest.to_str().unwrap(),
                "--examiner",
                "X",
                "--case",
                "Y",
                "-o",
                report.to_str().unwrap(),
            ])
            .assert()
            .success();

        let html = fs::read_to_string(&report).unwrap();
        assert!(
            html.contains("manifest-sha256") || html.contains("Manifest SHA-256"),
            "report must include manifest SHA-256 fingerprint"
        );
    }
}
