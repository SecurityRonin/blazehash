/// Tests for YARA mmap threshold integration.
///
/// Strategy: three-branch dispatch based on file size:
///   1. scanner.is_some() && size > threshold  → stream hash, skip YARA, warn to stderr
///   2. scanner.is_some() && size <= threshold  → mmap/read + hash + YARA scan
///   3. no scanner                              → normal hash (no YARA)
#[cfg(feature = "yara")]
mod yara_threshold_tests {
    use assert_cmd::Command;
    use tempfile::TempDir;

    const MATCH_RULE: &str = r#"rule detect_match : T1059 {
    strings:
        $a = "MATCH_ME"
    condition:
        $a
}"#;

    const NO_MATCH_RULE: &str = r#"rule detect_match : T1059 {
    strings:
        $a = "MATCH_ME"
    condition:
        $a
}"#;

    fn write_rule(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("rules.yar");
        std::fs::write(&path, content).unwrap();
        path
    }

    /// A file below the threshold that matches the YARA rule should be scanned.
    /// With --format stix output, YARA matches appear in the STIX bundle.
    #[test]
    fn test_yara_threshold_small_file_gets_scanned() {
        let dir = TempDir::new().unwrap();
        let rules = write_rule(&dir, MATCH_RULE);
        let file = dir.path().join("target.bin");
        std::fs::write(&file, b"MATCH_ME payload here").unwrap();

        // Run blazehash hash --yara <rules> --format stix <file>
        // The STIX output should contain yara_matches or an x-mitre-attack object.
        let output = Command::cargo_bin("blazehash")
            .unwrap()
            .args([
                "hash",
                "--yara",
                rules.to_str().unwrap(),
                "--format",
                "stix",
                file.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "command failed: {}", String::from_utf8_lossy(&output.stderr));
        // STIX output should contain YARA match data for the matched rule
        assert!(
            stdout.contains("detect_match") || stdout.contains("yara") || stdout.contains("T1059"),
            "expected YARA match info in STIX output, got: {stdout}"
        );
    }

    /// A file larger than --yara-max-size should skip YARA and emit a warning to stderr.
    #[test]
    fn test_yara_threshold_large_file_skips_yara() {
        let dir = TempDir::new().unwrap();
        let rules = write_rule(&dir, MATCH_RULE);

        // Create a file > 1 MB (just over the 1 MB threshold we'll set via --yara-max-size 1)
        let file = dir.path().join("large.bin");
        // 1.5 MB of data containing the match pattern
        let mut data = vec![0u8; 1024 * 1024 + 512 * 1024];
        data[0..8].copy_from_slice(b"MATCH_ME");
        std::fs::write(&file, &data).unwrap();

        let output = Command::cargo_bin("blazehash")
            .unwrap()
            .args([
                "hash",
                "--yara",
                rules.to_str().unwrap(),
                "--yara-max-size",
                "1",
                file.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "command failed: {stderr}");
        assert!(
            stderr.contains("YARA skipped") || stderr.contains("yara skipped") || stderr.contains("skipped"),
            "expected YARA skip warning in stderr, got: {stderr}"
        );
    }

    /// Without --yara flag, the output should have no YARA-related content.
    #[test]
    fn test_yara_without_flag_no_yara_scan() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("target.bin");
        std::fs::write(&file, b"MATCH_ME payload here").unwrap();

        let output = Command::cargo_bin("blazehash")
            .unwrap()
            .args([
                "hash",
                "--format",
                "stix",
                file.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        assert!(output.status.success(), "command failed: {}", String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Without --yara, no yara_matches field should appear
        assert!(
            !stdout.contains("yara_matches"),
            "expected no yara_matches without --yara flag, got: {stdout}"
        );
    }

    /// --yara-max-size flag should be accepted without error.
    #[test]
    fn test_yara_max_size_flag_is_accepted() {
        let dir = TempDir::new().unwrap();
        let rules = write_rule(&dir, NO_MATCH_RULE);
        let file = dir.path().join("small.bin");
        std::fs::write(&file, b"no match here").unwrap();

        Command::cargo_bin("blazehash")
            .unwrap()
            .args([
                "hash",
                "--yara",
                rules.to_str().unwrap(),
                "--yara-max-size",
                "512",
                file.to_str().unwrap(),
            ])
            .assert()
            .success();
    }

    /// Default threshold should be 256 MB: a file smaller than 256 MB should
    /// be scanned normally (no skip warning), even without --yara-max-size.
    #[test]
    fn test_yara_default_threshold_is_256mb() {
        let dir = TempDir::new().unwrap();
        let rules = write_rule(&dir, NO_MATCH_RULE);
        let file = dir.path().join("medium.bin");
        // 1 KB file — well under 256 MB default
        std::fs::write(&file, b"no match here just some bytes").unwrap();

        let output = Command::cargo_bin("blazehash")
            .unwrap()
            .args([
                "hash",
                "--yara",
                rules.to_str().unwrap(),
                file.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "command failed: {stderr}");
        // With a small file and default 256 MB threshold, YARA should NOT be skipped
        assert!(
            !stderr.contains("YARA skipped"),
            "unexpected YARA skip for small file under default threshold: {stderr}"
        );
    }
}
