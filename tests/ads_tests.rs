/// Tests for NTFS Alternate Data Stream enumeration and hashing.
///
/// Windows-specific tests are gated with `#[cfg(target_os = "windows")]`.
/// They run on the `windows-latest` GitHub Actions runner and will FAIL
/// until `enumerate_ads` is implemented with FindFirstStreamW/FindNextStreamW.
///
/// The non-Windows test (empty-vec contract) runs on all platforms.

#[cfg(target_os = "windows")]
mod windows {
    use assert_cmd::Command;
    use blazehash::ads::enumerate_ads;
    use blazehash::algorithm::Algorithm;
    use std::fs;
    use tempfile::TempDir;

    /// Write content into a named ADS on an existing file.
    /// Uses Rust's File::create which on Windows resolves "path:stream" via CreateFileW.
    fn write_ads(base: &std::path::Path, stream_name: &str, content: &[u8]) {
        let ads_path = format!("{}:{}", base.display(), stream_name);
        fs::write(&ads_path, content).expect("failed to write ADS");
    }

    #[test]
    fn test_enumerate_ads_finds_named_stream() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, b"main content").unwrap();
        write_ads(&file, "secret", b"hidden data");

        let streams = enumerate_ads(&file);
        assert!(
            !streams.is_empty(),
            "expected at least one ADS stream, got none"
        );
        assert!(
            streams
                .iter()
                .any(|p| p.to_string_lossy().contains("secret")),
            "expected stream named 'secret' in {streams:?}"
        );
    }

    #[test]
    fn test_enumerate_ads_skips_default_data_stream() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("noads.txt");
        fs::write(&file, b"just main content").unwrap();

        let streams = enumerate_ads(&file);
        // The unnamed default stream (::$DATA) must NOT appear in results
        assert!(
            streams.is_empty(),
            "file with no named ADS should return empty, got: {streams:?}"
        );
    }

    #[test]
    fn test_enumerate_ads_multiple_streams() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("multi.txt");
        fs::write(&file, b"main").unwrap();
        write_ads(&file, "stream1", b"data1");
        write_ads(&file, "stream2", b"data2");

        let streams = enumerate_ads(&file);
        assert_eq!(streams.len(), 2, "expected 2 ADS, got: {streams:?}");
    }

    #[test]
    fn test_ads_stream_is_hashable() {
        // hash_file must be able to open and hash a synthetic ADS path
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("hashable.txt");
        fs::write(&file, b"main").unwrap();
        write_ads(&file, "payload", b"secret payload");

        let streams = enumerate_ads(&file);
        assert!(
            !streams.is_empty(),
            "enumerate_ads returned nothing — stub not yet replaced"
        );

        let stream_path = &streams[0];
        let result = blazehash::hash::hash_file(
            stream_path,
            &[Algorithm::Blake3],
            false,
            false,
            false,
            blazehash::hash::YaraOpts::no_yara(),
        );
        assert!(
            result.is_ok(),
            "hash_file should be able to hash an ADS stream path: {result:?}"
        );
        let hr = result.unwrap();
        assert!(
            hr.hashes.contains_key(&Algorithm::Blake3),
            "missing blake3 hash for ADS"
        );
    }

    #[test]
    fn test_cli_ads_flag_hashes_streams() {
        // End-to-end: blazehash --ads should include ADS streams in manifest output
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("evidence.txt");
        fs::write(&file, b"main content").unwrap();
        write_ads(&file, "Zone.Identifier", b"[ZoneTransfer]\r\nZoneId=3\r\n");

        let output = Command::cargo_bin("blazehash")
            .unwrap()
            .arg("--ads")
            .arg(file.to_str().unwrap())
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Zone.Identifier"),
            "manifest should contain ADS stream name, got:\n{stdout}"
        );
    }
}

/// Non-Windows contract: enumerate_ads must always return empty on non-Windows.
#[cfg(not(target_os = "windows"))]
#[test]
fn test_enumerate_ads_noop_on_non_windows() {
    use blazehash::ads::enumerate_ads;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"content").unwrap();

    let streams = enumerate_ads(&file);
    assert!(streams.is_empty(), "non-Windows must always return empty");
}
