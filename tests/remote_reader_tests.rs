#[cfg(feature = "remote")]
mod remote_reader_tests {
    use blazehash::remote::reader::fetch_remote_text;

    #[test]
    fn test_fetch_remote_text_mem() {
        // mem:// creates a fresh in-process store per call — key won't exist, expect error
        let result = fetch_remote_text("mem://testbucket/nonexistent.hash");
        // Either an error (key not found) or empty string — both acceptable
        assert!(result.is_err() || result.unwrap().is_empty());
    }

    #[test]
    fn test_fetch_remote_text_not_found_errors() {
        let result = fetch_remote_text("s3://nonexistent-bucket-abc123/file.hash");
        // Without credentials/network this will fail — that's the expected behavior
        assert!(result.is_err());
    }

    #[test]
    fn test_fetch_remote_text_invalid_scheme_errors() {
        let result = fetch_remote_text("ftp://host/file.hash");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unsupported") || msg.contains("ftp"));
    }
}

// Always-compiled tests (no feature gate needed)
#[test]
fn test_is_remote_uri_sftp() {
    assert!(blazehash::remote::is_remote_uri("sftp://user@host/path/file.hash"));
}

#[test]
fn test_is_remote_uri_webdav() {
    assert!(blazehash::remote::is_remote_uri("webdav://files.example.com/evidence/"));
}
