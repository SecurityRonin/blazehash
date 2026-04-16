use blazehash::remote::{is_remote_uri, UriScheme};

#[test]
fn test_s3_uri_detected() {
    assert!(is_remote_uri("s3://bucket/key"));
}

#[test]
fn test_gcs_uri_detected() {
    assert!(is_remote_uri("gcs://bucket/key"));
}

#[test]
fn test_local_path_not_remote() {
    assert!(!is_remote_uri("/tmp/manifest.hash"));
    assert!(!is_remote_uri("relative/path.hash"));
    assert!(!is_remote_uri("manifest.hash"));
}

#[test]
fn test_scheme_detect_azblob() {
    assert_eq!(UriScheme::detect("azblob://container/blob"), Some(UriScheme::AzBlob));
}

#[test]
fn test_scheme_detect_unknown_returns_none() {
    assert_eq!(UriScheme::detect("ftp://host/path"), None);
}
