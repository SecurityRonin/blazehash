// Tests for oci:// URI as a hash pipeline source.
// These test the pure parsing/detection logic without network calls.

#[cfg(feature = "docker")]
mod oci_source_tests {
    #[test]
    fn test_oci_uri_detected() {
        assert!(blazehash::image::is_oci_uri("oci://nginx:latest"));
        assert!(blazehash::image::is_oci_uri("oci://ghcr.io/org/repo:v1"));
        assert!(!blazehash::image::is_oci_uri("/path/to/file"));
        assert!(!blazehash::image::is_oci_uri("https://example.com"));
    }

    #[test]
    fn test_oci_uri_strip_prefix() {
        let ref_str = blazehash::image::strip_oci_prefix("oci://nginx:latest");
        assert_eq!(ref_str, "nginx:latest");
    }

    #[test]
    fn test_oci_layer_path() {
        // The synthetic path used in the manifest for a layer
        let path = blazehash::image::layer_path("nginx:latest", 0, "sha256:abc123");
        assert_eq!(
            path.to_string_lossy(),
            "oci://nginx:latest/layer[0]/sha256:abc123"
        );
    }
}
