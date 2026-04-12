#[cfg(feature = "docker")]
mod image_tests {
    use blazehash::image::parse_image_ref;

    #[test]
    fn test_parse_image_ref_with_tag() {
        let r = parse_image_ref("nginx:latest").unwrap();
        assert_eq!(r.name, "library/nginx");
        assert_eq!(r.tag, "latest");
        assert_eq!(r.registry, "index.docker.io");
    }

    #[test]
    fn test_parse_image_ref_with_digest() {
        let r = parse_image_ref("alpine@sha256:abc123").unwrap();
        assert_eq!(r.name, "library/alpine");
        assert_eq!(r.digest, Some("sha256:abc123".to_string()));
    }

    #[test]
    fn test_parse_image_ref_custom_registry() {
        let r = parse_image_ref("ghcr.io/org/repo:v1.0").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.name, "org/repo");
        assert_eq!(r.tag, "v1.0");
    }

    #[test]
    fn test_parse_image_ref_implicit_latest() {
        let r = parse_image_ref("ubuntu").unwrap();
        assert_eq!(r.tag, "latest");
    }
}
