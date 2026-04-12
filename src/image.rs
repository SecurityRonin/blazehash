use anyhow::Result;

pub fn is_oci_uri(s: &str) -> bool {
    s.starts_with("oci://")
}

pub fn strip_oci_prefix(s: &str) -> &str {
    s.trim_start_matches("oci://")
}

pub fn layer_path(image_ref: &str, index: usize, digest: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("oci://{image_ref}/layer[{index}]/{digest}"))
}

#[derive(Debug)]
pub struct ImageRef {
    pub registry: String,
    pub name: String,
    pub tag: String,
    pub digest: Option<String>,
}

/// Parse OCI image references: "registry/name:tag", "name:tag", "name@digest"
pub fn parse_image_ref(s: &str) -> Result<ImageRef> {
    let (registry, rest) = if let Some(slash) = s.find('/') {
        let prefix = &s[..slash];
        if prefix.contains('.') || prefix.contains(':') {
            (prefix.to_string(), s[slash + 1..].to_string())
        } else {
            ("index.docker.io".to_string(), s.to_string())
        }
    } else {
        ("index.docker.io".to_string(), s.to_string())
    };

    let (name_part, digest) = if let Some(at) = rest.find('@') {
        (rest[..at].to_string(), Some(rest[at + 1..].to_string()))
    } else {
        (rest.clone(), None)
    };

    let (bare_name, tag) = if let Some(colon) = name_part.rfind(':') {
        (name_part[..colon].to_string(), name_part[colon + 1..].to_string())
    } else {
        (name_part.clone(), "latest".to_string())
    };

    let name = if registry == "index.docker.io" && !bare_name.contains('/') {
        format!("library/{bare_name}")
    } else {
        bare_name
    };

    Ok(ImageRef { registry, name, tag, digest })
}
