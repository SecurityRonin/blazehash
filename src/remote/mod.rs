#[cfg(feature = "remote")]
pub mod writer;
#[cfg(feature = "remote")]
pub mod reader;
#[cfg(feature = "remote")]
pub mod operator;
#[cfg(feature = "remote")]
pub mod walk;

/// Returns true if the string has a known remote URI scheme.
pub fn is_remote_uri(s: &str) -> bool {
    let s = s.trim();
    matches!(
        s.split_once("://").map(|(scheme, _)| scheme),
        Some("s3" | "gcs" | "azblob" | "sftp" | "webdav" | "hdfs"
            | "http" | "https" | "mem" | "file")
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum UriScheme {
    S3,
    Gcs,
    AzBlob,
    Sftp,
    WebDav,
    Hdfs,
    Http,
    Https,
    Mem,
    File,
}

impl UriScheme {
    pub fn detect(uri: &str) -> Option<Self> {
        let scheme = uri.split_once("://")?.0;
        match scheme {
            "s3"     => Some(Self::S3),
            "gcs"    => Some(Self::Gcs),
            "azblob" => Some(Self::AzBlob),
            "sftp"   => Some(Self::Sftp),
            "webdav" => Some(Self::WebDav),
            "hdfs"   => Some(Self::Hdfs),
            "http"   => Some(Self::Http),
            "https"  => Some(Self::Https),
            "mem"    => Some(Self::Mem),
            "file"   => Some(Self::File),
            _        => None,
        }
    }
}
