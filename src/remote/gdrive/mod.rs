pub mod auth;

/// Google Drive support: file ID parsing and public-file download+hash.
///
/// ## File ID formats
///
///   "0B" prefix — legacy format (pre-~2017). Longer base64-encoded IDs.
///                 Large files require a virus-scan confirmation bypass redirect.
///
///   "1Y" prefix — modern format (post-~2017). Shorter opaque IDs.
///                 Served via a simpler direct-download redirect.
///
/// ## Auth
///
/// Public share links require no credentials. For private files, set
/// `GOOGLE_APPLICATION_CREDENTIALS` to a service account JSON key path.
/// Authenticated access uses the `services-gdrive` opendal backend.
// Only the download+hash paths below (gated on `remote`) write to a sink;
// without the feature this import would be unused.
#[cfg(feature = "remote")]
use std::io::Write;

/// Result of a Google Drive download+hash operation.
#[derive(Debug)]
pub struct GDriveHashResult {
    /// File ID that was downloaded.
    pub file_id: String,
    /// Total bytes read from the response body.
    pub bytes_read: u64,
    /// SHA-256 hex digest, present when SHA-256 was requested.
    pub sha256: Option<String>,
    /// BLAKE3 hex digest, present when BLAKE3 was requested.
    pub blake3: Option<String>,
}

/// Extract a Google Drive file ID from a URL or URI in any of the supported formats:
///
/// - `https://drive.google.com/file/d/<id>/view`
/// - `https://drive.google.com/file/d/<id>/edit`
/// - `https://drive.google.com/open?id=<id>`
/// - `gdrive://<id>` — blazehash URI scheme
/// - Bare ID (no slashes, no `://`) — returned as-is
///
/// Returns `None` for empty strings or unrecognised URLs.
pub fn parse_file_id(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    // gdrive://<id>
    if let Some(id) = input.strip_prefix("gdrive://") {
        let id = id.trim_end_matches('/');
        return if id.is_empty() {
            None
        } else {
            Some(id.to_string())
        };
    }

    // https://drive.google.com/file/d/<id>/view  (or /edit, or bare)
    if let Some(rest) = input
        .strip_prefix("https://drive.google.com/file/d/")
        .or_else(|| input.strip_prefix("http://drive.google.com/file/d/"))
    {
        let id = rest.split('/').next().unwrap_or("").trim();
        return if id.is_empty() {
            None
        } else {
            Some(id.to_string())
        };
    }

    // https://drive.google.com/open?id=<id>
    if input.starts_with("https://drive.google.com/open")
        || input.starts_with("http://drive.google.com/open")
    {
        if let Some(id) = input.split("id=").nth(1) {
            let id = id.split('&').next().unwrap_or("").trim();
            return if id.is_empty() {
                None
            } else {
                Some(id.to_string())
            };
        }
        return None;
    }

    // Unrecognised URL (contains :// but not a known Drive pattern)
    if input.contains("://") {
        return None;
    }

    // Bare ID — no slashes, no scheme
    if input.contains('/') {
        return None;
    }
    Some(input.to_string())
}

/// Download a Google Drive file by ID, hash it, and emit a manifest line.
///
/// Auth is resolved automatically via [`auth::resolve_auth_mode`]:
///   - `GOOGLE_APPLICATION_CREDENTIALS` set → service account (not yet supported)
///   - Cached user OAuth token → authenticated Drive API v3
///   - Otherwise → public unauthenticated download
///
/// For full control over auth mode or to inject a test base URL, use
/// [`hash_gdrive_file_with_auth`] directly.
#[cfg(feature = "remote")]
pub fn hash_gdrive_file(
    file_id: &str,
    algos: &[crate::algorithm::Algorithm],
    sink: &mut dyn Write,
) -> Result<GDriveHashResult, Box<dyn std::error::Error>> {
    let auth = auth::resolve_auth_mode();
    hash_gdrive_file_with_auth_inner(file_id, &auth, algos, sink, None)
}

/// Download and hash a Google Drive file with explicit auth mode and optional
/// base URL override (for testing against a local mock server).
///
/// ## Auth modes
///
/// - `GDriveAuthMode::Public` — unauthenticated download via usercontent.google.com
/// - `GDriveAuthMode::UserOAuth { access_token }` — Drive API v3 with Bearer token
/// - `GDriveAuthMode::ServiceAccount { .. }` — not yet implemented
///
/// ## Base URL
///
/// | Mode            | Default base URL                          |
/// |-----------------|-------------------------------------------|
/// | `Public`        | `https://drive.usercontent.google.com`    |
/// | `UserOAuth`     | `https://www.googleapis.com`              |
///
/// Pass `Some("http://127.0.0.1:<port>")` in tests to point both modes at a
/// mock server.
#[cfg(feature = "remote")]
pub fn hash_gdrive_file_with_auth(
    file_id: &str,
    auth_mode: &auth::GDriveAuthMode,
    algos: &[crate::algorithm::Algorithm],
    sink: &mut dyn Write,
) -> Result<GDriveHashResult, Box<dyn std::error::Error>> {
    hash_gdrive_file_with_auth_inner(file_id, auth_mode, algos, sink, None)
}

// Separate inner function so the public API stays clean while tests can call
// the version with an injectable base URL.
#[cfg(feature = "remote")]
#[doc(hidden)]
pub fn hash_gdrive_file_with_auth_at(
    file_id: &str,
    auth_mode: &auth::GDriveAuthMode,
    algos: &[crate::algorithm::Algorithm],
    sink: &mut dyn Write,
    api_base: Option<&str>,
) -> Result<GDriveHashResult, Box<dyn std::error::Error>> {
    hash_gdrive_file_with_auth_inner(file_id, auth_mode, algos, sink, api_base)
}

#[cfg(feature = "remote")]
fn hash_gdrive_file_with_auth_inner(
    file_id: &str,
    auth_mode: &auth::GDriveAuthMode,
    algos: &[crate::algorithm::Algorithm],
    sink: &mut dyn Write,
    api_base: Option<&str>,
) -> Result<GDriveHashResult, Box<dyn std::error::Error>> {
    use crate::algorithm::Algorithm;
    use auth::GDriveAuthMode;

    let response = match auth_mode {
        GDriveAuthMode::Public => {
            let base = api_base.unwrap_or("https://drive.usercontent.google.com");
            let url = format!("{base}/download?id={file_id}&export=download&confirm=t");
            ureq::get(&url).call()?
        }
        GDriveAuthMode::UserOAuth { access_token } => {
            let base = api_base.unwrap_or("https://www.googleapis.com");
            let url = format!("{base}/drive/v3/files/{file_id}?alt=media");
            ureq::get(&url)
                .set("Authorization", &format!("Bearer {access_token}"))
                .call()?
        }
        GDriveAuthMode::ServiceAccount { .. } => {
            return Err("service account auth is not yet implemented — \
                 run `blazehash gdrive auth login` to authenticate as a user, \
                 or set GOOGLE_APPLICATION_CREDENTIALS and use `gcloud auth print-access-token`"
                .into());
        }
    };

    if response.status() != 200 {
        return Err(format!(
            "Google Drive returned HTTP {} for file ID {file_id}",
            response.status()
        )
        .into());
    }

    let mut body = response.into_reader();
    let mut buf = [0u8; 65536];
    let mut bytes_read: u64 = 0;

    use sha2::Digest as _;
    let mut sha256_hasher: Option<sha2::Sha256> = None;
    let mut blake3_hasher: Option<blake3::Hasher> = None;

    for algo in algos {
        match algo {
            Algorithm::Sha256 => sha256_hasher = Some(sha2::Sha256::new()),
            Algorithm::Blake3 => blake3_hasher = Some(blake3::Hasher::new()),
            _ => {}
        }
    }

    loop {
        let n = std::io::Read::read(&mut body, &mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        bytes_read += n as u64;
        if let Some(h) = &mut sha256_hasher {
            sha2::Digest::update(h, chunk);
        }
        if let Some(h) = &mut blake3_hasher {
            h.update(chunk);
        }
    }

    if bytes_read == 0 {
        return Err(format!(
            "Google Drive returned empty body for file ID {file_id} — \
             file may not be public or the token may be expired"
        )
        .into());
    }

    let sha256 = sha256_hasher.map(|h| format!("{:x}", sha2::Digest::finalize(h)));
    let blake3 = blake3_hasher.map(|h| h.finalize().to_hex().to_string());

    let hash_str = sha256
        .as_deref()
        .or(blake3.as_deref())
        .unwrap_or("(no hash)");
    writeln!(sink, "{hash_str}  gdrive://{file_id}")?;

    Ok(GDriveHashResult {
        file_id: file_id.to_string(),
        bytes_read,
        sha256,
        blake3,
    })
}
