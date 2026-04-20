//! FTP/FTPS fetch: bypass OpenDAL (services-ftp has async-tls/tokio-rustls conflict).
//! Uses suppaftp's blocking API with the rustls feature directly.

use anyhow::{anyhow, Result};

/// Parsed components of an `ftp://` or `ftps://` URI.
#[derive(Debug, PartialEq)]
pub struct FtpUri {
    /// Host (no port).
    pub host: String,
    /// Port (default 21).
    pub port: u16,
    /// Path within the FTP server (e.g. `/pub/file.txt`).
    pub path: String,
    /// Username for authentication (`None` → anonymous login).
    pub username: Option<String>,
    /// Password for authentication.
    pub password: Option<String>,
    /// `true` for `ftps://` (FTPS via TLS), `false` for plain `ftp://`.
    pub is_tls: bool,
}

/// Parse an `ftp://` or `ftps://` URI into its components.
///
/// # Supported forms
/// - `ftp://host/path`
/// - `ftp://host:port/path`
/// - `ftp://user:pass@host:port/path`
/// - `ftps://host/path`
pub fn parse_ftp_uri(uri: &str) -> Result<FtpUri> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| anyhow!("invalid FTP URI (no scheme): {uri}"))?;

    let is_tls = match scheme {
        "ftp" => false,
        "ftps" => true,
        other => return Err(anyhow!("expected ftp:// or ftps://, got {other}://")),
    };

    if rest.is_empty() {
        return Err(anyhow!("FTP URI has no host: {uri}"));
    }

    // Split authority from path
    let (authority, path) = rest
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((rest, "/".to_string()));

    if authority.is_empty() {
        return Err(anyhow!("FTP URI has empty host: {uri}"));
    }

    // Split optional user:pass@host
    let (userinfo, hostport) = if let Some((u, h)) = authority.split_once('@') {
        (Some(u), h)
    } else {
        (None, authority)
    };

    // Split host:port
    let (host, port) = if let Some((h, p)) = hostport.split_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| anyhow!("invalid port in FTP URI: {uri}"))?;
        (h.to_string(), port)
    } else {
        (hostport.to_string(), 21u16)
    };

    if host.is_empty() {
        return Err(anyhow!("FTP URI has empty host: {uri}"));
    }

    // Split user:pass
    let (username, password) = if let Some(ui) = userinfo {
        if let Some((u, p)) = ui.split_once(':') {
            (Some(u.to_string()), Some(p.to_string()))
        } else {
            (Some(ui.to_string()), None)
        }
    } else {
        (None, None)
    };

    Ok(FtpUri { host, port, path, username, password, is_tls })
}

/// Fetch the raw bytes of an `ftp://` or `ftps://` URI using a blocking FTP connection.
///
/// Anonymous login is used when no credentials are present in the URI.
pub fn fetch_ftp_bytes(uri: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    use suppaftp::FtpStream;

    let ftp_uri = parse_ftp_uri(uri)?;
    let addr = format!("{}:{}", ftp_uri.host, ftp_uri.port);

    let mut stream = FtpStream::connect(&addr)
        .map_err(|e| anyhow!("FTP connect to {addr} failed: {e}"))?;

    let user = ftp_uri.username.as_deref().unwrap_or("anonymous");
    let pass = ftp_uri.password.as_deref().unwrap_or("anonymous@");

    stream
        .login(user, pass)
        .map_err(|e| anyhow!("FTP login failed: {e}"))?;

    stream
        .transfer_type(suppaftp::types::FileType::Binary)
        .map_err(|e| anyhow!("FTP TYPE I failed: {e}"))?;

    let mut cursor = stream
        .retr_as_buffer(&ftp_uri.path)
        .map_err(|e| anyhow!("FTP RETR {} failed: {e}", ftp_uri.path))?;

    let mut bytes = Vec::new();
    cursor
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow!("FTP read failed: {e}"))?;

    let _ = stream.quit();
    Ok(bytes)
}
