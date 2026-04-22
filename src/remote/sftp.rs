//! SFTP fetch: cross-platform via ssh2 (libssh2 vendored).
//! Supports password, SSH agent, and key-file authentication.
//! Works on Linux, macOS, and Windows — no openssh Rust crate needed.

use anyhow::{anyhow, Result};

/// Parsed components of an `sftp://` URI.
#[derive(Debug, PartialEq)]
pub struct SftpUri {
    /// Hostname (no port).
    pub host: String,
    /// Port (default 22).
    pub port: u16,
    /// Remote path.
    pub path: String,
    /// Username (`None` → system username).
    pub username: Option<String>,
    /// Password for authentication (`None` → key/agent).
    pub password: Option<String>,
}

/// Parse an `sftp://` URI into its components.
///
/// # Supported forms
/// - `sftp://host/path`
/// - `sftp://host:port/path`
/// - `sftp://user@host/path`
/// - `sftp://user:pass@host:port/path`
pub fn parse_sftp_uri(uri: &str) -> Result<SftpUri> {
    let rest = uri
        .strip_prefix("sftp://")
        .ok_or_else(|| anyhow!("expected sftp:// URI, got: {uri}"))?;

    if rest.is_empty() {
        return Err(anyhow!("sftp URI has no host: {uri}"));
    }

    let (authority, path) = rest
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((rest, "/".to_string()));

    if authority.is_empty() {
        return Err(anyhow!("sftp URI has empty host: {uri}"));
    }

    let (userinfo, hostport) = if let Some((u, h)) = authority.split_once('@') {
        (Some(u), h)
    } else {
        (None, authority)
    };

    let (host, port) = if let Some((h, p)) = hostport.split_once(':') {
        let port: u16 = p.parse().map_err(|_| anyhow!("invalid port in sftp URI: {uri}"))?;
        (h.to_string(), port)
    } else {
        (hostport.to_string(), 22u16)
    };

    if host.is_empty() {
        return Err(anyhow!("sftp URI has empty host: {uri}"));
    }

    let (username, password) = match userinfo {
        Some(ui) => {
            if let Some((u, p)) = ui.split_once(':') {
                (Some(u.to_string()), Some(p.to_string()))
            } else {
                (Some(ui.to_string()), None)
            }
        }
        None => (None, None),
    };

    Ok(SftpUri { host, port, path, username, password })
}

/// Fetch raw bytes from an `sftp://` URI using libssh2.
///
/// Authentication order:
/// 1. Password from URI (if present)
/// 2. Key file from `BLAZEHASH_SFTP_KEY_PATH` env var (passphrase from `BLAZEHASH_SFTP_KEY_PASS`)
/// 3. SSH agent
pub fn fetch_sftp_bytes(uri: &str) -> Result<Vec<u8>> {
    use ssh2::Session;
    use std::io::Read;
    use std::net::TcpStream;

    let sftp_uri = parse_sftp_uri(uri)?;
    let addr = format!("{}:{}", sftp_uri.host, sftp_uri.port);

    let tcp = TcpStream::connect(&addr)
        .map_err(|e| anyhow!("SFTP TCP connect to {addr} failed: {e}"))?;

    let mut sess = Session::new().map_err(|e| anyhow!("SSH session init failed: {e}"))?;
    sess.set_tcp_stream(tcp);
    sess.handshake().map_err(|e| anyhow!("SSH handshake with {addr} failed: {e}"))?;

    let user = sftp_uri
        .username
        .as_deref()
        .or_else(|| std::env::var("USER").ok().as_deref().map(|_| "").ok_or(()).ok())
        .unwrap_or("anonymous");

    // Try password auth first
    if let Some(ref pass) = sftp_uri.password {
        sess.userauth_password(user, pass)
            .map_err(|e| anyhow!("SFTP password auth failed: {e}"))?;
    } else if let Ok(key_path) = std::env::var("BLAZEHASH_SFTP_KEY_PATH") {
        // Key file auth
        let passphrase = std::env::var("BLAZEHASH_SFTP_KEY_PASS").ok();
        sess.userauth_pubkey_file(
            user,
            None,
            std::path::Path::new(&key_path),
            passphrase.as_deref(),
        )
        .map_err(|e| anyhow!("SFTP key auth failed ({key_path}): {e}"))?;
    } else {
        // SSH agent
        let mut agent = sess.agent().map_err(|e| anyhow!("SSH agent init failed: {e}"))?;
        agent.connect().map_err(|e| anyhow!("SSH agent connect failed: {e}"))?;
        agent.list_identities().map_err(|e| anyhow!("SSH agent list failed: {e}"))?;
        let identities = agent.identities().map_err(|e| anyhow!("SSH agent identities: {e}"))?;
        let mut authed = false;
        for identity in identities {
            if agent.userauth(user, &identity).is_ok() {
                authed = true;
                break;
            }
        }
        if !authed {
            return Err(anyhow!(
                "SFTP auth failed for {user}@{addr}: no password, key, or agent identity worked"
            ));
        }
    }

    if !sess.authenticated() {
        return Err(anyhow!("SFTP authentication failed for {addr}"));
    }

    let sftp = sess.sftp().map_err(|e| anyhow!("SFTP subsystem init failed: {e}"))?;
    let mut file = sftp
        .open(std::path::Path::new(&sftp_uri.path))
        .map_err(|e| anyhow!("SFTP open '{}' failed: {e}", sftp_uri.path))?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| anyhow!("SFTP read '{}' failed: {e}", sftp_uri.path))?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_sftp_uri() {
        let u = parse_sftp_uri("sftp://host/path/to/file").unwrap();
        assert_eq!(u.host, "host");
        assert_eq!(u.port, 22);
        assert_eq!(u.path, "/path/to/file");
        assert_eq!(u.username, None);
        assert_eq!(u.password, None);
    }

    #[test]
    fn parse_sftp_with_user() {
        let u = parse_sftp_uri("sftp://analyst@192.168.1.10/evidence/disk.dd").unwrap();
        assert_eq!(u.host, "192.168.1.10");
        assert_eq!(u.port, 22);
        assert_eq!(u.path, "/evidence/disk.dd");
        assert_eq!(u.username, Some("analyst".into()));
        assert_eq!(u.password, None);
    }

    #[test]
    fn parse_sftp_with_user_pass_and_port() {
        let u = parse_sftp_uri("sftp://admin:secret@10.0.0.1:2222/data/forensics/dump.dd").unwrap();
        assert_eq!(u.host, "10.0.0.1");
        assert_eq!(u.port, 2222);
        assert_eq!(u.path, "/data/forensics/dump.dd");
        assert_eq!(u.username, Some("admin".into()));
        assert_eq!(u.password, Some("secret".into()));
    }

    #[test]
    fn parse_sftp_nested_path() {
        let u = parse_sftp_uri("sftp://analyst@server.corp/cases/2026/image.dd").unwrap();
        assert_eq!(u.path, "/cases/2026/image.dd");
    }

    #[test]
    fn parse_sftp_custom_port() {
        let u = parse_sftp_uri("sftp://host:2222/file.bin").unwrap();
        assert_eq!(u.port, 2222);
    }

    #[test]
    fn parse_sftp_wrong_scheme_errors() {
        assert!(parse_sftp_uri("ftp://host/path").is_err());
    }

    #[test]
    fn parse_sftp_empty_host_errors() {
        assert!(parse_sftp_uri("sftp:///path").is_err());
    }

    #[test]
    fn parse_sftp_invalid_port_errors() {
        assert!(parse_sftp_uri("sftp://host:notaport/path").is_err());
    }
}
