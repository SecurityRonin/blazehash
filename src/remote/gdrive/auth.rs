//! Google Drive OAuth2 auth flow.
//!
//! Auth priority (highest to lowest):
//!   1. Service account JSON — env GOOGLE_APPLICATION_CREDENTIALS
//!   2. Stored user OAuth token — ~/.config/blazehash/gdrive_token.json
//!   3. Public (unauthenticated) — share-link files only
//!
//! Browser flow — just run:
//!   blazehash gdrive auth login
//!
//! Embedded OAuth credentials are used by default (registered under SecurityRonin).
//! Power users can override with BLAZEHASH_GDRIVE_CLIENT_ID / BLAZEHASH_GDRIVE_CLIENT_SECRET.
//!
//! ## Why embedded credentials are safe for a desktop CLI
//!
//! Google classifies "Desktop app" OAuth clients as non-secret. The security
//! model relies on the redirect URI being localhost (only the local user can
//! receive it) and codes being short-lived, not on the client secret being
//! secret. This is the same approach used by `gh`, `gcloud`, `fly`, etc.
//! See: https://developers.google.com/identity/protocols/oauth2/native-app

/// Embedded OAuth client ID (SecurityRonin / blazehash Desktop app).
/// Users can override with BLAZEHASH_GDRIVE_CLIENT_ID env var.
pub const DEFAULT_CLIENT_ID: &str =
    "29377375716-g3p5kvq5v2vde0mb0fc7kdc534e59ljd.apps.googleusercontent.com";

/// Embedded OAuth client secret (non-sensitive for Desktop app type).
/// Users can override with BLAZEHASH_GDRIVE_CLIENT_SECRET env var.
pub const DEFAULT_CLIENT_SECRET: &str = "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";

use std::io::{BufRead, BufReader, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// How blazehash will authenticate to Google Drive for a given operation.
#[derive(Debug)]
pub enum GDriveAuthMode {
    /// No credentials — public share-link files only.
    Public,
    /// Service account JSON key file (env: GOOGLE_APPLICATION_CREDENTIALS).
    ServiceAccount { path: PathBuf },
    /// Stored user OAuth2 access token (from a previous `gdrive auth login`).
    UserOAuth { access_token: String },
}

/// OAuth2 token as returned by Google's token endpoint and stored in the cache.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

/// Build a Google OAuth2 authorization URL for the Drive readonly scope.
///
/// Direct the user to this URL to grant access. On approval, Google redirects
/// to `redirect_uri` with `?code=<auth_code>&state=<state>`.
pub fn build_oauth_auth_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    let scope = "https://www.googleapis.com/auth/drive.readonly";
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth\
         ?response_type=code\
         &client_id={client_id}\
         &redirect_uri={redirect_uri}\
         &scope={scope}\
         &state={state}\
         &access_type=offline\
         &prompt=consent"
    )
}

/// Extract the authorization code from a localhost redirect callback URL.
///
/// Parses `?code=<value>` from URLs like:
///   `http://localhost:9876/callback?code=4/0AfJohXm...&state=csrf`
///
/// Returns `None` if no `code` param is present (e.g. user denied access).
pub fn parse_auth_code_from_redirect(url: &str) -> Option<String> {
    let query = url.split('?').nth(1)?;
    for param in query.split('&') {
        if let Some(value) = param.strip_prefix("code=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Path where the user OAuth token is cached between sessions.
///
/// Returns `~/.config/blazehash/gdrive_token.json` on Unix,
/// or `%APPDATA%\blazehash\gdrive_token.json` on Windows.
pub fn token_cache_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    #[cfg(not(target_os = "windows"))]
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| PathBuf::from(".config"))
        });

    base.join("blazehash").join("gdrive_token.json")
}

/// Save an OAuth token to a specific path, creating parent directories as needed.
pub fn save_token(token: &OAuthToken, path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(token)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Load a cached OAuth token from a specific path.
pub fn load_token_from(path: &Path) -> Option<OAuthToken> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Load a cached OAuth token from the default cache path.
pub fn load_token() -> Option<OAuthToken> {
    load_token_from(&token_cache_path())
}

/// Find an available TCP port by binding to port 0 and reading the assigned port.
pub fn find_available_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Exchange an OAuth2 authorization code for an access token.
///
/// Posts to `token_endpoint` (default: `https://oauth2.googleapis.com/token`).
/// Pass a custom endpoint in tests to point at a local mock server.
pub fn exchange_code_for_token(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    token_endpoint: &str,
) -> Result<OAuthToken, Box<dyn std::error::Error>> {
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}\
         &code={code}&redirect_uri={redirect_uri}"
    );
    let response = ureq::post(token_endpoint)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body)?;

    if response.status() != 200 {
        return Err(format!(
            "token endpoint returned HTTP {}: {}",
            response.status(),
            response.into_string().unwrap_or_default()
        )
        .into());
    }

    let token: OAuthToken = response.into_json()?;
    Ok(token)
}

/// Initiate an OAuth2 browser flow to authenticate with Google Drive.
///
/// 1. Reads `BLAZEHASH_GDRIVE_CLIENT_ID` and `BLAZEHASH_GDRIVE_CLIENT_SECRET`.
/// 2. Binds a temporary localhost HTTP server on an ephemeral port.
/// 3. Prints the auth URL and attempts to open the browser automatically.
///    In SSH/headless environments the user copies the URL manually.
/// 4. Waits for the browser redirect, captures the `code=` param.
/// 5. Exchanges the code for tokens and saves them to `token_cache_path()`.
///
/// Pass `Some(token_endpoint)` to override the Google token URL (for tests).
/// Returns the access token string on success.
pub fn initiate_browser_auth(
    token_endpoint: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let client_id = std::env::var("BLAZEHASH_GDRIVE_CLIENT_ID")
        .unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());
    let client_secret = std::env::var("BLAZEHASH_GDRIVE_CLIENT_SECRET")
        .unwrap_or_else(|_| DEFAULT_CLIENT_SECRET.to_string());

    // Bind the callback server before building the URL so we know the port
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://localhost:{port}/callback");
    let state = format!("blazehash-{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs());

    let auth_url = build_oauth_auth_url(&client_id, &redirect_uri, &state);

    // Try to open the browser; fall back to printing the URL
    eprintln!("\nOpen this URL to authorise blazehash to access Google Drive:");
    eprintln!("\n  {auth_url}\n");
    let _ = std::process::Command::new("open").arg(&auth_url).status()
        .or_else(|_| std::process::Command::new("xdg-open").arg(&auth_url).status())
        .or_else(|_| std::process::Command::new("start").arg(&auth_url).status());
    eprintln!("Waiting for browser redirect...");

    // Accept one connection — the browser redirect
    let (stream, _) = listener.accept()?;
    let code = read_code_from_callback(stream)?;

    let endpoint = token_endpoint.unwrap_or("https://oauth2.googleapis.com/token");
    let token = exchange_code_for_token(&client_id, &client_secret, &code, &redirect_uri, endpoint)?;

    // Persist token and return access token
    let cache = token_cache_path();
    save_token(&token, &cache)?;
    let access_token = token.access_token.clone();
    eprintln!("Authentication successful. Token cached at {}", cache.display());
    Ok(access_token)
}

/// Read the authorization code from the browser's GET /callback?code=... request.
fn read_code_from_callback(stream: TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Request line: "GET /callback?code=XYZ&state=... HTTP/1.1"
    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or("malformed HTTP request")?;

    let full_url = format!("http://localhost{path}");
    let code = parse_auth_code_from_redirect(&full_url)
        .ok_or("no authorization code in callback URL")?;

    // Send a minimal success response so the browser tab closes cleanly
    let html = b"<html><body><h1>blazehash: authorised.</h1><p>You may close this tab.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        html.len()
    );
    (&stream).write_all(response.as_bytes())?;
    (&stream).write_all(html)?;

    Ok(code)
}

/// Determine the auth mode to use based on environment and cached credentials.
///
/// Priority:
///   1. `GOOGLE_APPLICATION_CREDENTIALS` env var pointing to a service account JSON file
///   2. Cached user OAuth token at `token_cache_path()`
///   3. `GDriveAuthMode::Public`
pub fn resolve_auth_mode() -> GDriveAuthMode {
    // 1. Service account
    if let Ok(path) = std::env::var("GOOGLE_APPLICATION_CREDENTIALS") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return GDriveAuthMode::ServiceAccount { path: p };
        }
    }

    // 2. Cached user token
    if let Some(token) = load_token() {
        return GDriveAuthMode::UserOAuth {
            access_token: token.access_token,
        };
    }

    // 3. Public fallback
    GDriveAuthMode::Public
}
