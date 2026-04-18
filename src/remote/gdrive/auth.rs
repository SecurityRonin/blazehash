/// Google Drive OAuth2 auth flow.
///
/// Auth priority (highest to lowest):
///   1. Service account JSON — env GOOGLE_APPLICATION_CREDENTIALS
///   2. Stored user OAuth token — ~/.config/blazehash/gdrive_token.json
///   3. Public (unauthenticated) — share-link files only
///
/// Browser flow:
///   Set BLAZEHASH_GDRIVE_CLIENT_ID + BLAZEHASH_GDRIVE_CLIENT_SECRET
///   (register at console.cloud.google.com → APIs & Services → Credentials).
///   Run `blazehash gdrive auth login` to initiate.

use std::path::PathBuf;

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

/// Load a cached OAuth token from disk, if one exists.
pub fn load_token() -> Option<OAuthToken> {
    let path = token_cache_path();
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
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
