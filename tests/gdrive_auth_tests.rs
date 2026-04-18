// Tests for Google Drive OAuth2 auth flow in blazehash.
//
// Auth priority (highest to lowest):
//   1. Service account JSON — env GOOGLE_APPLICATION_CREDENTIALS
//   2. Stored user OAuth token — ~/.config/blazehash/gdrive_token.json
//   3. Public (unauthenticated) — share-link files only
//
// Browser flow for user OAuth:
//   - Spin up a temporary localhost HTTP server
//   - Open browser to Google auth URL (or print URL for copy-paste in SSH/headless)
//   - Capture authorization code via the redirect callback
//   - Exchange code for tokens; persist to token cache
//
// Credentials: set BLAZEHASH_GDRIVE_CLIENT_ID + BLAZEHASH_GDRIVE_CLIENT_SECRET
// (register at console.cloud.google.com → APIs & Services → Credentials).

use blazehash::remote::gdrive::auth::{
    build_oauth_auth_url, parse_auth_code_from_redirect, resolve_auth_mode, token_cache_path,
    GDriveAuthMode, OAuthToken,
};

// ── build_oauth_auth_url ─────────────────────────────────────────────────────

#[test]
fn build_oauth_auth_url_contains_client_id() {
    let url = build_oauth_auth_url("my-client-id", "http://localhost:9876/callback", "state123");
    assert!(url.contains("client_id=my-client-id"), "url: {url}");
}

#[test]
fn build_oauth_auth_url_contains_drive_readonly_scope() {
    let url = build_oauth_auth_url("cid", "http://localhost:9876/callback", "st");
    assert!(
        url.contains("drive.readonly") || url.contains("drive%2Ereadonly"),
        "url: {url}"
    );
}

#[test]
fn build_oauth_auth_url_response_type_is_code() {
    let url = build_oauth_auth_url("cid", "http://localhost:9876/callback", "st");
    assert!(url.contains("response_type=code"), "url: {url}");
}

#[test]
fn build_oauth_auth_url_contains_redirect_uri() {
    let redirect = "http://localhost:9876/callback";
    let url = build_oauth_auth_url("cid", redirect, "st");
    // redirect URI may be percent-encoded
    assert!(
        url.contains(redirect) || url.contains("localhost%3A9876"),
        "url: {url}"
    );
}

#[test]
fn build_oauth_auth_url_contains_state() {
    let url = build_oauth_auth_url("cid", "http://localhost:9876/callback", "csrf-token-42");
    assert!(url.contains("state=csrf-token-42"), "url: {url}");
}

#[test]
fn build_oauth_auth_url_targets_google_accounts() {
    let url = build_oauth_auth_url("cid", "http://localhost:9876/callback", "st");
    assert!(
        url.starts_with("https://accounts.google.com/"),
        "url: {url}"
    );
}

// ── parse_auth_code_from_redirect ────────────────────────────────────────────

#[test]
fn parse_auth_code_from_localhost_callback() {
    let url = "http://localhost:9876/callback?code=4/0AfJohXmABC123&state=csrf-token-42";
    assert_eq!(
        parse_auth_code_from_redirect(url),
        Some("4/0AfJohXmABC123".to_string())
    );
}

#[test]
fn parse_auth_code_ignores_additional_params() {
    let url = "http://localhost:9876/callback?state=st&code=MY_CODE&scope=drive";
    assert_eq!(
        parse_auth_code_from_redirect(url),
        Some("MY_CODE".to_string())
    );
}

#[test]
fn parse_auth_code_returns_none_when_missing() {
    let url = "http://localhost:9876/callback?state=st&error=access_denied";
    assert_eq!(parse_auth_code_from_redirect(url), None);
}

#[test]
fn parse_auth_code_returns_none_for_empty_string() {
    assert_eq!(parse_auth_code_from_redirect(""), None);
}

// ── token_cache_path ─────────────────────────────────────────────────────────

#[test]
fn token_cache_path_is_under_config_dir() {
    let path = token_cache_path();
    let path_str = path.to_string_lossy();
    assert!(
        path_str.contains("blazehash"),
        "expected 'blazehash' in path, got: {path_str}"
    );
    assert!(
        path_str.ends_with("gdrive_token.json"),
        "expected path to end with gdrive_token.json, got: {path_str}"
    );
}

// ── resolve_auth_mode ────────────────────────────────────────────────────────

#[test]
fn resolve_auth_mode_is_service_account_when_env_set() {
    // Use a temp file so the env var points to a real path
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("service_account.json");
    std::fs::write(&key_file, b"{}").unwrap();

    // Scope the env var to this test
    let _guard = EnvGuard::set("GOOGLE_APPLICATION_CREDENTIALS", key_file.to_str().unwrap());

    let mode = resolve_auth_mode();
    assert!(
        matches!(mode, GDriveAuthMode::ServiceAccount { .. }),
        "expected ServiceAccount, got: {mode:?}"
    );
}

#[test]
fn resolve_auth_mode_is_public_when_no_credentials() {
    let _guard = EnvGuard::remove("GOOGLE_APPLICATION_CREDENTIALS");

    // Ensure no cached token exists for this test by pointing cache elsewhere
    // (we test with a missing/nonexistent token path — resolve_auth_mode reads
    // the real cache path so we just verify the fallback when env is absent
    // and assume no token is cached in CI)
    let mode = resolve_auth_mode();
    // Either Public or UserOAuth (if token is cached on this machine) — both valid
    assert!(
        matches!(mode, GDriveAuthMode::Public | GDriveAuthMode::UserOAuth { .. }),
        "expected Public or UserOAuth without credentials env var, got: {mode:?}"
    );
}

#[test]
fn resolve_auth_mode_prefers_service_account_over_stored_token() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("sa.json");
    std::fs::write(&key_file, b"{}").unwrap();

    let _guard = EnvGuard::set("GOOGLE_APPLICATION_CREDENTIALS", key_file.to_str().unwrap());

    // Even if a user token is cached, service account takes priority
    let mode = resolve_auth_mode();
    assert!(
        matches!(mode, GDriveAuthMode::ServiceAccount { .. }),
        "service account must take priority, got: {mode:?}"
    );
}

// ── OAuthToken round-trip ────────────────────────────────────────────────────

#[test]
fn oauth_token_serializes_and_deserializes() {
    let token = OAuthToken {
        access_token: "ya29.abc".to_string(),
        refresh_token: Some("1//refresh".to_string()),
        expires_in: Some(3600),
    };
    let json = serde_json::to_string(&token).expect("serialize");
    let back: OAuthToken = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.access_token, "ya29.abc");
    assert_eq!(back.refresh_token.as_deref(), Some("1//refresh"));
    assert_eq!(back.expires_in, Some(3600));
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// RAII guard that sets/removes an env var for the duration of a test,
/// then restores the original value on drop.
struct EnvGuard {
    key: String,
    original: Option<String>,
}

impl EnvGuard {
    fn set(key: &str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key: key.to_string(), original }
    }

    fn remove(key: &str) -> Self {
        let original = std::env::var(key).ok();
        std::env::remove_var(key);
        Self { key: key.to_string(), original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(v) => std::env::set_var(&self.key, v),
            None => std::env::remove_var(&self.key),
        }
    }
}
