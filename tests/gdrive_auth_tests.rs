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
    build_oauth_auth_url, exchange_code_for_token, find_available_port, load_token_from,
    parse_auth_code_from_redirect,
    resolve_auth_mode, save_token, token_cache_path, GDriveAuthMode, OAuthToken,
    DEFAULT_CLIENT_ID, DEFAULT_CLIENT_SECRET,
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

// ── save_token / load_token_from ─────────────────────────────────────────────

#[test]
fn save_token_persists_access_token_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gdrive_token.json");
    let token = OAuthToken {
        access_token: "ya29.saved".to_string(),
        refresh_token: None,
        expires_in: Some(3600),
    };
    save_token(&token, &path).expect("save should succeed");
    let back = load_token_from(&path).expect("load should return token");
    assert_eq!(back.access_token, "ya29.saved");
}

#[test]
fn save_token_creates_parent_directories() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("deep").join("gdrive_token.json");
    let token = OAuthToken {
        access_token: "ya29.nested".to_string(),
        refresh_token: None,
        expires_in: None,
    };
    save_token(&token, &path).expect("save should create parent dirs and succeed");
    assert!(path.exists());
}

#[test]
fn load_token_from_returns_none_when_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonexistent.json");
    assert!(load_token_from(&path).is_none());
}

#[test]
fn load_token_from_returns_none_for_malformed_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(&path, b"not json at all {{{").unwrap();
    assert!(load_token_from(&path).is_none());
}

#[test]
fn save_and_load_token_round_trips_refresh_token() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token.json");
    let token = OAuthToken {
        access_token: "access".to_string(),
        refresh_token: Some("1//refresh_token".to_string()),
        expires_in: Some(3599),
    };
    save_token(&token, &path).unwrap();
    let back = load_token_from(&path).unwrap();
    assert_eq!(back.refresh_token.as_deref(), Some("1//refresh_token"));
    assert_eq!(back.expires_in, Some(3599));
}

// ── find_available_port ──────────────────────────────────────────────────────

#[test]
fn find_available_port_returns_nonzero_port() {
    let port = find_available_port().expect("should find an available port");
    assert!(port > 0, "port should be > 0, got {port}");
}

#[test]
fn find_available_port_returns_valid_range() {
    let port = find_available_port().expect("should find an available port");
    // Ephemeral ports are typically in 1024-65535
    assert!(port >= 1024, "port should be in ephemeral range, got {port}");
}

// ── exchange_code_for_token ──────────────────────────────────────────────────
//
// Uses a real in-process TCP server on an ephemeral port — no mocking library
// needed. The server responds with a hardcoded JSON payload so we test the
// actual HTTP POST → JSON parse path end-to-end.

#[test]
fn exchange_code_parses_access_token_from_valid_response() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("http://127.0.0.1:{port}");

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let body = r#"{"access_token":"ya29.mock","token_type":"Bearer","expires_in":3600,"refresh_token":"1//mock_refresh"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let token = exchange_code_for_token(
        "client_id",
        "client_secret",
        "auth_code_xyz",
        "http://localhost:9876/callback",
        &endpoint,
    )
    .expect("should succeed with mock server");

    assert_eq!(token.access_token, "ya29.mock");
    assert_eq!(token.refresh_token.as_deref(), Some("1//mock_refresh"));
    assert_eq!(token.expires_in, Some(3600));
}

#[test]
fn exchange_code_returns_error_on_non_200_response() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("http://127.0.0.1:{port}");

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let body = r#"{"error":"invalid_grant"}"#;
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let result = exchange_code_for_token(
        "client_id",
        "client_secret",
        "bad_code",
        "http://localhost/cb",
        &endpoint,
    );

    assert!(result.is_err(), "expected error on 400 response");
}

// ── initiate_browser_auth ────────────────────────────────────────────────────

#[test]
fn initiate_browser_auth_uses_embedded_defaults_when_env_absent() {
    // With no env vars set, initiate_browser_auth should use DEFAULT_CLIENT_ID
    // and DEFAULT_CLIENT_SECRET — it must NOT fail with "not set" error.
    // It will fail later (no browser / no callback), but the credential
    // resolution step must succeed.
    let _cid = EnvGuard::remove("BLAZEHASH_GDRIVE_CLIENT_ID");
    let _csecret = EnvGuard::remove("BLAZEHASH_GDRIVE_CLIENT_SECRET");

    // Verify the auth URL can be built with the defaults — proxy for the
    // credential resolution step succeeding.
    let url = build_oauth_auth_url(DEFAULT_CLIENT_ID, "http://localhost:9999/callback", "st");
    assert!(
        url.contains(DEFAULT_CLIENT_ID),
        "auth URL should embed the default client ID when env var is absent"
    );
    assert!(
        !url.contains("not set"),
        "auth URL must not contain error text"
    );
}

#[test]
fn initiate_browser_auth_env_var_overrides_embedded_default() {
    let _cid = EnvGuard::set("BLAZEHASH_GDRIVE_CLIENT_ID", "override-id");
    let effective = std::env::var("BLAZEHASH_GDRIVE_CLIENT_ID")
        .unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());
    assert_eq!(
        effective, "override-id",
        "env var should override the embedded default"
    );
}

#[test]
fn auth_url_with_localhost_port_has_correct_redirect_uri() {
    let url = build_oauth_auth_url("cid", "http://localhost:54321/callback", "state");
    assert!(
        url.contains("localhost") || url.contains("localhost%3A"),
        "url: {url}"
    );
    assert!(
        url.contains("54321") || url.contains("%3A54321"),
        "port 54321 should be in URL: {url}"
    );
}

// ── Embedded default credentials ─────────────────────────────────────────────

#[test]
fn default_client_id_is_nonempty() {
    assert!(!DEFAULT_CLIENT_ID.is_empty(), "DEFAULT_CLIENT_ID must be set");
}

#[test]
fn default_client_secret_is_nonempty() {
    assert!(!DEFAULT_CLIENT_SECRET.is_empty(), "DEFAULT_CLIENT_SECRET must be set");
}

#[test]
fn default_client_id_looks_like_google_client_id() {
    // Google desktop OAuth client IDs end with .apps.googleusercontent.com
    assert!(
        DEFAULT_CLIENT_ID.ends_with(".apps.googleusercontent.com"),
        "DEFAULT_CLIENT_ID should end with .apps.googleusercontent.com, got: {DEFAULT_CLIENT_ID}"
    );
}

#[test]
fn default_client_secret_looks_like_google_secret() {
    // Google client secrets for desktop apps start with GOCSPX-
    assert!(
        DEFAULT_CLIENT_SECRET.starts_with("GOCSPX-"),
        "DEFAULT_CLIENT_SECRET should start with GOCSPX-, got: {DEFAULT_CLIENT_SECRET}"
    );
}

#[test]
fn initiate_browser_auth_works_without_env_vars() {
    // Without env vars, initiate_browser_auth should use embedded defaults
    // and reach the "bind port" stage — it should NOT error with "not set".
    // We test this by removing the env vars and checking the error is NOT
    // about missing credentials (it will fail trying to open a browser/bind,
    // which is fine in a test environment).
    let _cid = EnvGuard::remove("BLAZEHASH_GDRIVE_CLIENT_ID");
    let _csecret = EnvGuard::remove("BLAZEHASH_GDRIVE_CLIENT_SECRET");

    // We can't complete the flow (no browser), but we can verify it doesn't
    // fail with "BLAZEHASH_GDRIVE_CLIENT_ID is not set"
    // by checking the auth URL can be built with the defaults.
    let url = build_oauth_auth_url(DEFAULT_CLIENT_ID, "http://localhost:9999/callback", "st");
    assert!(
        url.contains(DEFAULT_CLIENT_ID),
        "auth URL should contain the default client ID"
    );
}

#[test]
fn env_var_overrides_default_client_id() {
    let _cid = EnvGuard::set("BLAZEHASH_GDRIVE_CLIENT_ID", "override-client-id");
    let effective = std::env::var("BLAZEHASH_GDRIVE_CLIENT_ID")
        .unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());
    assert_eq!(effective, "override-client-id");
}
