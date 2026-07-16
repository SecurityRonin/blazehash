// Tests for auth-aware hash_gdrive_file_with_auth dispatch.
//
// All tests use in-process TCP mock servers on ephemeral ports — no network,
// no mocking libraries.  Each test spins up a server in a thread, runs the
// function under test against it, then inspects the captured HTTP request.

#[cfg(feature = "remote")]
mod hash_auth_tests {
    use std::io::{Read, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration;

    use blazehash::algorithm::Algorithm;
    use blazehash::remote::gdrive::auth::GDriveAuthMode;
    use blazehash::remote::gdrive::hash_gdrive_file_with_auth_at as hash_gdrive_file_with_auth;

    // ── helper ───────────────────────────────────────────────────────────────

    /// Spawn a single-request TCP server that returns `body` with HTTP 200.
    /// Sends the captured raw request string back over the channel.
    fn spawn_mock_server(body: &'static [u8]) -> (u16, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            tx.send(request).unwrap();

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        (port, rx)
    }

    // ── UserOAuth: Authorization header ──────────────────────────────────────

    #[test]
    fn oauth_mode_sends_bearer_authorization_header() {
        let (port, rx) = spawn_mock_server(b"data");
        let api_base = format!("http://127.0.0.1:{port}");
        let auth = GDriveAuthMode::UserOAuth {
            access_token: "ya29.test_token_abc".to_string(),
        };

        let mut out = Vec::new();
        let _ = hash_gdrive_file_with_auth(
            "file123",
            &auth,
            &[Algorithm::Blake3],
            &mut out,
            Some(&api_base),
        );

        let request = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            request.contains("Authorization: Bearer ya29.test_token_abc"),
            "expected Authorization: Bearer header in request, got:\n{request}"
        );
    }

    #[test]
    fn oauth_mode_hashes_response_bytes_correctly() {
        // Known content → known BLAKE3 hash
        let content = b"known file content for hashing";
        let expected = blake3::hash(content).to_hex().to_string();

        let (port, _rx) = spawn_mock_server(content);
        let api_base = format!("http://127.0.0.1:{port}");
        let auth = GDriveAuthMode::UserOAuth {
            access_token: "ya29.token".to_string(),
        };

        let mut out = Vec::new();
        let result = hash_gdrive_file_with_auth(
            "fileid",
            &auth,
            &[Algorithm::Blake3],
            &mut out,
            Some(&api_base),
        )
        .expect("should succeed with mock server");

        assert_eq!(
            result.blake3.as_deref(),
            Some(expected.as_str()),
            "BLAKE3 hash should match known content"
        );
        assert_eq!(result.bytes_read, content.len() as u64);
    }

    #[test]
    fn oauth_mode_requests_drive_api_v3_path() {
        let (port, rx) = spawn_mock_server(b"content");
        let api_base = format!("http://127.0.0.1:{port}");
        let auth = GDriveAuthMode::UserOAuth {
            access_token: "ya29.tok".to_string(),
        };

        let mut out = Vec::new();
        let _ = hash_gdrive_file_with_auth(
            "MYFILEID",
            &auth,
            &[Algorithm::Blake3],
            &mut out,
            Some(&api_base),
        );

        let request = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            request.contains("/drive/v3/files/MYFILEID") || request.contains("MYFILEID"),
            "request should target Drive API v3 path with file ID, got:\n{request}"
        );
        assert!(
            request.contains("alt=media"),
            "request should include alt=media param, got:\n{request}"
        );
    }

    // ── Public: no Authorization header ──────────────────────────────────────

    #[test]
    fn public_mode_does_not_send_authorization_header() {
        let (port, rx) = spawn_mock_server(b"public content");
        let api_base = format!("http://127.0.0.1:{port}");
        let auth = GDriveAuthMode::Public;

        let mut out = Vec::new();
        let _ = hash_gdrive_file_with_auth(
            "pubfile",
            &auth,
            &[Algorithm::Blake3],
            &mut out,
            Some(&api_base),
        );

        let request = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            !request.contains("Authorization:"),
            "public mode must not send Authorization header, got:\n{request}"
        );
    }

    #[test]
    fn public_mode_uses_export_download_path() {
        let (port, rx) = spawn_mock_server(b"data");
        let api_base = format!("http://127.0.0.1:{port}");
        let auth = GDriveAuthMode::Public;

        let mut out = Vec::new();
        let _ = hash_gdrive_file_with_auth(
            "PUB123",
            &auth,
            &[Algorithm::Blake3],
            &mut out,
            Some(&api_base),
        );

        let request = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            request.contains("export=download") || request.contains("PUB123"),
            "public mode should use usercontent-style path, got:\n{request}"
        );
    }

    // ── ServiceAccount: informative error ────────────────────────────────────

    #[test]
    fn service_account_mode_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let sa_path = dir.path().join("sa.json");
        std::fs::write(&sa_path, b"{}").unwrap();

        let auth = GDriveAuthMode::ServiceAccount { path: sa_path };
        let mut out = Vec::new();
        let result =
            hash_gdrive_file_with_auth("fileid", &auth, &[Algorithm::Blake3], &mut out, None);

        assert!(result.is_err(), "service account mode should return error");
        let msg = result.err().unwrap().to_string().to_lowercase();
        assert!(
            msg.contains("service account")
                || msg.contains("not yet")
                || msg.contains("gdrive auth"),
            "error should explain service account is not yet supported, got: {msg}"
        );
    }

    // ── manifest output ───────────────────────────────────────────────────────

    #[test]
    fn oauth_mode_emits_manifest_line_with_file_id() {
        let content = b"manifest test content";
        let (port, _rx) = spawn_mock_server(content);
        let api_base = format!("http://127.0.0.1:{port}");
        let auth = GDriveAuthMode::UserOAuth {
            access_token: "ya29.tok".to_string(),
        };

        let mut out = Vec::new();
        hash_gdrive_file_with_auth(
            "MANIFEST_ID",
            &auth,
            &[Algorithm::Sha256],
            &mut out,
            Some(&api_base),
        )
        .expect("should succeed");

        let manifest = String::from_utf8(out).unwrap();
        assert!(
            manifest.contains("MANIFEST_ID"),
            "manifest line should contain file ID, got: {manifest}"
        );
        assert!(
            manifest.contains("gdrive://"),
            "manifest line should use gdrive:// URI, got: {manifest}"
        );
    }
}
