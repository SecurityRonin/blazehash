# blazehash Feature Batch 15: Universal Remote Storage Adapter

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Universal protocol adapter layer via Apache OpenDAL — read from and write to
`s3://`, `gcs://`, `azblob://`, `sftp://`, `webdav://`, `hdfs://`, `http(s)://`, and more.
Both directions: `blazehash hash s3://bucket/evidence/` and `blazehash hash . -o s3://bucket/manifest.hash`.

**Architecture:**
- Foundation: `opendal` crate (50+ backends, async + blocking layers, Apache project)
- Feature flag: `remote` gates all opendal deps; not in `default` (keeps binary size for air-gapped use)
- Write path: `RemoteWriter` buffers into `Vec<u8>`, uploads atomically on `Drop` — **zero changes to the 72 dispatch sites** in `main.rs`
- Read path: URI-detected inputs fetch bytes via OpenDAL blocking reader
- Testing: OpenDAL `memory` service (in-process, no cloud credentials, no Docker)

**URI schemes supported:**

| Scheme | Backend | Notes |
|--------|---------|-------|
| `s3://bucket/key` | S3 + S3-compatible | AWS, MinIO, R2, Wasabi, B2 |
| `gcs://bucket/key` | Google Cloud Storage | Service account / ADC |
| `azblob://container/key` | Azure Blob Storage | SAS / managed identity |
| `sftp://user@host/path` | SFTP | russh (pure Rust) |
| `webdav://host/path` | WebDAV | Nextcloud, Box, SharePoint |
| `hdfs://namenode/path` | HDFS | hdfs-native |
| `http://host/path` | HTTP read-only | Range requests |
| `https://host/path` | HTTPS read-only | Range requests |
| `mem://bucket/key` | In-memory | **Test-only** |
| `file:///abs/path` | Local filesystem | Explicit file:// |

**Two commits per task: RED (failing tests) then GREEN (implementation + zero clippy).**

---

## Task 1: Cargo deps + URI parser

Add `opendal` and parse URI strings into a typed enum.

### Cargo.toml additions

```toml
[features]
remote = [
    "dep:opendal",
    "dep:bytes",
]

[dependencies]
opendal = { version = "0.50", optional = true, features = [
    "services-s3",
    "services-gcs",
    "services-azblob",
    "services-sftp",
    "services-webdav",
    "services-memory",
    "services-fs",
] }
bytes = { version = "1", optional = true }
```

> Note: check `crates.io` for the latest `opendal` version before adding.
> The `services-hdfs` feature requires the Java runtime; leave it out of default remote for now.

### `src/remote/mod.rs`

```rust
#[cfg(feature = "remote")]
pub mod writer;
#[cfg(feature = "remote")]
pub mod reader;
#[cfg(feature = "remote")]
pub mod operator;

/// Detect whether a string looks like a remote URI (has a known scheme://).
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
            "s3"      => Some(Self::S3),
            "gcs"     => Some(Self::Gcs),
            "azblob"  => Some(Self::AzBlob),
            "sftp"    => Some(Self::Sftp),
            "webdav"  => Some(Self::WebDav),
            "hdfs"    => Some(Self::Hdfs),
            "http"    => Some(Self::Http),
            "https"   => Some(Self::Https),
            "mem"     => Some(Self::Mem),
            "file"    => Some(Self::File),
            _         => None,
        }
    }
}
```

### `tests/remote_uri_tests.rs`

5 tests (no `remote` feature needed — `is_remote_uri` and `UriScheme::detect` are always compiled):

1. `test_s3_uri_detected` — `is_remote_uri("s3://bucket/key")` → true
2. `test_gcs_uri_detected` — `is_remote_uri("gcs://bucket/key")` → true
3. `test_local_path_not_remote` — `is_remote_uri("/tmp/manifest.hash")` → false
4. `test_scheme_detect_azblob` — `UriScheme::detect("azblob://container/blob")` → `Some(AzBlob)`
5. `test_scheme_detect_unknown_returns_none` — `UriScheme::detect("ftp://host/path")` → `None`

**Note:** Remove `#[cfg(feature = "remote")]` guards from `is_remote_uri` and `UriScheme` — they must compile without the feature so `output_writer` can check them in all builds and emit a helpful error when `remote` is not enabled.

---

## Task 2: `RemoteWriter` — `-o s3://bucket/manifest.hash`

Buffer manifest output into memory, upload atomically on `Drop`.
**Zero changes to existing dispatch sites in `main.rs`.**

### `src/remote/operator.rs`

```rust
use anyhow::{bail, Result};
use opendal::{Operator, services};

/// Build an OpenDAL Operator from a URI string.
/// The returned (operator, relative_path) pair lets callers read/write `relative_path`.
pub fn operator_for_uri(uri: &str) -> Result<(Operator, String)> {
    let (scheme, rest) = uri.split_once("://")
        .ok_or_else(|| anyhow::anyhow!("not a URI: {uri}"))?;
    match scheme {
        "mem" => {
            // mem://bucket/path  →  bucket is the root, path is the key
            let (root, path) = rest.split_once('/').unwrap_or((rest, ""));
            let op = Operator::new(services::Memory::default())?.finish();
            Ok((op, format!("{root}/{path}")))
        }
        "s3" => {
            // s3://bucket/key  — auth from env (AWS_ACCESS_KEY_ID etc.)
            let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
            let builder = services::S3::default()
                .bucket(bucket)
                .region(&std::env::var("AWS_DEFAULT_REGION").unwrap_or_else(|_| "us-east-1".into()));
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }
        "gcs" => {
            let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
            let builder = services::Gcs::default().bucket(bucket);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }
        "azblob" => {
            let (container, blob) = rest.split_once('/').unwrap_or((rest, ""));
            let account = std::env::var("AZURE_STORAGE_ACCOUNT")
                .unwrap_or_else(|_| "devstoreaccount1".into());
            let builder = services::Azblob::default()
                .container(container)
                .account_name(&account);
            let op = Operator::new(builder)?.finish();
            Ok((op, blob.to_string()))
        }
        "webdav" => {
            let endpoint = format!("https://{}", rest.split('/').next().unwrap_or(""));
            let path = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
            let builder = services::Webdav::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "sftp" => {
            // sftp://user@host/path
            let (userhost, path) = rest.split_once('/').unwrap_or((rest, ""));
            let (user, host) = userhost.split_once('@').unwrap_or(("", userhost));
            let builder = services::Sftp::default()
                .endpoint(host)
                .user(user)
                .root("/");
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "http" | "https" => {
            let endpoint = format!("{scheme}://{}", rest.split('/').next().unwrap_or(""));
            let path = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
            let builder = services::Http::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "file" => {
            // file:///absolute/path
            let (dir, file) = rest.rsplit_once('/').unwrap_or(("/", rest));
            let builder = services::Fs::default().root(dir);
            let op = Operator::new(builder)?.finish();
            Ok((op, file.to_string()))
        }
        other => bail!("unsupported URI scheme: {other}://"),
    }
}
```

### `src/remote/writer.rs`

```rust
use anyhow::Result;
use opendal::BlockingOperator;
use std::io::Write;

/// A `Write` implementation that buffers all output and uploads atomically
/// to a remote URI via OpenDAL when `finish()` is called.
pub struct RemoteWriter {
    buf: Vec<u8>,
    op: BlockingOperator,
    path: String,
}

impl RemoteWriter {
    pub fn new(op: BlockingOperator, path: String) -> Self {
        Self { buf: Vec::new(), op, path }
    }

    /// Upload buffered content. Call explicitly to propagate errors.
    pub fn finish(self) -> Result<()> {
        self.op.write(&self.path, self.buf)?;
        Ok(())
    }
}

impl Write for RemoteWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
```

### Extend `src/commands/mod.rs` `output_writer`

```rust
pub fn output_writer(path: Option<&std::path::Path>) -> Result<Box<dyn std::io::Write>> {
    match path {
        None => Ok(Box::new(std::io::stdout())),
        Some(p) => {
            let s = p.to_string_lossy();
            #[cfg(feature = "remote")]
            if crate::remote::is_remote_uri(&s) {
                let (op, rel) = crate::remote::operator::operator_for_uri(&s)?;
                let blocking = op.blocking();
                return Ok(Box::new(crate::remote::writer::RemoteWriter::new(blocking, rel)));
            }
            #[cfg(not(feature = "remote"))]
            if crate::remote::is_remote_uri(&s) {
                anyhow::bail!("remote URIs require the `remote` feature: recompile with --features remote");
            }
            Ok(Box::new(std::fs::File::create(p)?))
        }
    }
}
```

**Important:** `RemoteWriter` implements `Write` but its `finish()` is not called automatically here — the buffer uploads when `RemoteWriter` is dropped (via a best-effort `Drop`). For explicit error propagation, callers that know they have a `RemoteWriter` can downcast. For now, implement `Drop` that logs to stderr on failure:

```rust
impl Drop for RemoteWriter {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            if let Err(e) = self.op.write(&self.path, std::mem::take(&mut self.buf)) {
                eprintln!("blazehash: error: remote write failed: {e}");
            }
        }
    }
}
```

### `tests/remote_writer_tests.rs`

5 tests (require `remote` feature):

1. `test_remote_writer_buffers_content` — write bytes to `RemoteWriter`, call `finish()`, read back via operator, verify match
2. `test_remote_writer_empty_write_succeeds` — finish with empty buffer, no error
3. `test_output_writer_mem_uri_writes` — call `output_writer(Some(Path::new("mem://test/out.hash")))`, write manifest line, drop → read back from memory operator
4. `test_output_writer_local_path_unchanged` — local path still works (regression)
5. `test_output_writer_unknown_scheme_errors` — `ftp://host/file` with `remote` feature returns error

---

## Task 3: Remote manifest reader

Fetch a manifest from any URI and pass its bytes to the existing manifest parser.

### `src/remote/reader.rs`

```rust
use anyhow::Result;
use super::operator::operator_for_uri;

/// Fetch the full contents of a remote URI as a String.
pub fn fetch_remote_text(uri: &str) -> Result<String> {
    let (op, path) = operator_for_uri(uri)?;
    let blocking = op.blocking();
    let bytes = blocking.read(&path)?;
    Ok(String::from_utf8(bytes.to_vec())?)
}
```

### Extend manifest loader (`src/manifest_loader.rs` or wherever `load_manifest` lives)

Add a new `load_manifest_uri(uri: &str) -> Result<Vec<ManifestRecord>>` that:
1. Fetches text via `fetch_remote_text`
2. Parses lines using the same logic as `load_manifest`

OR (simpler): write the fetched content to a `tempfile` and call existing `load_manifest`.

### Extend CLI path resolution

In `main.rs`, wherever `paths[1]` is used as a manifest path, detect if it's a URI and download to a temp file first. Introduce a helper:

```rust
fn resolve_manifest_path(raw: &str) -> Result<std::path::PathBuf> {
    if crate::remote::is_remote_uri(raw) {
        #[cfg(feature = "remote")]
        {
            let text = crate::remote::reader::fetch_remote_text(raw)?;
            let mut tmp = tempfile::NamedTempFile::new()?;
            use std::io::Write;
            tmp.write_all(text.as_bytes())?;
            Ok(tmp.into_temp_path().keep()?)
        }
        #[cfg(not(feature = "remote"))]
        anyhow::bail!("remote URIs require --features remote")
    } else {
        Ok(std::path::PathBuf::from(raw))
    }
}
```

### `tests/remote_reader_tests.rs`

5 tests:

1. `test_fetch_remote_text_mem` — seed `mem://` operator with content, fetch via `fetch_remote_text`, verify text
2. `test_fetch_remote_text_not_found_errors` — non-existent key returns error
3. `test_remote_manifest_audit_via_mem` — write manifest to `mem://`, call `blazehash audit mem://...` CLI, verify output
4. `test_remote_manifest_cat_via_mem` — `blazehash cat mem://a.hash mem://b.hash` fetches both
5. `test_resolve_manifest_path_local_unchanged` — local path returns same path (regression)

---

## Task 4: Remote directory hashing — `blazehash hash s3://bucket/prefix/`

Walk a remote prefix, download each object, hash bytes, emit manifest.

### `src/remote/walk.rs`

```rust
use anyhow::Result;
use blazehash::algorithm::{hash_bytes, Algorithm};
use opendal::BlockingOperator;
use std::io::Write;

pub fn hash_remote_prefix(
    op: &BlockingOperator,
    prefix: &str,
    algos: &[Algorithm],
    out: &mut impl Write,
) -> Result<usize> {
    let mut count = 0;
    // List all objects under prefix recursively
    let entries = op.list_with(prefix).recursive(true).call()?;
    for entry in entries {
        let meta = entry.metadata();
        if meta.is_dir() { continue; }
        let path = entry.path();
        let bytes = op.read(path)?.to_vec();
        for algo in algos {
            let h = hash_bytes(*algo, &bytes);
            writeln!(out, "{algo}  {h}  {path}")?;
        }
        count += 1;
    }
    Ok(count)
}
```

### Wire into `main.rs` hash command

In the main hash walk, before calling the local filesystem walker, check if `paths[0]` (or the first non-subcommand path) is a remote URI. If so, call `hash_remote_prefix` instead.

### `tests/remote_hash_tests.rs`

5 tests:

1. `test_hash_remote_prefix_hashes_objects` — seed `mem://` with 3 objects, hash prefix, output contains all 3 paths
2. `test_hash_remote_prefix_correct_hash` — single object with known content, verify BLAKE3 hash in output
3. `test_hash_remote_prefix_skips_dirs` — directory entries not emitted as hash lines
4. `test_hash_remote_single_object` — `blazehash hash mem://bucket/file.bin` hashes one object
5. `test_hash_remote_output_to_remote` — `blazehash hash mem://src/ -o mem://dst/manifest.hash` end-to-end

---

## Task 5: Auth wiring + multi-backend smoke tests

Wire environment variable auth for S3/GCS/Azure/SFTP. Add `--remote-config` flag for overrides.

### Auth environment variables (read in `operator_for_uri`)

| Backend | Env vars |
|---------|----------|
| S3 | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`, `AWS_ENDPOINT_URL` (for MinIO/R2) |
| GCS | `GOOGLE_APPLICATION_CREDENTIALS` (path to service account JSON) |
| Azure | `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_ACCESS_KEY` or `AZURE_STORAGE_SAS_TOKEN` |
| SFTP | `SFTP_PASSWORD` or `SFTP_KEY_PATH` |
| WebDAV | `WEBDAV_USERNAME`, `WEBDAV_PASSWORD` |

### New CLI flag

```rust
/// Remote backend config overrides (key=value, repeatable)
#[arg(long = "remote-config", value_name = "KEY=VALUE")]
pub remote_config: Vec<String>,
```

Pass these into `operator_for_uri` as an override map.

### `tests/remote_auth_tests.rs`

5 tests (all use `mem://` — no real credentials needed):

1. `test_s3_endpoint_override_from_env` — set `AWS_ENDPOINT_URL=http://localhost:9000`, build S3 operator, verify endpoint set (inspect builder, don't actually connect)
2. `test_remote_config_flag_parsed` — `--remote-config region=eu-west-1` appears in `cli.remote_config`
3. `test_mem_backend_round_trip` — write then read via `mem://` operator, full round trip
4. `test_webdav_auth_env_read` — `WEBDAV_USERNAME=user` picked up by operator builder
5. `test_full_suite_still_passes` — `cargo test --all-features` passes (regression guard)

---

## Commit sequence (per task)

```bash
export GITSIGN_CREDENTIAL_CACHE="/Users/4n6h4x0r/.cache/sigstore/gitsign/cache.sock"

# RED
cargo test --all-features --test <name>_tests 2>&1 | tail -10
git add tests/<name>_tests.rs
git commit -m "test(RED): add failing tests for blazehash remote <topic>"

# GREEN
cargo test --all-features --test <name>_tests 2>&1 | tail -5
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -5
git add src/remote/*.rs src/commands/mod.rs src/cli.rs src/main.rs Cargo.toml
git commit -m "feat: blazehash remote <topic>"
```

After Task 5 GREEN: full suite + push.

---

## Design notes for implementer

- **opendal version**: check `crates.io/crates/opendal` for the latest `0.x` — API changes between minor versions. Read the changelog before writing code.
- **BlockingOperator**: `op.blocking()` gives sync access; use this everywhere so we don't need an async runtime in tests.
- **`mem://` in tests**: build a `Memory` operator programmatically, not via URI parsing, to avoid chicken-and-egg in the URI dispatcher tests. The URI dispatcher tests (`remote_uri_tests`) don't require the `remote` feature.
- **opendal `list_with(...).recursive(true)`**: API may differ — check the opendal docs for the exact list API.
- **Temp file lifetime**: in `resolve_manifest_path`, keep the `NamedTempFile` alive until after the manifest is loaded. Use `.keep()` to persist it or restructure so it outlives the parse call.
- **Do not use `services-hdfs`** in the feature list — it requires a JVM and breaks macOS CI.
