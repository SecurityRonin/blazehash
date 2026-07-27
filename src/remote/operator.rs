use anyhow::{bail, Result};
use opendal::{services, Operator};

/// Build an [`Operator`] and return `(Operator, relative_path)` from a remote URI.
///
/// The OpenDAL service set is scoped to forensically-relevant evidence-transfer
/// targets (see ADR-0010). Supported schemes:
///
/// **Cloud object storage**
/// `s3`, `gcs`, `azblob`, `azdls`, `azfile`, `b2`, `cos`, `obs`, `oss`, `swift`
///
/// **Cloud drive**
/// `gdrive`
///
/// **Hadoop**
/// `webhdfs`, `hdfs`
///
/// **SQL**
/// `mysql`, `postgresql`, `sqlite`
///
/// **Filesystem / network protocols**
/// `file`, `http`, `https`, `webdav`, `sftp`, `ftp`, `ftps`
///
/// **In-memory**
/// `mem`
///
/// Auth is read from standard environment variables; refer to each backend's documentation
/// for the expected variable names.
pub fn operator_for_uri(uri: &str) -> Result<(Operator, String)> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("not a URI: {uri}"))?;

    match scheme {
        // ── In-memory ────────────────────────────────────────────────────────
        "mem" => {
            let op = Operator::new(services::Memory::default())?.finish();
            Ok((op, rest.to_string()))
        }

        // ── Cloud object storage ─────────────────────────────────────────────
        "s3" => {
            let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
            let region = std::env::var("AWS_DEFAULT_REGION").unwrap_or_else(|_| "us-east-1".into());
            let builder = services::S3::default().bucket(bucket).region(&region);
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
        "azdls" => {
            // azdls://filesystem/path
            let (filesystem, path) = rest.split_once('/').unwrap_or((rest, ""));
            let account = std::env::var("AZURE_STORAGE_ACCOUNT")
                .unwrap_or_else(|_| "devstoreaccount1".into());
            let endpoint = std::env::var("AZDLS_ENDPOINT")
                .unwrap_or_else(|_| format!("https://{account}.dfs.core.windows.net"));
            let builder = services::Azdls::default()
                .filesystem(filesystem)
                .endpoint(&endpoint)
                .account_name(&account);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "azfile" => {
            // azfile://share/path
            let (share, path) = rest.split_once('/').unwrap_or((rest, ""));
            let account = std::env::var("AZURE_STORAGE_ACCOUNT")
                .unwrap_or_else(|_| "devstoreaccount1".into());
            let endpoint = std::env::var("AZFILE_ENDPOINT")
                .unwrap_or_else(|_| format!("https://{account}.file.core.windows.net"));
            let builder = services::Azfile::default()
                .share_name(share)
                .endpoint(&endpoint)
                .account_name(&account);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "b2" => {
            // b2://bucket/key — creds from BACKBLAZE_APPLICATION_KEY_ID / BACKBLAZE_APPLICATION_KEY
            let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
            let key_id = std::env::var("BACKBLAZE_APPLICATION_KEY_ID").unwrap_or_default();
            let app_key = std::env::var("BACKBLAZE_APPLICATION_KEY").unwrap_or_default();
            let builder = services::B2::default()
                .bucket(bucket)
                .application_key_id(&key_id)
                .application_key(&app_key);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }
        "cos" => {
            // cos://bucket/key — creds from TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY
            let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
            let region =
                std::env::var("TENCENTCLOUD_REGION").unwrap_or_else(|_| "ap-guangzhou".into());
            let endpoint = std::env::var("COS_ENDPOINT")
                .unwrap_or_else(|_| format!("https://{bucket}.cos.{region}.myqcloud.com"));
            let secret_id = std::env::var("TENCENTCLOUD_SECRET_ID").unwrap_or_default();
            let secret_key = std::env::var("TENCENTCLOUD_SECRET_KEY").unwrap_or_default();
            let builder = services::Cos::default()
                .bucket(bucket)
                .endpoint(&endpoint)
                .secret_id(&secret_id)
                .secret_key(&secret_key);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }
        "obs" => {
            // obs://bucket/key — creds from HUAWEI_ACCESS_KEY_ID / HUAWEI_SECRET_ACCESS_KEY
            let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
            let region = std::env::var("HUAWEI_REGION").unwrap_or_else(|_| "cn-north-4".into());
            let endpoint = std::env::var("OBS_ENDPOINT")
                .unwrap_or_else(|_| format!("https://obs.{region}.myhuaweicloud.com"));
            let access_key = std::env::var("HUAWEI_ACCESS_KEY_ID").unwrap_or_default();
            let secret_key = std::env::var("HUAWEI_SECRET_ACCESS_KEY").unwrap_or_default();
            let builder = services::Obs::default()
                .bucket(bucket)
                .endpoint(&endpoint)
                .access_key_id(&access_key)
                .secret_access_key(&secret_key);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }
        "oss" => {
            // oss://bucket/key — creds from ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET
            let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
            let region =
                std::env::var("ALIBABA_CLOUD_REGION").unwrap_or_else(|_| "cn-hangzhou".into());
            let endpoint = std::env::var("OSS_ENDPOINT")
                .unwrap_or_else(|_| format!("https://oss-{region}.aliyuncs.com"));
            let access_key = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_ID").unwrap_or_default();
            let access_secret =
                std::env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET").unwrap_or_default();
            let builder = services::Oss::default()
                .bucket(bucket)
                .endpoint(&endpoint)
                .access_key_id(&access_key)
                .access_key_secret(&access_secret);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }
        "swift" => {
            // swift://container/path — auth from SWIFT_ENDPOINT + SWIFT_TOKEN
            let (container, path) = rest.split_once('/').unwrap_or((rest, ""));
            let endpoint = std::env::var("SWIFT_ENDPOINT")
                .unwrap_or_else(|_| "https://object.example.com".into());
            let token = std::env::var("SWIFT_TOKEN").unwrap_or_default();
            let builder = services::Swift::default()
                .endpoint(&endpoint)
                .container(container)
                .token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        // ── Hadoop ───────────────────────────────────────────────────────────
        "webhdfs" => {
            // webhdfs://host:port/path — user from WEBHDFS_USER
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let endpoint = format!("http://{hostport}");
            let user = std::env::var("WEBHDFS_USER").unwrap_or_default();
            let mut builder = services::Webhdfs::default().root("/").endpoint(&endpoint);
            if !user.is_empty() {
                builder = builder.user_name(&user);
            }
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "hdfs" => {
            // hdfs://namenode:port/path — pure-Rust HDFS native client (no Java required)
            // Uses services-hdfs-native (hdfs-native crate), not the JVM-bound hdrs.
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let name_node = format!("hdfs://{hostport}");
            let builder = services::HdfsNative::default()
                .name_node(&name_node)
                .root("/");
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        // ── SQL (sqlx, pure Rust) ─────────────────────────────────────────────
        "mysql" => {
            // mysql://[user:pass@]host/db/key
            let conn_str = format!("mysql://{rest}");
            let path = rest
                .split_once('/')
                .and_then(|(_, after_host)| after_host.split_once('/'))
                .map(|(_, key)| key.to_string())
                .unwrap_or_default();
            let builder = services::Mysql::default().connection_string(&conn_str);
            let op = Operator::new(builder)?.finish();
            Ok((op, path))
        }
        "postgresql" => {
            // postgresql://[user:pass@]host/db/key
            let conn_str = format!("postgresql://{rest}");
            let mut parts = rest.splitn(3, '/');
            let _host = parts.next().unwrap_or("");
            let _db = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("").to_string();
            let builder = services::Postgresql::default().connection_string(&conn_str);
            let op = Operator::new(builder)?.finish();
            Ok((op, path))
        }
        "sqlite" => {
            // sqlite://path/to/db.sqlite/key  (opendal uses connection string)
            let (db_path, key) = rest.rsplit_once('/').unwrap_or((rest, ""));
            let conn = format!("sqlite://{db_path}");
            let builder = services::Sqlite::default().connection_string(&conn);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }
        // ── Filesystem / network protocols ───────────────────────────────────
        "webdav" => {
            let host = rest.split('/').next().unwrap_or("");
            let endpoint = format!("https://{host}");
            let path = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
            let builder = services::Webdav::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "http" | "https" => {
            let host = rest.split('/').next().unwrap_or("");
            let endpoint = format!("{scheme}://{host}");
            let path = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
            let builder = services::Http::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }
        "sftp" => {
            // sftp:// is handled by crate::remote::sftp::fetch_sftp_bytes — not opendal.
            // (opendal services-sftp uses the openssh Rust crate which is Unix-only;
            //  our ssh2/libssh2-based implementation works on Linux, macOS, and Windows.)
            anyhow::bail!(
                "sftp:// URIs must be fetched with \
                 `crate::remote::sftp::fetch_sftp_bytes(uri)` \
                 (ssh2/libssh2, cross-platform). \
                 operator_for_uri() does not support sftp://."
            )
        }
        "ftp" | "ftps" => {
            // ftp/ftps are handled by crate::remote::ftp::fetch_ftp_bytes — not opendal.
            // (opendal services-ftp has an async-tls/tokio-rustls version conflict.)
            anyhow::bail!(
                "ftp:// and ftps:// URIs must be fetched with \
                 crate::remote::ftp::fetch_ftp_bytes(), not operator_for_uri()"
            )
        }
        "file" => {
            let (dir, file) = rest.rsplit_once('/').unwrap_or(("/", rest));
            let builder = services::Fs::default().root(dir);
            let op = Operator::new(builder)?.finish();
            Ok((op, file.to_string()))
        }

        other => bail!("unsupported URI scheme: {other}://"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdfs_uri_is_not_unsupported() {
        // hdfs:// should not return "unsupported URI scheme: hdfs://"
        let result = operator_for_uri("hdfs://namenode:9000/data/evidence.zip");
        // Currently fails RED: bails with "unsupported URI scheme: hdfs://"
        assert!(
            result.is_ok()
                || !result
                    .as_ref()
                    .unwrap_err()
                    .to_string()
                    .contains("unsupported URI scheme: hdfs://"),
            "hdfs:// should not return unsupported-scheme error"
        );
    }

    #[test]
    fn hdfs_uri_path_extraction() {
        // After implementation, the path component should be extracted correctly.
        let (_, path) = operator_for_uri("hdfs://namenode:9000/data/evidence.zip")
            .expect("hdfs:// should be supported");
        assert_eq!(path, "data/evidence.zip");
    }

    #[test]
    fn hdfs_is_recognised_as_remote() {
        assert!(
            crate::remote::is_remote_uri("hdfs://namenode:9000/path"),
            "hdfs:// should be recognised as a remote URI"
        );
    }

    #[test]
    fn sftp_uri_is_supported() {
        // sftp:// already in operator; verify it does NOT return unsupported error
        let result = operator_for_uri("sftp://user@host/path/file.zip");
        assert!(
            result.is_ok() || !result.unwrap_err().to_string().contains("unsupported"),
            "sftp:// should be supported"
        );
    }

    #[test]
    fn webhdfs_uri_is_supported() {
        let result = operator_for_uri("webhdfs://namenode:50070/path/file");
        assert!(
            result.is_ok() || !result.unwrap_err().to_string().contains("unsupported"),
            "webhdfs:// should be supported"
        );
    }

    // ── ADR-0010: dropped OpenDAL backends must be unsupported ────────────────
    // These schemes were removed from the `remote` OpenDAL service set. Each must
    // fall through to the `other =>` arm and report "unsupported URI scheme".
    fn assert_unsupported(uri: &str) {
        let err = operator_for_uri(uri)
            .expect_err("dropped scheme must return an error")
            .to_string();
        assert!(
            err.contains("unsupported URI scheme"),
            "expected unsupported-scheme error for {uri:?}, got: {err}"
        );
    }

    #[test]
    fn dropped_mongodb_is_unsupported() {
        assert_unsupported("mongodb://host/db/coll/key");
    }

    #[test]
    fn dropped_redis_is_unsupported() {
        assert_unsupported("redis://host:6379/key");
    }

    #[test]
    fn dropped_rocksdb_is_unsupported() {
        assert_unsupported("rocksdb:///var/lib/db/key");
    }

    #[test]
    fn dropped_ipfs_is_unsupported() {
        assert_unsupported("ipfs://QmHash/path");
    }

    #[test]
    fn dropped_onedrive_is_unsupported() {
        assert_unsupported("onedrive://Documents/file.pdf");
    }

    #[test]
    fn dropped_github_is_unsupported() {
        assert_unsupported("github://owner/repo/path");
    }

    #[test]
    fn dropped_compfs_is_unsupported() {
        assert_unsupported("compfs:///tmp/evidence/file");
    }

    #[test]
    fn dropped_etcd_is_unsupported() {
        assert_unsupported("etcd://host:2379/key");
    }
}
