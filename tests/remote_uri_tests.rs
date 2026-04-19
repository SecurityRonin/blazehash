use blazehash::remote::{is_remote_uri, UriScheme};

// ── Original passing tests ────────────────────────────────────────────────────

#[test]
fn test_s3_uri_detected() {
    assert!(is_remote_uri("s3://bucket/key"));
}

#[test]
fn test_gcs_uri_detected() {
    assert!(is_remote_uri("gcs://bucket/key"));
}

#[test]
fn test_local_path_not_remote() {
    assert!(!is_remote_uri("/tmp/manifest.hash"));
    assert!(!is_remote_uri("relative/path.hash"));
    assert!(!is_remote_uri("manifest.hash"));
}

#[test]
fn test_scheme_detect_azblob() {
    assert_eq!(UriScheme::detect("azblob://container/blob"), Some(UriScheme::AzBlob));
}

// Renamed from test_scheme_detect_unknown_returns_none — ftp is now supported;
// use a genuinely unsupported scheme.
#[test]
fn test_scheme_detect_truly_unknown_returns_none() {
    assert_eq!(UriScheme::detect("smb://host/share"), None);
    assert_eq!(UriScheme::detect("nfs://host/export"), None);
}

// ── FTP / FTPS ────────────────────────────────────────────────────────────────

#[test]
fn ftp_uri_is_detected() {
    assert!(is_remote_uri("ftp://user:pass@host/path"));
    assert!(is_remote_uri("ftps://user:pass@host/path"));
}

#[test]
fn scheme_detect_ftp() {
    assert_eq!(UriScheme::detect("ftp://host/path"), Some(UriScheme::Ftp));
    assert_eq!(UriScheme::detect("ftps://host/path"), Some(UriScheme::Ftps));
}

// ── SFTP ──────────────────────────────────────────────────────────────────────

#[test]
fn sftp_uri_is_detected() {
    assert!(is_remote_uri("sftp://user@host/path"));
}

#[test]
fn scheme_detect_sftp() {
    assert_eq!(UriScheme::detect("sftp://user@host/path"), Some(UriScheme::Sftp));
}

// ── Microsoft OneDrive ────────────────────────────────────────────────────────

#[test]
fn onedrive_uri_is_detected() {
    assert!(is_remote_uri("onedrive://Documents/report.pdf"));
}

#[test]
fn scheme_detect_onedrive() {
    assert_eq!(UriScheme::detect("onedrive://path/file"), Some(UriScheme::OneDrive));
}

// ── Dropbox ───────────────────────────────────────────────────────────────────

#[test]
fn dropbox_uri_is_detected() {
    assert!(is_remote_uri("dropbox://evidence/dump.zip"));
}

#[test]
fn scheme_detect_dropbox() {
    assert_eq!(UriScheme::detect("dropbox://path/file"), Some(UriScheme::Dropbox));
}

// ── Backblaze B2 ──────────────────────────────────────────────────────────────

#[test]
fn b2_uri_is_detected() {
    assert!(is_remote_uri("b2://bucket/key"));
}

#[test]
fn scheme_detect_b2() {
    assert_eq!(UriScheme::detect("b2://bucket/key"), Some(UriScheme::B2));
}

// ── Tencent COS ───────────────────────────────────────────────────────────────

#[test]
fn cos_uri_is_detected() {
    assert!(is_remote_uri("cos://bucket/key"));
}

#[test]
fn scheme_detect_cos() {
    assert_eq!(UriScheme::detect("cos://bucket/key"), Some(UriScheme::Cos));
}

// ── Huawei OBS ────────────────────────────────────────────────────────────────

#[test]
fn obs_uri_is_detected() {
    assert!(is_remote_uri("obs://bucket/key"));
}

#[test]
fn scheme_detect_obs() {
    assert_eq!(UriScheme::detect("obs://bucket/key"), Some(UriScheme::Obs));
}

// ── Alibaba OSS ───────────────────────────────────────────────────────────────

#[test]
fn oss_uri_is_detected() {
    assert!(is_remote_uri("oss://bucket/key"));
}

#[test]
fn scheme_detect_oss() {
    assert_eq!(UriScheme::detect("oss://bucket/key"), Some(UriScheme::Oss));
}

// ── OpenStack Swift ───────────────────────────────────────────────────────────

#[test]
fn swift_uri_is_detected() {
    assert!(is_remote_uri("swift://container/path"));
}

#[test]
fn scheme_detect_swift() {
    assert_eq!(UriScheme::detect("swift://container/path"), Some(UriScheme::Swift));
}

// ── Azure Files ───────────────────────────────────────────────────────────────

#[test]
fn azfile_uri_is_detected() {
    assert!(is_remote_uri("azfile://share/path/to/file"));
}

#[test]
fn scheme_detect_azfile() {
    assert_eq!(UriScheme::detect("azfile://share/file"), Some(UriScheme::AzFile));
}

// ── Azure Data Lake Storage ───────────────────────────────────────────────────

#[test]
fn azdls_uri_is_detected() {
    assert!(is_remote_uri("azdls://container/path"));
}

#[test]
fn scheme_detect_azdls() {
    assert_eq!(UriScheme::detect("azdls://container/path"), Some(UriScheme::AzDls));
}

// ── GitHub ────────────────────────────────────────────────────────────────────

#[test]
fn github_uri_is_detected() {
    assert!(is_remote_uri("github://owner/repo/path/to/file"));
}

#[test]
fn scheme_detect_github() {
    assert_eq!(UriScheme::detect("github://owner/repo/file"), Some(UriScheme::GitHub));
}

// ── IPFS / IPMFS ─────────────────────────────────────────────────────────────

#[test]
fn ipfs_uri_is_detected() {
    assert!(is_remote_uri("ipfs://QmHash/path"));
}

#[test]
fn ipmfs_uri_is_detected() {
    assert!(is_remote_uri("ipmfs:///path/in/mfs"));
}

#[test]
fn scheme_detect_ipfs() {
    assert_eq!(UriScheme::detect("ipfs://QmHash"), Some(UriScheme::Ipfs));
}

#[test]
fn scheme_detect_ipmfs() {
    assert_eq!(UriScheme::detect("ipmfs:///path"), Some(UriScheme::Ipmfs));
}

// ── WebHDFS ───────────────────────────────────────────────────────────────────

#[test]
fn webhdfs_uri_is_detected() {
    assert!(is_remote_uri("webhdfs://namenode:50070/user/data/file"));
}

#[test]
fn scheme_detect_webhdfs() {
    assert_eq!(UriScheme::detect("webhdfs://host/path"), Some(UriScheme::WebHdfs));
}

// ── HDFS native (pure-Rust, no JVM) ──────────────────────────────────────────

#[test]
fn hdfs_uri_is_detected() {
    assert!(is_remote_uri("hdfs://namenode:9000/user/evidence/disk.dd"));
    assert!(is_remote_uri("hdfs://cluster.hadoop.corp:8020/data/case-001/image.raw"));
}

#[test]
fn hdfs_not_remote_without_host() {
    // bare path must not be mistaken for an hdfs URI
    assert!(!is_remote_uri("hdfs_local/path"));
}

#[test]
fn scheme_detect_hdfs() {
    assert_eq!(UriScheme::detect("hdfs://namenode:9000/path"), Some(UriScheme::Hdfs));
    assert_eq!(UriScheme::detect("hdfs://nn.corp:8020/data/file"), Some(UriScheme::Hdfs));
}

// ── Alluxio ───────────────────────────────────────────────────────────────────

#[test]
fn alluxio_uri_is_detected() {
    assert!(is_remote_uri("alluxio://master:19998/data/file"));
}

#[test]
fn scheme_detect_alluxio() {
    assert_eq!(UriScheme::detect("alluxio://host/path"), Some(UriScheme::Alluxio));
}

// ── LakeFS ────────────────────────────────────────────────────────────────────

#[test]
fn lakefs_uri_is_detected() {
    assert!(is_remote_uri("lakefs://repo/branch/path/to/object"));
}

#[test]
fn scheme_detect_lakefs() {
    assert_eq!(UriScheme::detect("lakefs://repo/main/file"), Some(UriScheme::LakeFs));
}

// ── Aliyun Drive ─────────────────────────────────────────────────────────────

#[test]
fn aliyun_drive_uri_is_detected() {
    assert!(is_remote_uri("aliyun-drive://path/to/file"));
}

#[test]
fn scheme_detect_aliyun_drive() {
    assert_eq!(UriScheme::detect("aliyun-drive://path"), Some(UriScheme::AliyunDrive));
}

// ── Seafile ───────────────────────────────────────────────────────────────────

#[test]
fn seafile_uri_is_detected() {
    assert!(is_remote_uri("seafile://server/repo/path/to/file"));
}

#[test]
fn scheme_detect_seafile() {
    assert_eq!(UriScheme::detect("seafile://server/repo/file"), Some(UriScheme::Seafile));
}

// ── pCloud ────────────────────────────────────────────────────────────────────

#[test]
fn pcloud_uri_is_detected() {
    assert!(is_remote_uri("pcloud://path/to/file"));
}

#[test]
fn scheme_detect_pcloud() {
    assert_eq!(UriScheme::detect("pcloud://path"), Some(UriScheme::PCloud));
}

// ── Koofr ─────────────────────────────────────────────────────────────────────

#[test]
fn koofr_uri_is_detected() {
    assert!(is_remote_uri("koofr://path/to/file"));
}

#[test]
fn scheme_detect_koofr() {
    assert_eq!(UriScheme::detect("koofr://path"), Some(UriScheme::Koofr));
}

// ── Yandex Disk ───────────────────────────────────────────────────────────────

#[test]
fn yandex_disk_uri_is_detected() {
    assert!(is_remote_uri("yandex-disk://path/to/file"));
}

#[test]
fn scheme_detect_yandex_disk() {
    assert_eq!(UriScheme::detect("yandex-disk://path"), Some(UriScheme::YandexDisk));
}

// ── HuggingFace ───────────────────────────────────────────────────────────────

#[test]
fn huggingface_uri_is_detected() {
    assert!(is_remote_uri("huggingface://owner/repo/file"));
}

#[test]
fn scheme_detect_huggingface() {
    assert_eq!(UriScheme::detect("huggingface://owner/repo/file"), Some(UriScheme::HuggingFace));
}

// ── Upyun ─────────────────────────────────────────────────────────────────────

#[test]
fn upyun_uri_is_detected() {
    assert!(is_remote_uri("upyun://bucket/path"));
}

#[test]
fn scheme_detect_upyun() {
    assert_eq!(UriScheme::detect("upyun://bucket/key"), Some(UriScheme::Upyun));
}

// ── Vercel Blob ───────────────────────────────────────────────────────────────

#[test]
fn vercel_blob_uri_is_detected() {
    assert!(is_remote_uri("vercel-blob://key"));
}

#[test]
fn scheme_detect_vercel_blob() {
    assert_eq!(UriScheme::detect("vercel-blob://key"), Some(UriScheme::VercelBlob));
}

// ── RocksDB (optional feature: rocksdb-storage) ───────────────────────────────

#[cfg(feature = "rocksdb-storage")]
#[test]
fn rocksdb_uri_is_detected() {
    assert!(is_remote_uri("rocksdb:///var/lib/rocksdb/evidence"));
}

#[cfg(feature = "rocksdb-storage")]
#[test]
fn scheme_detect_rocksdb() {
    assert_eq!(UriScheme::detect("rocksdb:///path/to/db"), Some(UriScheme::RocksDb));
}

// ── Monoio filesystem (monoiofs, Linux only) ──────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn monoiofs_uri_is_detected() {
    assert!(is_remote_uri("monoiofs:///tmp/evidence/file.bin"));
}

#[cfg(target_os = "linux")]
#[test]
fn scheme_detect_monoiofs() {
    assert_eq!(UriScheme::detect("monoiofs:///path/to/file"), Some(UriScheme::Monoiofs));
}

// ── Compio filesystem (compfs) ────────────────────────────────────────────────

#[test]
fn compfs_uri_is_detected() {
    assert!(is_remote_uri("compfs:///tmp/evidence/file.bin"));
}

#[test]
fn scheme_detect_compfs() {
    assert_eq!(UriScheme::detect("compfs:///path/to/file"), Some(UriScheme::Compfs));
}

// ── Redis TLS (rediss) ────────────────────────────────────────────────────────

#[test]
fn rediss_uri_is_detected() {
    assert!(is_remote_uri("rediss://host:6380/key"));
}

#[test]
fn scheme_detect_rediss() {
    assert_eq!(UriScheme::detect("rediss://host:6380/key"), Some(UriScheme::RedisTls));
}

// ── operator_for_uri compile-only checks (behind remote feature) ──────────────

#[cfg(feature = "remote")]
mod operator_tests {
    use blazehash::remote::operator::operator_for_uri;

    fn assert_not_unsupported(uri: &str) {
        match operator_for_uri(uri) {
            Err(e) if e.to_string().contains("unsupported URI scheme") => {
                panic!("operator_for_uri({uri:?}) returned unsupported URI scheme: {e}");
            }
            _ => {} // Ok or other error (missing creds, etc.) is fine
        }
    }

    #[test]
    fn operator_ftp_not_unsupported() {
        assert_not_unsupported("ftp://user:pass@host/path");
    }

    #[test]
    fn operator_sftp_not_unsupported() {
        assert_not_unsupported("sftp://user@host/path");
    }

    #[test]
    fn operator_onedrive_not_unsupported() {
        assert_not_unsupported("onedrive://Documents/file.pdf");
    }

    #[test]
    fn operator_dropbox_not_unsupported() {
        assert_not_unsupported("dropbox://path/file");
    }

    #[test]
    fn operator_b2_not_unsupported() {
        assert_not_unsupported("b2://bucket/key");
    }

    #[test]
    fn operator_cos_not_unsupported() {
        assert_not_unsupported("cos://bucket/key");
    }

    #[test]
    fn operator_obs_not_unsupported() {
        assert_not_unsupported("obs://bucket/key");
    }

    #[test]
    fn operator_oss_not_unsupported() {
        assert_not_unsupported("oss://bucket/key");
    }

    #[test]
    fn operator_swift_not_unsupported() {
        assert_not_unsupported("swift://container/path");
    }

    #[test]
    fn operator_azfile_not_unsupported() {
        assert_not_unsupported("azfile://share/path");
    }

    #[test]
    fn operator_azdls_not_unsupported() {
        assert_not_unsupported("azdls://container/path");
    }

    #[test]
    fn operator_github_not_unsupported() {
        assert_not_unsupported("github://owner/repo/path");
    }

    #[test]
    fn operator_ipfs_not_unsupported() {
        assert_not_unsupported("ipfs://QmHash/path");
    }

    #[test]
    fn operator_ipmfs_not_unsupported() {
        assert_not_unsupported("ipmfs:///path");
    }

    #[test]
    fn operator_webhdfs_not_unsupported() {
        assert_not_unsupported("webhdfs://host:50070/path");
    }

    #[test]
    fn operator_alluxio_not_unsupported() {
        assert_not_unsupported("alluxio://master:19998/path");
    }

    #[test]
    fn operator_lakefs_not_unsupported() {
        assert_not_unsupported("lakefs://repo/main/file");
    }

    #[test]
    fn operator_seafile_not_unsupported() {
        assert_not_unsupported("seafile://server/repo/file");
    }

    #[test]
    fn operator_pcloud_not_unsupported() {
        assert_not_unsupported("pcloud://path/file");
    }

    #[test]
    fn operator_koofr_not_unsupported() {
        assert_not_unsupported("koofr://path/file");
    }

    #[test]
    fn operator_yandex_disk_not_unsupported() {
        assert_not_unsupported("yandex-disk://path/file");
    }

    #[test]
    fn operator_huggingface_not_unsupported() {
        assert_not_unsupported("huggingface://owner/repo/file");
    }

    #[test]
    fn operator_upyun_not_unsupported() {
        assert_not_unsupported("upyun://bucket/key");
    }

    #[test]
    fn operator_aliyun_drive_not_unsupported() {
        assert_not_unsupported("aliyun-drive://path/file");
    }

    #[test]
    fn operator_vercel_blob_not_unsupported() {
        assert_not_unsupported("vercel-blob://key");
    }

    // ── sftp path extraction (TDD redo) ───────────────────────────────────────

    #[test]
    fn sftp_path_extracted_correctly() {
        let (_, path) = operator_for_uri("sftp://user@192.168.1.10/evidence/disk.dd")
            .expect("sftp:// should be supported");
        assert_eq!(path, "evidence/disk.dd");
    }

    #[test]
    fn sftp_nested_path_extracted_correctly() {
        let (_, path) = operator_for_uri("sftp://analyst@server.corp/cases/2026/image.dd")
            .expect("sftp:// should be supported");
        assert_eq!(path, "cases/2026/image.dd");
    }

    #[test]
    fn sftp_userpass_path_extracted_correctly() {
        // sftp://user:pass@host/path — password stripped, path still correct
        let (_, path) = operator_for_uri("sftp://admin:secret@10.0.0.1/data/forensics/dump.dd")
            .expect("sftp:// with password should be supported");
        assert_eq!(path, "data/forensics/dump.dd");
    }

    // ── ftp path extraction (TDD redo) ────────────────────────────────────────

    #[test]
    fn ftp_path_extracted_correctly() {
        let (_, path) = operator_for_uri("ftp://user:pass@ftpserver.example.com/data/malware.zip")
            .expect("ftp:// should be supported");
        assert_eq!(path, "data/malware.zip");
    }

    #[test]
    fn ftps_path_extracted_correctly() {
        let (_, path) = operator_for_uri("ftps://user:pass@secure.example.com/evidence/image.dd")
            .expect("ftps:// should be supported");
        assert_eq!(path, "evidence/image.dd");
    }

    #[test]
    fn ftp_no_credentials_path_extracted() {
        // ftp://host/path — no credentials in URI
        let (_, path) = operator_for_uri("ftp://public.example.com/pub/forensics/file.zip")
            .expect("ftp:// without credentials should be supported");
        assert_eq!(path, "pub/forensics/file.zip");
    }

    // ── rocksdb:// (optional feature: rocksdb-storage) ────────────────────────

    #[cfg(feature = "rocksdb-storage")]
    #[test]
    fn operator_rocksdb_not_unsupported() {
        assert_not_unsupported("rocksdb:///tmp/bh-rocksdb-test-a/evidence/manifest");
    }

    #[cfg(feature = "rocksdb-storage")]
    #[test]
    fn rocksdb_path_extracted_correctly() {
        let (_, key) = operator_for_uri("rocksdb:///tmp/bh-rocksdb-test-b/evidence/case-001")
            .expect("rocksdb:// should be supported with rocksdb-storage feature");
        assert_eq!(key, "case-001");
    }

    // ── monoiofs:// (monoio filesystem, Linux only) ───────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn operator_monoiofs_not_unsupported() {
        assert_not_unsupported("monoiofs:///tmp/evidence");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monoiofs_path_extracted_correctly() {
        let (_, path) = operator_for_uri("monoiofs:///evidence/disk.dd")
            .expect("monoiofs:// should be supported");
        assert_eq!(path, "disk.dd");
    }

    // ── compfs:// (compio filesystem) ─────────────────────────────────────────

    #[test]
    fn operator_compfs_not_unsupported() {
        assert_not_unsupported("compfs:///tmp/evidence");
    }

    #[test]
    fn compfs_path_extracted_correctly() {
        let (_, path) = operator_for_uri("compfs:///tmp/evidence/disk.dd")
            .expect("compfs:// should be supported");
        assert_eq!(path, "disk.dd");
    }

    // ── rediss:// (Redis with TLS) ─────────────────────────────────────────────

    #[test]
    fn operator_rediss_not_unsupported() {
        assert_not_unsupported("rediss://host:6380/mykey");
    }

    #[test]
    fn rediss_path_extracted_correctly() {
        let (_, key) = operator_for_uri("rediss://localhost:6380/cache:evidence:hash")
            .expect("rediss:// should be supported");
        assert_eq!(key, "cache:evidence:hash");
    }

    // ── HDFS native path extraction (TDD) ─────────────────────────────────────

    #[test]
    fn operator_hdfs_not_unsupported() {
        assert_not_unsupported("hdfs://namenode:9000/data/evidence.zip");
    }

    #[test]
    fn hdfs_path_extracted_correctly() {
        let (_, path) = operator_for_uri("hdfs://namenode:9000/data/evidence.zip")
            .expect("hdfs:// should be supported");
        assert_eq!(path, "data/evidence.zip");
    }

    #[test]
    fn hdfs_nested_path_extracted_correctly() {
        let (_, path) = operator_for_uri("hdfs://cluster.corp:8020/user/analyst/cases/2026/image.raw")
            .expect("hdfs:// nested path should be supported");
        assert_eq!(path, "user/analyst/cases/2026/image.raw");
    }
}
