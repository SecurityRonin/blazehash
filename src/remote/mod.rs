#[cfg(feature = "remote")]
pub mod ftp;
pub mod gdrive;
#[cfg(feature = "remote")]
pub mod operator;
#[cfg(feature = "remote")]
pub mod reader;
#[cfg(feature = "remote")]
pub mod sftp;
#[cfg(feature = "remote")]
pub mod tftp;
#[cfg(feature = "remote")]
pub mod walk;
#[cfg(feature = "remote")]
pub mod writer;

/// Returns true if the string has a known remote URI scheme.
pub fn is_remote_uri(s: &str) -> bool {
    let s = s.trim();
    matches!(
        s.split_once("://").map(|(scheme, _)| scheme),
        Some(
            // Cloud object storage
            "s3" | "gcs" | "azblob" | "azdls" | "azfile" | "b2"
            | "cos" | "obs" | "oss" | "swift" | "upyun"
            // Consumer / enterprise cloud drives
            | "gdrive" | "onedrive" | "dropbox"
            | "aliyun-drive" | "yandex-disk" | "pcloud" | "koofr" | "seafile"
            // Developer / ML / infra
            | "github" | "huggingface"
            | "vercel-blob" | "vercel-artifacts"
            // Distributed / big data
            | "alluxio" | "webhdfs" | "hdfs" | "lakefs" | "dbfs" | "ghac"
            // Decentralized
            | "ipfs" | "ipmfs"
            // Network KV / databases
            | "redis" | "rediss" | "memcached" | "etcd" | "tikv"
            | "mongodb" | "mysql" | "postgresql" | "sqlite"
            | "surrealdb" | "rocksdb"
            // Misc
            | "cloudflare-kv" | "d1"
            // Filesystem / network protocols
            | "http" | "https" | "webdav" | "sftp" | "ftp" | "ftps" | "tftp"
            | "compfs" | "monoiofs"
            | "mem" | "file"
        )
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum UriScheme {
    // Cloud object storage
    S3,
    Gcs,
    AzBlob,
    AzDls,
    AzFile,
    B2,
    Cos,
    Obs,
    Oss,
    Swift,
    Upyun,
    // Consumer / enterprise cloud drives
    GDrive,
    OneDrive,
    Dropbox,
    AliyunDrive,
    YandexDisk,
    PCloud,
    Koofr,
    Seafile,
    // Developer / ML / infra
    GitHub,
    HuggingFace,
    VercelBlob,
    VercelArtifacts,
    // Distributed / big data
    Alluxio,
    WebHdfs,
    LakeFs,
    Dbfs,
    Ghac,
    // Decentralized
    Ipfs,
    Ipmfs,
    // Network KV / databases
    Redis,
    RedisTls,
    Memcached,
    Etcd,
    TiKv,
    MongoDB,
    Gridfs,
    MySQL,
    PostgreSQL,
    SQLite,
    SurrealDB,
    #[cfg(feature = "rocksdb-storage")]
    RocksDb,
    // Misc
    CloudflareKv,
    D1,
    // Filesystem / network protocols
    Http,
    Https,
    WebDav,
    Sftp,
    Ftp,
    Ftps,
    Tftp,
    Compfs,
    Monoiofs,
    Mem,
    File,
    // Distributed big-data
    Hdfs,
}

impl UriScheme {
    pub fn detect(uri: &str) -> Option<Self> {
        let scheme = uri.split_once("://")?.0;
        match scheme {
            "s3" => Some(Self::S3),
            "gcs" => Some(Self::Gcs),
            "azblob" => Some(Self::AzBlob),
            "azdls" => Some(Self::AzDls),
            "azfile" => Some(Self::AzFile),
            "b2" => Some(Self::B2),
            "cos" => Some(Self::Cos),
            "obs" => Some(Self::Obs),
            "oss" => Some(Self::Oss),
            "swift" => Some(Self::Swift),
            "upyun" => Some(Self::Upyun),
            "gdrive" => Some(Self::GDrive),
            "onedrive" => Some(Self::OneDrive),
            "dropbox" => Some(Self::Dropbox),
            "aliyun-drive" => Some(Self::AliyunDrive),
            "yandex-disk" => Some(Self::YandexDisk),
            "pcloud" => Some(Self::PCloud),
            "koofr" => Some(Self::Koofr),
            "seafile" => Some(Self::Seafile),
            "github" => Some(Self::GitHub),
            "huggingface" => Some(Self::HuggingFace),
            "vercel-blob" => Some(Self::VercelBlob),
            "vercel-artifacts" => Some(Self::VercelArtifacts),
            "alluxio" => Some(Self::Alluxio),
            "webhdfs" => Some(Self::WebHdfs),
            "hdfs" => Some(Self::Hdfs),
            "lakefs" => Some(Self::LakeFs),
            "dbfs" => Some(Self::Dbfs),
            "ghac" => Some(Self::Ghac),
            "ipfs" => Some(Self::Ipfs),
            "ipmfs" => Some(Self::Ipmfs),
            "redis" => Some(Self::Redis),
            "rediss" => Some(Self::RedisTls),
            "memcached" => Some(Self::Memcached),
            "etcd" => Some(Self::Etcd),
            "tikv" => Some(Self::TiKv),
            "mongodb" => Some(Self::MongoDB),
            "gridfs" => Some(Self::Gridfs),
            "mysql" => Some(Self::MySQL),
            "postgresql" => Some(Self::PostgreSQL),
            "sqlite" => Some(Self::SQLite),
            "surrealdb" => Some(Self::SurrealDB),
            #[cfg(feature = "rocksdb-storage")]
            "rocksdb" => Some(Self::RocksDb),
            "cloudflare-kv" => Some(Self::CloudflareKv),
            "d1" => Some(Self::D1),
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "webdav" => Some(Self::WebDav),
            "sftp" => Some(Self::Sftp),
            "ftp" => Some(Self::Ftp),
            "ftps" => Some(Self::Ftps),
            "tftp" => Some(Self::Tftp),
            "compfs" => Some(Self::Compfs),
            "monoiofs" => Some(Self::Monoiofs),
            "mem" => Some(Self::Mem),
            "file" => Some(Self::File),
            _ => None,
        }
    }
}
