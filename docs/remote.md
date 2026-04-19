# Remote Storage

blazehash speaks **50+ storage protocols** natively via [Apache OpenDAL](https://opendal.apache.org/). Any URI that resolves to file-like data is a valid input path or `-o` output target — no plugins, no adapters, no staging.

```bash
# Read from remote, write manifest to remote — entirely off-disk
blazehash s3://dfir-bucket/case-001/ -o gcs://evidence-archive/case-001.hash
```

---

## Cloud Object Storage

These are the most common backends for evidence archiving.

| Scheme | Backend | Auth env vars |
|--------|---------|---------------|
| `s3://bucket/key` | AWS S3, MinIO, Cloudflare R2, Wasabi, Backblaze B2 (S3-compat) | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION` |
| `gcs://bucket/key` | Google Cloud Storage | `GOOGLE_APPLICATION_CREDENTIALS` |
| `azblob://container/key` | Azure Blob Storage | `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_ACCESS_KEY` |
| `azdls://filesystem/path` | Azure Data Lake Storage Gen2 | `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_ACCESS_KEY` |
| `azfile://share/path` | Azure Files | `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_ACCESS_KEY` |
| `b2://bucket/key` | Backblaze B2 (native API, not S3-compat) | `BACKBLAZE_APPLICATION_KEY_ID`, `BACKBLAZE_APPLICATION_KEY` |
| `cos://bucket/key` | Tencent Cloud COS | `TENCENTCLOUD_SECRET_ID`, `TENCENTCLOUD_SECRET_KEY`, `TENCENTCLOUD_REGION` |
| `obs://bucket/key` | Huawei Cloud OBS | `HUAWEI_ACCESS_KEY_ID`, `HUAWEI_SECRET_ACCESS_KEY`, `HUAWEI_REGION` |
| `oss://bucket/key` | Alibaba Cloud OSS | `ALIBABA_CLOUD_ACCESS_KEY_ID`, `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, `ALIBABA_CLOUD_REGION` |
| `swift://container/path` | OpenStack Swift | `SWIFT_ENDPOINT`, `SWIFT_TOKEN` |
| `upyun://bucket/key` | Upyun CDN storage | `UPYUN_OPERATOR`, `UPYUN_PASSWORD` |

### S3-compatible endpoints

MinIO, Cloudflare R2, Wasabi, and Backblaze B2 (S3-compat mode) all use `s3://`. Point to the right endpoint via `AWS_ENDPOINT_URL`:

```bash
# MinIO
export AWS_ENDPOINT_URL=http://localhost:9000
blazehash s3://evidence-bucket/case-001/

# Cloudflare R2
export AWS_ENDPOINT_URL=https://<account>.r2.cloudflarestorage.com
blazehash s3://dfir-bucket/image.dd

# Backblaze B2 (S3-compat)
export AWS_ENDPOINT_URL=https://s3.us-west-004.backblazeb2.com
blazehash s3://my-bucket/evidence/
```

---

## Cloud Drives

Consumer and enterprise cloud drives — useful when evidence is a file shared from a suspect's or custodian's account.

| Scheme | Backend | Auth |
|--------|---------|------|
| `gdrive://file-id` | Google Drive | Run `blazehash gdrive auth login` once to cache OAuth2 token |
| `onedrive://path` | Microsoft OneDrive | `ONEDRIVE_ACCESS_TOKEN` |
| `dropbox://path` | Dropbox | `DROPBOX_ACCESS_TOKEN` |
| `aliyun-drive://path` | Aliyun Drive (Alibaba) | `ALIYUN_DRIVE_ACCESS_TOKEN` |
| `yandex-disk://path` | Yandex Disk | `YANDEX_DISK_ACCESS_TOKEN` |
| `pcloud://path` | pCloud | `PCLOUD_USERNAME`, `PCLOUD_PASSWORD`, `PCLOUD_ENDPOINT` |
| `koofr://path` | Koofr | `KOOFR_EMAIL`, `KOOFR_PASSWORD`, `KOOFR_ENDPOINT` |
| `seafile://server/repo/path` | Seafile | `SEAFILE_USERNAME`, `SEAFILE_PASSWORD` |

### Google Drive without downloading

blazehash uses the Drive API to hash without staging the file locally:

```bash
# By file ID
blazehash gdrive://1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0

# By share URL
blazehash https://drive.google.com/file/d/1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0/view

# First-time auth (browser OAuth2 flow, token cached in ~/.config/blazehash/)
blazehash gdrive auth login
```

### OneDrive / SharePoint

```bash
export ONEDRIVE_ACCESS_TOKEN=$(az account get-access-token --resource https://graph.microsoft.com -o tsv --query accessToken)
blazehash onedrive://Documents/CaseFiles/image.dd
```

---

## Developer / ML / Infra

| Scheme | Backend | Auth |
|--------|---------|------|
| `github://owner/repo/path` | GitHub (raw file access) | `GITHUB_TOKEN` |
| `huggingface://owner/repo/path` | HuggingFace datasets and models | `HUGGINGFACE_TOKEN` |
| `vercel-blob://key` | Vercel Blob storage | `BLOB_READ_WRITE_TOKEN` |
| `vercel-artifacts://key` | Vercel build artifact cache | `VERCEL_ARTIFACTS_TOKEN` |
| `ghac://key` | GitHub Actions Cache | Set in GitHub Actions environment |
| `dbfs://path` | Databricks DBFS | `DATABRICKS_HOST`, `DATABRICKS_TOKEN` |
| `alluxio://host:port/path` | Alluxio data orchestration | — |
| `webhdfs://host:port/path` | WebHDFS REST (Hadoop — no JVM required) | `WEBHDFS_USER` |
| `lakefs://repo/branch/path` | LakeFS data versioning | `LAKEFS_ACCESS_KEY_ID`, `LAKEFS_SECRET_ACCESS_KEY`, `LAKEFS_ENDPOINT` |
| `ipfs://CID/path` | IPFS content-addressed storage | `IPFS_GATEWAY` (default: `http://127.0.0.1:8080`) |
| `ipmfs:///path` | IPFS Mutable File System | `IPFS_ENDPOINT` (default: `http://127.0.0.1:5001`) |

### Hadoop / HDFS

Two schemes are available depending on your cluster setup:

| Scheme | Backend | Notes |
|--------|---------|-------|
| `hdfs://namenode:port/path` | HDFS (pure-Rust native client) | No JVM, no `libhdfs` — uses `hdfs-native` crate speaking Hadoop RPC |
| `webhdfs://namenode:port/path` | WebHDFS REST API | No JVM, works with any Hadoop 2.x+ namenode |

```bash
# Pure-Rust HDFS native client (no Java required)
blazehash hdfs://namenode.corp:8020/user/evidence/case-001/

# WebHDFS REST (also no Java required)
blazehash webhdfs://namenode.corp:50070/user/evidence/case-001/
```

`hdfs://` is preferred when the cluster exposes the native Hadoop RPC port (default 8020/9000). `webhdfs://` is the fallback when only the HTTP REST endpoint is reachable.

### GitHub (code forensics)

Hash the exact state of a repository path at HEAD (or any ref via the API):

```bash
export GITHUB_TOKEN=ghp_...
blazehash github://octocat/Hello-World/README
```

---

## Network KV / Databases

Useful when evidence artifacts are stored in operational datastores rather than file systems.

| Scheme | Backend | Auth / connection |
|--------|---------|-------------------|
| `redis://host/key` | Redis | Standard Redis URL (supports `redis://[:password@]host:port`) |
| `memcached://host/key` | Memcached | `tcp://host:port` |
| `etcd://host/key` | etcd (gRPC) | `ETCD_USERNAME`, `ETCD_PASSWORD` |
| `tikv://pd-host/key` | TiKV distributed KV | PD endpoint |
| `mongodb://host/db/collection/key` | MongoDB | Standard MongoDB connection string |
| `gridfs://host/db/bucket/key` | MongoDB GridFS | Standard MongoDB connection string |
| `mysql://host/db/key` | MySQL / MariaDB | Standard DSN |
| `postgresql://host/db/key` | PostgreSQL | Standard DSN |
| `sqlite://path/to.db/key` | SQLite (file on disk) | File path |
| `cloudflare-kv://namespace/key` | Cloudflare Workers KV | `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` |
| `d1://database-id/key` | Cloudflare D1 (SQLite via REST) | `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` |

```bash
# Hash a value stored in Redis
blazehash redis://localhost/evidence:case-001:image

# Hash a MongoDB document field
blazehash mongodb://localhost/forensics/artifacts/abc123
```

---

## Filesystem & Protocols

| Scheme | Backend | Auth |
|--------|---------|------|
| `sftp://user@host/path` | SFTP / SSH | SSH agent, `BLAZEHASH_SFTP_KEY_PATH`, or `BLAZEHASH_SFTP_KNOWN_HOSTS_STRATEGY` |
| `ftp://user:pass@host/path` | FTP | Credentials in URI |
| `ftps://user:pass@host/path` | FTPS (FTP over TLS) | Credentials in URI |
| `webdav://host/path` | WebDAV (Nextcloud, Box, SharePoint on-prem) | Server-specific |
| `http://host/path` | HTTP (read-only) | — |
| `https://host/path` | HTTPS (read-only) | — |
| `file:///abs/path` | Explicit local filesystem | — |

### SFTP usage

```bash
# SSH agent (default — no config needed if your key is loaded)
blazehash sftp://admin@192.168.1.10/evidence/disk.dd

# Explicit key file
export BLAZEHASH_SFTP_KEY_PATH=~/.ssh/forensic_rsa
blazehash sftp://admin@192.168.1.10/evidence/disk.dd

# Known hosts strategy (add | strict | accept_new)
export BLAZEHASH_SFTP_KNOWN_HOSTS_STRATEGY=strict
blazehash sftp://admin@192.168.1.10/evidence/disk.dd
```

---

## In-Memory / Embedded (testing & pipelines)

| Scheme | Backend | Notes |
|--------|---------|-------|
| `mem://bucket/key` | In-process memory | Ephemeral; useful in tests and pipeline stages |
| `redis://...` | Redis (plaintext) | Also serves as fast shared cache between pipeline stages |
| `rediss://host:port/key` | Redis with TLS | Same as `redis://` but over an encrypted connection |
| `sqlite://path/db/key` | SQLite file | Lightweight embedded KV; good for offline pipelines |
| `rocksdb:///path/to/db/key` | RocksDB embedded KV | Requires `--features rocksdb-storage` (compile-time opt-in) |

### Redis TLS (`rediss://`)

The `rediss://` scheme (double-s) connects to Redis over TLS — useful when your Redis instance requires encrypted connections (e.g. Redis Cloud, Upstash, or self-hosted with TLS).

```bash
# Hash a value stored in Redis over TLS
blazehash rediss://redis.cloud.example.com:6380/evidence:case-001:hash
```

### RocksDB (`rocksdb://`)

RocksDB support is an optional compile-time feature — it pulls in the RocksDB C++ library at build time. Not included in the default binary; build with:

```bash
cargo install blazehash --features rocksdb-storage
```

```bash
# Hash a value stored in a local RocksDB database
blazehash rocksdb:///var/lib/evidence/casedb/artifact-001
```

## Compio / Monoio Async Filesystems

These backends replace the standard OS filesystem (`file://`) with alternative async I/O runtimes for workloads where kernel-level async matters.

| Scheme | Backend | Platform |
|--------|---------|----------|
| `compfs:///abs/path/file` | compio filesystem | macOS, Linux, Windows (io_uring / kqueue / IOCP) |
| `monoiofs:///abs/path/file` | monoio filesystem | Linux only (io_uring) |

```bash
# Hash via compio (cross-platform async I/O)
blazehash compfs:///mnt/evidence/disk.dd

# Hash via monoio (Linux io_uring — lower overhead for large sequential reads)
blazehash monoiofs:///mnt/evidence/disk.dd
```

In practice, for most forensic workloads the default filesystem is sufficient. These backends are relevant when integrating blazehash into a compio or monoio async pipeline.

---

## Writing manifests to remote storage

Any `-o` output path accepts a remote URI:

```bash
# Write manifest to S3
blazehash -r /mnt/evidence -c blake3,sha256 -o s3://dfir-bucket/case-001.hash

# Sign a remote manifest in-place
blazehash sign s3://dfir-bucket/case-001.hash

# Audit remotely — no local copy of the manifest needed
blazehash -a -k s3://dfir-bucket/case-001.hash -r /mnt/evidence
```

---

## Environment variable reference

| Variable | Used by |
|----------|---------|
| `AWS_ACCESS_KEY_ID` | S3 |
| `AWS_SECRET_ACCESS_KEY` | S3 |
| `AWS_DEFAULT_REGION` | S3 |
| `AWS_ENDPOINT_URL` | S3 (custom endpoints: MinIO, R2, Wasabi, etc.) |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCS |
| `AZURE_STORAGE_ACCOUNT` | azblob, azdls, azfile |
| `AZURE_STORAGE_ACCESS_KEY` | azblob, azdls, azfile |
| `BACKBLAZE_APPLICATION_KEY_ID` | b2 |
| `BACKBLAZE_APPLICATION_KEY` | b2 |
| `TENCENTCLOUD_SECRET_ID` | cos |
| `TENCENTCLOUD_SECRET_KEY` | cos |
| `TENCENTCLOUD_REGION` | cos |
| `HUAWEI_ACCESS_KEY_ID` | obs |
| `HUAWEI_SECRET_ACCESS_KEY` | obs |
| `HUAWEI_REGION` | obs |
| `ALIBABA_CLOUD_ACCESS_KEY_ID` | oss |
| `ALIBABA_CLOUD_ACCESS_KEY_SECRET` | oss |
| `ALIBABA_CLOUD_REGION` | oss |
| `SWIFT_ENDPOINT` | swift |
| `SWIFT_TOKEN` | swift |
| `UPYUN_OPERATOR` | upyun |
| `UPYUN_PASSWORD` | upyun |
| `ONEDRIVE_ACCESS_TOKEN` | onedrive |
| `DROPBOX_ACCESS_TOKEN` | dropbox |
| `ALIYUN_DRIVE_ACCESS_TOKEN` | aliyun-drive |
| `YANDEX_DISK_ACCESS_TOKEN` | yandex-disk |
| `PCLOUD_USERNAME` / `PCLOUD_PASSWORD` | pcloud |
| `PCLOUD_ENDPOINT` | pcloud (default: `https://api.pcloud.com`) |
| `KOOFR_EMAIL` / `KOOFR_PASSWORD` | koofr |
| `KOOFR_ENDPOINT` | koofr (default: `https://app.koofr.net`) |
| `SEAFILE_USERNAME` / `SEAFILE_PASSWORD` | seafile |
| `SEAFILE_REPO` | seafile (repo name, default: `My Library`) |
| `GITHUB_TOKEN` | github |
| `HUGGINGFACE_TOKEN` | huggingface |
| `BLOB_READ_WRITE_TOKEN` | vercel-blob |
| `VERCEL_ARTIFACTS_TOKEN` | vercel-artifacts |
| `DATABRICKS_HOST` | dbfs |
| `DATABRICKS_TOKEN` | dbfs |
| `WEBHDFS_USER` | webhdfs |
| `LAKEFS_ACCESS_KEY_ID` | lakefs |
| `LAKEFS_SECRET_ACCESS_KEY` | lakefs |
| `LAKEFS_ENDPOINT` | lakefs (default: `http://localhost:8000`) |
| `IPFS_GATEWAY` | ipfs (default: `http://127.0.0.1:8080`) |
| `IPFS_ENDPOINT` | ipmfs (default: `http://127.0.0.1:5001`) |
| `CLOUDFLARE_ACCOUNT_ID` | cloudflare-kv, d1 |
| `CLOUDFLARE_API_TOKEN` | cloudflare-kv, d1 |
| `BLAZEHASH_SFTP_KEY_PATH` | sftp |
| `BLAZEHASH_SFTP_KNOWN_HOSTS_STRATEGY` | sftp (`add` \| `strict` \| `accept_new`) |
