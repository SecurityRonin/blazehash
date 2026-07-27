# Remote Storage

blazehash reads and writes evidence directly from remote storage via
[Apache OpenDAL](https://opendal.apache.org/), scoped to the backends where
forensic evidence actually lives and where DFIR collectors (Velociraptor, KAPE)
deposit it: object storage, SFTP/FTP, Hadoop, SQL stores, and WebDAV/HTTP. Any
URI that resolves to file-like data is a valid input path or `-o` output target —
no plugins, no adapters, no staging.

```bash
# Read from remote, write manifest to remote — entirely off-disk
blazehash s3://dfir-bucket/case-001/ -o gcs://evidence-archive/case-001.hash
```

The remote stack is an opt-in build feature (`--features remote`); the release
binaries enable it. ADR-0002 records why it is opt-in and ADR-0010 why the
backend set is scoped to evidence-transfer targets (both in the project's
`docs/decisions/`).

---

## Cloud Object Storage

The most common backends for evidence archiving.

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

## Google Drive

Useful when evidence is a file shared from a suspect's or custodian's account. blazehash uses the Drive API to hash without staging the file locally:

| Scheme | Backend | Auth |
|--------|---------|------|
| `gdrive://file-id` | Google Drive | Run `blazehash gdrive auth login` once to cache the OAuth2 token |

```bash
# By file ID
blazehash gdrive://1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0

# By share URL
blazehash https://drive.google.com/file/d/1Ykbd9fDXxWnD1-MTag_-8-Wh_Wnd28q0/view

# First-time auth (browser OAuth2 flow, token cached in ~/.config/blazehash/)
blazehash gdrive auth login
```

---

## Hadoop / HDFS

Two schemes, depending on your cluster setup — both pure-Rust, no JVM and no `libhdfs`:

| Scheme | Backend | Notes |
|--------|---------|-------|
| `hdfs://namenode:port/path` | HDFS (pure-Rust native client) | Speaks Hadoop RPC via the `hdfs-native` crate |
| `webhdfs://host:port/path` | WebHDFS REST API | Works with any Hadoop 2.x+ namenode; `WEBHDFS_USER` for the user name |

```bash
# Pure-Rust HDFS native client (no Java required)
blazehash hdfs://namenode.corp:8020/user/evidence/case-001/

# WebHDFS REST (also no Java required)
blazehash webhdfs://namenode.corp:50070/user/evidence/case-001/
```

`hdfs://` is preferred when the cluster exposes the native Hadoop RPC port (default 8020/9000). `webhdfs://` is the fallback when only the HTTP REST endpoint is reachable.

---

## SQL Databases

Useful when evidence artifacts are stored in operational datastores rather than file systems.

| Scheme | Backend | Auth / connection |
|--------|---------|-------------------|
| `mysql://host/db/key` | MySQL / MariaDB | Standard DSN |
| `postgresql://host/db/key` | PostgreSQL | Standard DSN |
| `sqlite://path/to.db/key` | SQLite (file on disk) | File path |

```bash
# Hash a value stored in a PostgreSQL row
blazehash postgresql://user:pass@localhost/forensics/artifacts
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
| `sqlite://path/db/key` | SQLite file | Lightweight embedded store; good for offline pipelines |

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
| `WEBHDFS_USER` | webhdfs |
| `BLAZEHASH_SFTP_KEY_PATH` | sftp |
| `BLAZEHASH_SFTP_KNOWN_HOSTS_STRATEGY` | sftp (`add` \| `strict` \| `accept_new`) |
