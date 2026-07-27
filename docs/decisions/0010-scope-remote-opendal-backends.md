# 10. Scope the `remote` OpenDAL backend set to forensically-relevant evidence-transfer targets

Date: 2026-07-27
Status: Accepted

## Context

ADR-0002 gated the whole `opendal` cloud stack behind the opt-in `remote`
feature, so the default binary and the security audit stay opendal-free. It did
not scope *which* OpenDAL services `remote` compiles — every service OpenDAL
publishes (~50) was enabled. That set carries native database/KV engines and an
exotic long tail that no evidence-transfer workflow exercises but that costs real
build time:

- `services-rocksdb` pulls `librocksdb-sys`, a bundled C++ build — the
  `link.exe LNK1102` OOM culprit on the Windows leg under a debuginfo build.
- `services-etcd` / `services-tikv` pull `tonic`/`prost` gRPC stacks that need a
  `protoc` binary at build time — the sole reason `ci.yml` installs
  `protobuf-compiler` on all three OSes.
- `services-mongodb`/`gridfs` and the cache / embedded-KV set (`redis`,
  `memcached`, `sled`, `redb`, `persy`, `moka`, `mini-moka`, `dashmap`,
  `cacache`) add breadth with no forensic evidence-transfer story.

blazehash's `remote` feature exists so an examiner can hash evidence that lives
on a remote store, and write a collection back to one — the same targets DFIR
collectors (Velociraptor, KAPE) upload to: object storage (S3/Azure/GCS),
SFTP/FTP, WebHDFS/HDFS, and SQL stores. A distributed-KV cache or a
decentralized-filesystem gateway is not where case evidence lives.

Two honesty notes on the analysis behind this decision. An initial review pass
claimed specific dependency-crate-count reductions and a `libsqlite3-sys`
removal; a Codex critic could not reproduce those counts (`--all-features`
measured ~771 crates, not the cited figure) and `libsqlite3-sys` is pulled by
`rusqlite` regardless — so no crate-count figure is asserted here. The
load-bearing, verifiable claim is narrower and structural: dropping
`rocksdb`/`etcd`/`tikv` removes the `librocksdb-sys` C++ build and the
`tonic`/`prost` chains, which lets the `protoc` install step leave CI entirely.
The compile-time and linker-RSS win is confirmed by the before/after CI
wall-clock on the enactment PR, not by a crate count.

## Decision

Scope the `remote` feature's OpenDAL service set to forensically-relevant
evidence-transfer targets. `remote` stays opt-in and remote-free-by-default
(ADR-0002 unchanged); this ADR narrows *which* services it compiles.

**KEEP** — evidence-transfer targets:

- Object storage: `s3`, `gcs`, `azblob`, `azdls`, `azfile`, `b2`, `cos`, `obs`,
  `oss`, `swift`
- Cloud drive: `gdrive` — the one drive with dedicated wiring
  (`src/remote/gdrive/`)
- Hadoop: `webhdfs`, `hdfs-native` (pure-Rust, no JVM)
- SQL: `mysql`, `postgresql`, `sqlite` (sqlx; PostgreSQL is README-advertised)
- Local / protocol: `fs`, `memory`, `http`, `webdav`, plus SFTP (`ssh2`) and
  FTP (`suppaftp`), which are non-opendal by design (ADR-0002 §4)

**DROP**:

- Native DB/KV + caches: `rocksdb` (and the `rocksdb-storage` feature), `etcd`,
  `tikv`, `mongodb`, `gridfs`, `redis` (+`redis-native-tls`), `memcached`,
  `sled`, `redb`, `persy`, `moka`, `mini-moka`, `dashmap`, `cacache`
- Dev / ML / CI-cache: `github`, `huggingface`, `vercel-blob`,
  `vercel-artifacts`, `ghac`
- Big data beyond WebHDFS/HDFS: `alluxio`, `lakefs`, `dbfs`
- Decentralized: `ipfs`, `ipmfs`
- Alternate-runtime filesystems: `compfs`, `monoiofs`
- Cloudflare: `cloudflare-kv`, `d1`
- Regional / consumer drives: `onedrive`, `dropbox`, `aliyun-drive`,
  `yandex-disk`, `pcloud`, `koofr`, `seafile`, `upyun`

On the drives specifically: GDrive is kept because it carries dedicated wiring;
OneDrive and Dropbox had only generic scheme wiring (no CLI or test path), so
absent a concrete case they ship as unexercised capability and are dropped —
one line to re-add if a real need appears.

## Consequences

- The `protoc` build-tool install step is removed from `ci.yml` (no
  `etcd`/`tikv` gRPC stack remains to need it).
- `librocksdb-sys` leaves the `--features remote` graph, removing the
  Windows-linker memory pressure it contributed.
- `rocksdb-storage` is removed from `[features]`, and `deny.toml`'s per-feature
  enumeration drops it.
- `operator_for_uri` loses the ~25 dropped scheme arms; the KEEP schemes and the
  informative SFTP/FTP bail arms remain.
- The cost win — smaller `remote` compile, lower Windows-linker RSS — is proven
  by the enactment PR's CI wall-clock against the prior run, not asserted as a
  crate-count figure.
- Re-adding any dropped backend is a one-line feature plus one match arm; nothing
  here is one-way.
