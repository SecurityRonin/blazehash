#[cfg(feature = "nsrl")]
mod bloom;
#[cfg(feature = "nsrl")]
mod sqlite;

#[cfg(feature = "nsrl")]
#[derive(Debug, PartialEq, Eq)]
pub enum NsrlResult {
    KnownGood,
    Unknown,
}

#[cfg(feature = "nsrl")]
pub struct NsrlLookup {
    inner: NsrlBackend,
}

#[cfg(feature = "nsrl")]
enum NsrlBackend {
    Sqlite(sqlite::SqliteNsrl),
    Bloom(bloom::BloomNsrl),
}

#[cfg(feature = "nsrl")]
impl NsrlLookup {
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "bloom" {
            anyhow::bail!(
                "bloom filter files are not supported for NSRL lookup. \
                 Bloom filters are probabilistic and can produce false positives, \
                 potentially suppressing evidence. Use a SQLite database (--nsrl file.db) instead."
            );
        }
        Ok(NsrlLookup {
            inner: NsrlBackend::Sqlite(sqlite::SqliteNsrl::open(path)?),
        })
    }

    pub fn lookup(&self, hash: &str) -> NsrlResult {
        match &self.inner {
            NsrlBackend::Sqlite(s) => s.lookup(hash),
            NsrlBackend::Bloom(b) => b.lookup(hash),
        }
    }
}

#[cfg(feature = "nsrl")]
pub fn build_bloom(
    db_path: &std::path::Path,
    out_path: &std::path::Path,
    fp_rate: f64,
) -> anyhow::Result<()> {
    bloom::build_bloom_from_sqlite(db_path, out_path, fp_rate)
}
