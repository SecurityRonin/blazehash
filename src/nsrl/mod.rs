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
#[allow(dead_code)] // Bloom variant kept for future .bloom import support
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

/// Load a NIST NSRL flat `.hsh` file, returning all SHA-1 hashes (lowercased).
/// Format: pipe-delimited, first column is quoted SHA-1, first line is header.
#[cfg(feature = "nsrl")]
pub fn load_hsh(path: &std::path::Path) -> anyhow::Result<std::collections::HashSet<String>> {
    use std::io::{BufRead, BufReader};
    let f = std::fs::File::open(path)?;
    let mut set = std::collections::HashSet::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        if i == 0 {
            continue; // skip header
        }
        let sha1 = line
            .split('|')
            .next()
            .unwrap_or("")
            .trim_matches('"')
            .to_lowercase();
        if sha1.len() == 40 {
            set.insert(sha1);
        }
    }
    Ok(set)
}

#[cfg(feature = "nsrl")]
pub fn build_bloom(
    db_path: &std::path::Path,
    out_path: &std::path::Path,
    fp_rate: f64,
) -> anyhow::Result<()> {
    bloom::build_bloom_from_sqlite(db_path, out_path, fp_rate)
}
