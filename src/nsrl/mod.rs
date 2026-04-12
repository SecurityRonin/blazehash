#[cfg(feature = "hashdb")]
mod bloom;
#[cfg(feature = "hashdb")]
mod sqlite;

#[cfg(feature = "hashdb")]
#[derive(Debug, PartialEq, Eq)]
pub enum HashDbResult {
    KnownGood,
    KnownBad,
    Unknown,
}

/// Backwards-compat alias so existing internal call sites don't need updating.
#[cfg(feature = "hashdb")]
pub type NsrlResult = HashDbResult;

#[cfg(feature = "hashdb")]
pub struct NsrlLookup {
    inner: NsrlBackend,
}

#[cfg(feature = "hashdb")]
#[allow(dead_code)] // Bloom variant kept for future .bloom import support
enum NsrlBackend {
    Sqlite(sqlite::SqliteNsrl),
    Bloom(bloom::BloomNsrl),
}

#[cfg(feature = "hashdb")]
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
#[cfg(feature = "hashdb")]
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

/// Load a flat bad-hash file: one SHA-256 (64 hex chars) or SHA-1 (40 hex chars) per line.
/// Lines starting with `#` are comments. Empty lines are skipped.
#[cfg(feature = "hashdb")]
pub fn load_bad_list(path: &std::path::Path) -> anyhow::Result<std::collections::HashSet<String>> {
    use std::io::{BufRead, BufReader};
    let f = std::fs::File::open(path)?;
    let mut set = std::collections::HashSet::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if lower.len() >= 32 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
            set.insert(lower);
        }
    }
    Ok(set)
}

#[cfg(feature = "hashdb")]
pub fn build_bloom(
    db_path: &std::path::Path,
    out_path: &std::path::Path,
    fp_rate: f64,
) -> anyhow::Result<()> {
    bloom::build_bloom_from_sqlite(db_path, out_path, fp_rate)
}
