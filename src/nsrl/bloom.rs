use super::NsrlResult;
use anyhow::Result;
use bloomfilter::Bloom;
use rusqlite::Connection;
use std::path::Path;

pub struct BloomNsrl {
    bloom: Bloom<String>,
}

impl BloomNsrl {
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let bloom: Bloom<String> = bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid bloom file: {e}"))?;
        Ok(BloomNsrl { bloom })
    }

    pub fn lookup(&self, hash: &str) -> NsrlResult {
        if self.bloom.check(&hash.to_uppercase()) {
            NsrlResult::KnownGood
        } else {
            NsrlResult::Unknown
        }
    }
}

pub fn build_bloom_from_sqlite(db_path: &Path, out_path: &Path, fp_rate: f64) -> Result<()> {
    let conn = Connection::open(db_path)?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM FILE", [], |r| r.get(0))?;
    // Bloom::new_for_fp_rate requires items_count > 0
    let items = (count as usize).max(1);
    let mut bloom: Bloom<String> = Bloom::new_for_fp_rate(items, fp_rate);

    let mut stmt = conn.prepare("SELECT UPPER(SHA256) FROM FILE WHERE SHA256 IS NOT NULL")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let hash: String = row.get(0)?;
        bloom.set(&hash);
    }

    let bytes = bincode::serialize(&bloom)?;
    std::fs::write(out_path, bytes)?;
    eprintln!("[+] Bloom filter written to {}", out_path.display());
    Ok(())
}
