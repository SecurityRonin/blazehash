use super::NsrlResult;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;

pub struct SqliteNsrl {
    conn: Connection,
}

impl SqliteNsrl {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Ok(SqliteNsrl { conn })
    }

    pub fn lookup(&self, hash: &str) -> NsrlResult {
        let hash_upper = hash.to_uppercase();
        let exists: bool = self
            .conn
            .prepare_cached(
                "SELECT 1 FROM FILE WHERE UPPER(SHA256) = ?1 OR UPPER(MD5) = ?1 LIMIT 1",
            )
            .and_then(|mut s| s.exists(params![hash_upper]))
            .unwrap_or(false);
        if exists {
            NsrlResult::KnownGood
        } else {
            NsrlResult::Unknown
        }
    }
}
