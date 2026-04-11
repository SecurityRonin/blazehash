#[cfg(feature = "nsrl")]
use crate::algorithm::Algorithm;
#[cfg(feature = "nsrl")]
use crate::hash::FileHashResult;
#[cfg(feature = "nsrl")]
use anyhow::Result;
#[cfg(feature = "nsrl")]
use std::path::Path;

#[cfg(feature = "nsrl")]
pub fn write_sqlite(path: &Path, results: &[FileHashResult], algos: &[Algorithm]) -> Result<()> {
    use rusqlite::Connection;

    let conn = Connection::open(path)?;

    let algo_cols: String = algos
        .iter()
        .map(|a| format!("{} TEXT", a.hashdeep_name()))
        .collect::<Vec<_>>()
        .join(", ");

    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS files \
         (path TEXT PRIMARY KEY, size INTEGER, entropy REAL{sep}{algo_cols})",
        sep = if algo_cols.is_empty() { "" } else { ", " },
    );
    conn.execute_batch(&create_sql)?;

    if results.is_empty() {
        return Ok(());
    }

    let col_names: Vec<&str> = algos.iter().map(|a| a.hashdeep_name()).collect();
    let n = 3 + algos.len();
    let placeholders: String = (0..n).map(|_| "?").collect::<Vec<_>>().join(", ");
    let insert_sql = format!(
        "INSERT OR REPLACE INTO files (path, size, entropy{sep}{cols}) VALUES ({placeholders})",
        sep = if col_names.is_empty() { "" } else { ", " },
        cols = col_names.join(", "),
    );

    for r in results {
        let mut stmt = conn.prepare(&insert_sql)?;
        let path_str = r.path.to_string_lossy().into_owned();
        let size = r.size as i64;
        let entropy = r.entropy.unwrap_or(0.0);

        // Build a Vec<Box<dyn ToSql>> for dynamic dispatch
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> =
            vec![Box::new(path_str), Box::new(size), Box::new(entropy)];
        for algo in algos {
            let v = r.hashes.get(algo).cloned().unwrap_or_default();
            params.push(Box::new(v));
        }

        stmt.execute(rusqlite::params_from_iter(
            params.iter().map(|p| p.as_ref()),
        ))?;
    }
    Ok(())
}
