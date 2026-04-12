#[cfg(feature = "duckdb-output")]
use crate::algorithm::Algorithm;
#[cfg(feature = "duckdb-output")]
use crate::hash::FileHashResult;
#[cfg(feature = "duckdb-output")]
use anyhow::Result;
#[cfg(feature = "duckdb-output")]
use std::path::Path;

#[cfg(feature = "duckdb-output")]
pub fn write_duckdb(path: &Path, results: &[FileHashResult], algos: &[Algorithm]) -> Result<()> {
    use duckdb::Connection;

    let conn = Connection::open(path)?;

    let algo_cols: String = algos
        .iter()
        .map(|a| format!("{} VARCHAR", a.hashdeep_name()))
        .collect::<Vec<_>>()
        .join(", ");

    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS files \
         (path VARCHAR PRIMARY KEY, size BIGINT, entropy DOUBLE{sep}{algo_cols})",
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

        let mut params: Vec<Box<dyn duckdb::ToSql>> =
            vec![Box::new(path_str), Box::new(size), Box::new(entropy)];
        for algo in algos {
            let v = r.hashes.get(algo).cloned().unwrap_or_default();
            params.push(Box::new(v));
        }

        stmt.execute(duckdb::params_from_iter(params.iter().map(|p| p.as_ref())))?;
    }
    Ok(())
}
